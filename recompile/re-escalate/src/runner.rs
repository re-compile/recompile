//! Escalation runner - orchestrates tool execution

use crate::{
    parse_asan_output, parse_lsan_output, parse_ubsan_output, parse_valgrind_output,
    EscalationConfig, EscalationError, EscalationResult, Finding, Result,
};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command as TokioCommand;
use tokio::time::{timeout, Duration as TokioDuration};
use uuid::Uuid;

/// Main escalation runner
pub struct EscalationRunner {
    config: EscalationConfig,
    cooldowns: std::collections::HashMap<String, Instant>,
}

impl EscalationRunner {
    /// Create a new escalation runner
    pub fn new(config: EscalationConfig) -> Self {
        Self {
            config,
            cooldowns: std::collections::HashMap::new(),
        }
    }

    /// Run escalation for a finding
    pub async fn escalate(&mut self, finding: &Finding) -> Result<EscalationResult> {
        let escalation_plan = finding
            .escalation
            .as_ref()
            .ok_or_else(|| EscalationError::Config("No escalation plan in finding".to_string()))?;

        // Check cooldown
        if self.is_in_cooldown(&escalation_plan.tool) {
            return Err(EscalationError::Config(format!(
                "Tool {} is in cooldown",
                escalation_plan.tool
            )));
        }

        log::info!(
            "Escalating finding {} with tool {}",
            finding.id,
            escalation_plan.tool
        );

        let start_time = Instant::now();
        let escalation_id = Uuid::new_v4().to_string();

        let duration_start = start_time;
        let result = match escalation_plan.tool.as_str() {
            "asan" => self.run_asan_result(finding, &escalation_id).await,
            "lsan" => self.run_lsan_result(finding, &escalation_id).await,
            "ubsan" => self.run_ubsan_result(finding, &escalation_id).await,
            "valgrind" => self.run_valgrind_escalation(finding, &escalation_id).await,
            "gdb" => self.run_gdb_result(finding, &escalation_id).await,
            tool => Ok(self.failure_result(
                finding,
                &escalation_id,
                tool,
                false,
                duration_start.elapsed().as_millis() as u64,
                format!("Unknown escalation tool: {}", tool),
            )),
        };

        let escalation_result = result?;

        // Update cooldown
        self.update_cooldown(&escalation_plan.tool, escalation_plan.cooldown_ms);

        Ok(escalation_result)
    }

    /// Run an escalation tool against the configured binary without requiring a finding.
    pub async fn check_clean_binary(&mut self, tool: &str) -> Result<EscalationResult> {
        if self.is_in_cooldown(tool) {
            return Err(EscalationError::Config(format!(
                "Tool {} is in cooldown",
                tool
            )));
        }

        let escalation_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();
        let result = match tool {
            "valgrind" => self.run_valgrind_clean_check(&escalation_id).await,
            "asan" => self.run_asan_clean_check(&escalation_id).await,
            "lsan" => self.run_lsan_clean_check(&escalation_id).await,
            "ubsan" => self.run_ubsan_clean_check(&escalation_id).await,
            "gdb" => Ok(self.result_failure(
                "clean-run",
                &escalation_id,
                tool,
                false,
                start_time.elapsed().as_millis() as u64,
                format!("Clean checks are not implemented for {}", tool),
            )),
            other => Ok(self.result_failure(
                "clean-run",
                &escalation_id,
                other,
                false,
                start_time.elapsed().as_millis() as u64,
                format!("Unknown escalation tool: {}", other),
            )),
        };

        let escalation_result = result?;
        self.update_cooldown(tool, 0);
        Ok(escalation_result)
    }

    /// Check if a tool is in cooldown
    fn is_in_cooldown(&self, tool: &str) -> bool {
        if let Some(until) = self.cooldowns.get(tool) {
            Instant::now() < *until
        } else {
            false
        }
    }

    /// Update cooldown for a tool
    fn update_cooldown(&mut self, tool: &str, cooldown_ms: u32) {
        let effective_cooldown = if cooldown_ms == 0 {
            self.config
                .cooldowns
                .per_tool
                .get(tool)
                .copied()
                .unwrap_or(self.config.cooldowns.default_ms)
        } else {
            cooldown_ms
        };
        self.cooldowns.insert(
            tool.to_string(),
            Instant::now() + std::time::Duration::from_millis(effective_cooldown as u64),
        );
    }

    async fn run_asan_result(
        &self,
        finding: &Finding,
        escalation_id: &str,
    ) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.asan.enabled {
            return Ok(self.failure_result(
                finding,
                escalation_id,
                "asan",
                false,
                start_time.elapsed().as_millis() as u64,
                "ASan escalation is disabled".to_string(),
            ));
        }

        let binary_path = self.find_binary(finding)?;
        self.run_asan_binary(&finding.id, &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_gdb_result(
        &self,
        finding: &Finding,
        escalation_id: &str,
    ) -> Result<EscalationResult> {
        let start_time = Instant::now();
        let result = self.run_gdb_escalation(finding, escalation_id).await;
        let duration_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(path) => Ok(EscalationResult {
                id: escalation_id.to_string(),
                finding_id: finding.id.clone(),
                tool: "gdb".to_string(),
                success: true,
                tool_available: true,
                duration_ms,
                output_path: Some(path),
                stdout_path: None,
                stderr_path: None,
                report_path: None,
                command: Vec::new(),
                exit_code: None,
                confirmed: false,
                error: None,
                findings_detected: Vec::new(),
                timestamp: unix_timestamp(),
            }),
            Err(error) => Ok(self.failure_result(
                finding,
                escalation_id,
                "gdb",
                true,
                duration_ms,
                error.to_string(),
            )),
        }
    }

    async fn run_ubsan_result(
        &self,
        finding: &Finding,
        escalation_id: &str,
    ) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.ubsan.enabled {
            return Ok(self.failure_result(
                finding,
                escalation_id,
                "ubsan",
                false,
                start_time.elapsed().as_millis() as u64,
                "UBSan escalation is disabled".to_string(),
            ));
        }

        let binary_path = self.find_binary(finding)?;
        self.run_ubsan_binary(&finding.id, &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_lsan_result(
        &self,
        finding: &Finding,
        escalation_id: &str,
    ) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.lsan.enabled {
            return Ok(self.failure_result(
                finding,
                escalation_id,
                "lsan",
                false,
                start_time.elapsed().as_millis() as u64,
                "LSan escalation is disabled".to_string(),
            ));
        }

        let binary_path = self.find_binary(finding)?;
        self.run_lsan_binary(&finding.id, &binary_path, escalation_id, start_time)
            .await
    }

    fn failure_result(
        &self,
        finding: &Finding,
        escalation_id: &str,
        tool: &str,
        tool_available: bool,
        duration_ms: u64,
        error: String,
    ) -> EscalationResult {
        self.result_failure(
            &finding.id,
            escalation_id,
            tool,
            tool_available,
            duration_ms,
            error,
        )
    }

    fn result_failure(
        &self,
        finding_id: &str,
        escalation_id: &str,
        tool: &str,
        tool_available: bool,
        duration_ms: u64,
        error: String,
    ) -> EscalationResult {
        EscalationResult {
            id: escalation_id.to_string(),
            finding_id: finding_id.to_string(),
            tool: tool.to_string(),
            success: false,
            tool_available,
            duration_ms,
            output_path: None,
            stdout_path: None,
            stderr_path: None,
            report_path: None,
            command: Vec::new(),
            exit_code: None,
            confirmed: false,
            error: Some(error),
            findings_detected: Vec::new(),
            timestamp: unix_timestamp(),
        }
    }

    async fn run_asan_clean_check(&self, escalation_id: &str) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.asan.enabled {
            return Ok(self.result_failure(
                "clean-run",
                escalation_id,
                "asan",
                false,
                start_time.elapsed().as_millis() as u64,
                "ASan escalation is disabled".to_string(),
            ));
        }

        let binary_path = self
            .config
            .binary_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .ok_or_else(|| {
                EscalationError::Config(
                    "Clean ASan check requires an existing binary_path".to_string(),
                )
            })?;

        self.run_asan_binary("clean-run", &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_asan_binary(
        &self,
        finding_id: &str,
        binary_path: &Path,
        escalation_id: &str,
        start_time: Instant,
    ) -> Result<EscalationResult> {
        if !self.binary_looks_asan_instrumented(binary_path).await? {
            return Ok(self.result_failure(
                finding_id,
                escalation_id,
                "asan",
                false,
                start_time.elapsed().as_millis() as u64,
                format!(
                    "ASan requires a binary built with -fsanitize=address: {}",
                    binary_path.display()
                ),
            ));
        }

        let output_dir = Path::new(&self.config.output_dir).join("asan");
        tokio::fs::create_dir_all(&output_dir).await?;

        let stdout_file = output_dir.join(format!("asan_{}.stdout.log", escalation_id));
        let stderr_file = output_dir.join(format!("asan_{}.stderr.log", escalation_id));
        let report_file = output_dir.join(format!("asan_{}.json", escalation_id));

        let executable_path = canonical_binary_path(binary_path);
        let mut cmd = TokioCommand::new(&executable_path);
        let mut command = vec![executable_path.display().to_string()];
        for arg in &self.config.args {
            cmd.arg(arg);
            command.push(arg.clone());
        }

        let runtime_flags = self.config.tools.asan.runtime_flags.join(":");
        cmd.env("ASAN_OPTIONS", runtime_flags);
        self.apply_cwd(&mut cmd, &mut command);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.asan.timeout_ms);
        let output = timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| EscalationError::Timeout("ASan execution timed out".to_string()))?;

        let output = output.map_err(|error| EscalationError::ToolExecution(error.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        let report = parse_asan_output(&output_str, &error_str);

        tokio::fs::write(&stdout_file, output_str.as_bytes()).await?;
        tokio::fs::write(&stderr_file, error_str.as_bytes()).await?;
        tokio::fs::write(&report_file, serde_json::to_vec_pretty(&report)?).await?;

        let findings_detected = report.detected_classes();

        log::info!("ASan escalation completed: {}", report_file.display());
        Ok(EscalationResult {
            id: escalation_id.to_string(),
            finding_id: finding_id.to_string(),
            tool: "asan".to_string(),
            success: true,
            tool_available: true,
            duration_ms: start_time.elapsed().as_millis() as u64,
            output_path: Some(report_file.display().to_string()),
            stdout_path: Some(stdout_file.display().to_string()),
            stderr_path: Some(stderr_file.display().to_string()),
            report_path: Some(report_file.display().to_string()),
            command,
            exit_code: output.status.code(),
            confirmed: report.confirmed(),
            error: None,
            findings_detected,
            timestamp: unix_timestamp(),
        })
    }

    async fn run_ubsan_clean_check(&self, escalation_id: &str) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.ubsan.enabled {
            return Ok(self.result_failure(
                "clean-run",
                escalation_id,
                "ubsan",
                false,
                start_time.elapsed().as_millis() as u64,
                "UBSan escalation is disabled".to_string(),
            ));
        }

        let binary_path = self
            .config
            .binary_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .ok_or_else(|| {
                EscalationError::Config(
                    "Clean UBSan check requires an existing binary_path".to_string(),
                )
            })?;

        self.run_ubsan_binary("clean-run", &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_lsan_clean_check(&self, escalation_id: &str) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.lsan.enabled {
            return Ok(self.result_failure(
                "clean-run",
                escalation_id,
                "lsan",
                false,
                start_time.elapsed().as_millis() as u64,
                "LSan escalation is disabled".to_string(),
            ));
        }

        let binary_path = self
            .config
            .binary_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .ok_or_else(|| {
                EscalationError::Config(
                    "Clean LSan check requires an existing binary_path".to_string(),
                )
            })?;

        self.run_lsan_binary("clean-run", &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_lsan_binary(
        &self,
        finding_id: &str,
        binary_path: &Path,
        escalation_id: &str,
        start_time: Instant,
    ) -> Result<EscalationResult> {
        if !self.binary_looks_lsan_instrumented(binary_path).await? {
            return Ok(self.result_failure(
                finding_id,
                escalation_id,
                "lsan",
                false,
                start_time.elapsed().as_millis() as u64,
                format!(
                    "LSan requires a binary built with -fsanitize=leak: {}",
                    binary_path.display()
                ),
            ));
        }

        let output_dir = Path::new(&self.config.output_dir).join("lsan");
        tokio::fs::create_dir_all(&output_dir).await?;

        let stdout_file = output_dir.join(format!("lsan_{}.stdout.log", escalation_id));
        let stderr_file = output_dir.join(format!("lsan_{}.stderr.log", escalation_id));
        let report_file = output_dir.join(format!("lsan_{}.json", escalation_id));

        let executable_path = canonical_binary_path(binary_path);
        let mut cmd = TokioCommand::new(&executable_path);
        let mut command = vec![executable_path.display().to_string()];
        for arg in &self.config.args {
            cmd.arg(arg);
            command.push(arg.clone());
        }

        let runtime_flags = self.config.tools.lsan.runtime_flags.join(":");
        cmd.env("LSAN_OPTIONS", runtime_flags);
        self.apply_cwd(&mut cmd, &mut command);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.lsan.timeout_ms);
        let output = timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| EscalationError::Timeout("LSan execution timed out".to_string()))?;

        let output = output.map_err(|error| EscalationError::ToolExecution(error.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        let report = parse_lsan_output(&output_str, &error_str);

        tokio::fs::write(&stdout_file, output_str.as_bytes()).await?;
        tokio::fs::write(&stderr_file, error_str.as_bytes()).await?;
        tokio::fs::write(&report_file, serde_json::to_vec_pretty(&report)?).await?;

        let findings_detected = report.detected_classes();

        log::info!("LSan escalation completed: {}", report_file.display());
        Ok(EscalationResult {
            id: escalation_id.to_string(),
            finding_id: finding_id.to_string(),
            tool: "lsan".to_string(),
            success: true,
            tool_available: true,
            duration_ms: start_time.elapsed().as_millis() as u64,
            output_path: Some(report_file.display().to_string()),
            stdout_path: Some(stdout_file.display().to_string()),
            stderr_path: Some(stderr_file.display().to_string()),
            report_path: Some(report_file.display().to_string()),
            command,
            exit_code: output.status.code(),
            confirmed: report.confirmed(),
            error: None,
            findings_detected,
            timestamp: unix_timestamp(),
        })
    }

    async fn run_ubsan_binary(
        &self,
        finding_id: &str,
        binary_path: &Path,
        escalation_id: &str,
        start_time: Instant,
    ) -> Result<EscalationResult> {
        if !self.binary_looks_ubsan_instrumented(binary_path).await? {
            return Ok(self.result_failure(
                finding_id,
                escalation_id,
                "ubsan",
                false,
                start_time.elapsed().as_millis() as u64,
                format!(
                    "UBSan requires a binary built with -fsanitize=undefined: {}",
                    binary_path.display()
                ),
            ));
        }

        let output_dir = Path::new(&self.config.output_dir).join("ubsan");
        tokio::fs::create_dir_all(&output_dir).await?;

        let stdout_file = output_dir.join(format!("ubsan_{}.stdout.log", escalation_id));
        let stderr_file = output_dir.join(format!("ubsan_{}.stderr.log", escalation_id));
        let report_file = output_dir.join(format!("ubsan_{}.json", escalation_id));

        let executable_path = canonical_binary_path(binary_path);
        let mut cmd = TokioCommand::new(&executable_path);
        let mut command = vec![executable_path.display().to_string()];
        for arg in &self.config.args {
            cmd.arg(arg);
            command.push(arg.clone());
        }

        let runtime_flags = self.config.tools.ubsan.runtime_flags.join(":");
        cmd.env("UBSAN_OPTIONS", runtime_flags);
        self.apply_cwd(&mut cmd, &mut command);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.ubsan.timeout_ms);
        let output = timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| EscalationError::Timeout("UBSan execution timed out".to_string()))?;

        let output = output.map_err(|error| EscalationError::ToolExecution(error.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        let report = parse_ubsan_output(&output_str, &error_str);

        tokio::fs::write(&stdout_file, output_str.as_bytes()).await?;
        tokio::fs::write(&stderr_file, error_str.as_bytes()).await?;
        tokio::fs::write(&report_file, serde_json::to_vec_pretty(&report)?).await?;

        let findings_detected = report.detected_classes();

        log::info!("UBSan escalation completed: {}", report_file.display());
        Ok(EscalationResult {
            id: escalation_id.to_string(),
            finding_id: finding_id.to_string(),
            tool: "ubsan".to_string(),
            success: true,
            tool_available: true,
            duration_ms: start_time.elapsed().as_millis() as u64,
            output_path: Some(report_file.display().to_string()),
            stdout_path: Some(stdout_file.display().to_string()),
            stderr_path: Some(stderr_file.display().to_string()),
            report_path: Some(report_file.display().to_string()),
            command,
            exit_code: output.status.code(),
            confirmed: report.confirmed(),
            error: None,
            findings_detected,
            timestamp: unix_timestamp(),
        })
    }

    /// Run Valgrind escalation
    async fn run_valgrind_escalation(
        &self,
        finding: &Finding,
        escalation_id: &str,
    ) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.valgrind.enabled {
            return Ok(self.failure_result(
                finding,
                escalation_id,
                "valgrind",
                false,
                start_time.elapsed().as_millis() as u64,
                "Valgrind escalation is disabled".to_string(),
            ));
        }

        // Find the binary for the finding
        let binary_path = self.find_binary(finding)?;
        self.run_valgrind_binary(&finding.id, &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_valgrind_clean_check(&self, escalation_id: &str) -> Result<EscalationResult> {
        let start_time = Instant::now();
        if !self.config.tools.valgrind.enabled {
            return Ok(self.result_failure(
                "clean-run",
                escalation_id,
                "valgrind",
                false,
                start_time.elapsed().as_millis() as u64,
                "Valgrind escalation is disabled".to_string(),
            ));
        }

        let binary_path = self
            .config
            .binary_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .ok_or_else(|| {
                EscalationError::Config(
                    "Clean Valgrind check requires an existing binary_path".to_string(),
                )
            })?;

        self.run_valgrind_binary("clean-run", &binary_path, escalation_id, start_time)
            .await
    }

    async fn run_valgrind_binary(
        &self,
        finding_id: &str,
        binary_path: &Path,
        escalation_id: &str,
        start_time: Instant,
    ) -> Result<EscalationResult> {
        let output_dir = Path::new(&self.config.output_dir).join("valgrind");
        tokio::fs::create_dir_all(&output_dir).await?;

        let stdout_file = output_dir.join(format!("valgrind_{}.stdout.log", escalation_id));
        let stderr_file = output_dir.join(format!("valgrind_{}.stderr.log", escalation_id));
        let report_file = output_dir.join(format!("valgrind_{}.json", escalation_id));

        // Run with Valgrind
        let mut cmd = TokioCommand::new("valgrind");
        let mut command = vec!["valgrind".to_string()];
        for flag in &self.config.tools.valgrind.flags {
            cmd.arg(flag);
            command.push(flag.clone());
        }
        let executable_path = canonical_binary_path(binary_path);
        cmd.arg(&executable_path);
        command.push(executable_path.display().to_string());
        for arg in &self.config.args {
            cmd.arg(arg);
            command.push(arg.clone());
        }
        self.apply_cwd(&mut cmd, &mut command);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.valgrind.timeout_ms);
        let output = timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| EscalationError::Timeout("Valgrind execution timed out".to_string()))?;

        let output = match output {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(self.result_failure(
                    finding_id,
                    escalation_id,
                    "valgrind",
                    false,
                    start_time.elapsed().as_millis() as u64,
                    "valgrind not found in PATH".to_string(),
                ));
            }
            Err(error) => return Err(EscalationError::ToolExecution(error.to_string())),
        };

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        let report = parse_valgrind_output(&output_str, &error_str);

        tokio::fs::write(&stdout_file, output_str.as_bytes()).await?;
        tokio::fs::write(&stderr_file, error_str.as_bytes()).await?;
        tokio::fs::write(&report_file, serde_json::to_vec_pretty(&report)?).await?;

        let findings_detected = report.detected_classes();

        log::info!("Valgrind escalation completed: {}", report_file.display());
        Ok(EscalationResult {
            id: escalation_id.to_string(),
            finding_id: finding_id.to_string(),
            tool: "valgrind".to_string(),
            success: true,
            tool_available: true,
            duration_ms: start_time.elapsed().as_millis() as u64,
            output_path: Some(report_file.display().to_string()),
            stdout_path: Some(stdout_file.display().to_string()),
            stderr_path: Some(stderr_file.display().to_string()),
            report_path: Some(report_file.display().to_string()),
            command,
            exit_code: output.status.code(),
            confirmed: report.confirmed(),
            error: None,
            findings_detected,
            timestamp: unix_timestamp(),
        })
    }

    /// Run GDB escalation
    async fn run_gdb_escalation(&self, finding: &Finding, escalation_id: &str) -> Result<String> {
        if !self.config.tools.gdb.enabled {
            return Err(EscalationError::Config(
                "GDB escalation is disabled".to_string(),
            ));
        }

        let output_dir = Path::new(&self.config.output_dir).join("gdb");
        tokio::fs::create_dir_all(&output_dir).await?;

        // Find the binary for the finding
        let binary_path = self.find_binary(finding)?;
        let output_file = output_dir.join(format!("gdb_{}.log", escalation_id));

        // Create GDB script
        let gdb_script = self.config.tools.gdb.commands.join("\n");
        let script_file = output_dir.join(format!("gdb_script_{}.gdb", escalation_id));
        tokio::fs::write(&script_file, &gdb_script).await?;

        // Run GDB
        let mut cmd = TokioCommand::new("gdb");
        cmd.args(&[
            "-batch",
            "-x",
            script_file.to_str().unwrap(),
            binary_path.to_str().unwrap(),
        ]);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.gdb.timeout_ms);
        let output = timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| EscalationError::Timeout("GDB execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        let full_output = format!("STDOUT:\n{}\nSTDERR:\n{}", output_str, error_str);

        // Save output
        tokio::fs::write(&output_file, &full_output).await?;

        log::info!("GDB escalation completed: {}", output_file.display());
        Ok(output_file.to_string_lossy().to_string())
    }

    /// Find binary for a finding
    fn find_binary(&self, finding: &Finding) -> Result<PathBuf> {
        if let Some(path) = finding
            .provenance
            .as_ref()
            .and_then(|provenance| provenance.binary_path.as_deref())
            .map(PathBuf::from)
            .filter(|path| path.exists())
        {
            return Ok(path);
        }

        if let Some(path) = finding
            .provenance
            .as_ref()
            .and_then(|provenance| provenance.original_binary_path.as_deref())
            .map(PathBuf::from)
            .filter(|path| path.exists())
        {
            return Ok(path);
        }

        if let Some(binary_path) = &self.config.binary_path {
            let path = PathBuf::from(binary_path);
            if path.exists() {
                return Ok(path);
            }
        }

        Err(EscalationError::Config(format!(
            "Could not find binary for finding {}",
            finding.id
        )))
    }

    fn apply_cwd(&self, cmd: &mut TokioCommand, command: &mut Vec<String>) {
        if let Some(cwd) = self.config.cwd.as_deref() {
            cmd.current_dir(cwd);
            command.splice(0..0, ["cwd".to_string(), cwd.to_string()]);
        }
    }

    async fn binary_looks_asan_instrumented(&self, binary_path: &Path) -> Result<bool> {
        let bytes = tokio::fs::read(binary_path).await?;
        let haystack = String::from_utf8_lossy(&bytes);
        Ok(haystack.contains("__asan_")
            || haystack.contains("libasan")
            || haystack.contains("AddressSanitizer"))
    }

    async fn binary_looks_lsan_instrumented(&self, binary_path: &Path) -> Result<bool> {
        let bytes = tokio::fs::read(binary_path).await?;
        let haystack = String::from_utf8_lossy(&bytes);
        Ok(haystack.contains("__lsan_")
            || haystack.contains("liblsan")
            || haystack.contains("LeakSanitizer"))
    }

    async fn binary_looks_ubsan_instrumented(&self, binary_path: &Path) -> Result<bool> {
        let bytes = tokio::fs::read(binary_path).await?;
        let haystack = String::from_utf8_lossy(&bytes);
        Ok(haystack.contains("__ubsan_")
            || haystack.contains("libubsan")
            || haystack.contains("UndefinedBehaviorSanitizer"))
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn canonical_binary_path(binary_path: &Path) -> PathBuf {
    std::fs::canonicalize(binary_path).unwrap_or_else(|_| binary_path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use re_crashpack::{
        EscalationPlan, Evidence, FindingProvenance, MemoryEvidence, StackEvidence,
    };
    use std::fs;

    fn sample_finding() -> Finding {
        Finding {
            schema_version: "1.0".to_string(),
            id: "F-test".to_string(),
            class: "heap_overflow".to_string(),
            confidence: "high".to_string(),
            severity: "high".to_string(),
            timestamp: 0,
            pid: 1,
            evidence: Evidence {
                memory: Some(MemoryEvidence {
                    ptr: 0,
                    size: 1,
                    alloc_size: 1,
                    operation: "memcpy".to_string(),
                }),
                resource: None,
                stacks: Some(StackEvidence {
                    alloc: Vec::new(),
                    call: Vec::new(),
                    open: Vec::new(),
                    action: Vec::new(),
                }),
                alloc_site: None,
                event_sequence: None,
            },
            escalation: Some(EscalationPlan {
                tool: "asan".to_string(),
                reason: "test".to_string(),
                estimated_cost: "low".to_string(),
                cooldown_ms: 0,
            }),
            provenance: None,
            related: Vec::new(),
        }
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("recompile-{}-{}", name, Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn find_binary_prefers_finding_provenance() {
        let dir = unique_test_dir("binary");
        let crashpack_binary = dir.join("copied-bin");
        fs::write(&crashpack_binary, b"binary").unwrap();

        let mut finding = sample_finding();
        finding.provenance = Some(FindingProvenance {
            binary_path: Some(crashpack_binary.display().to_string()),
            original_binary_path: Some("/does/not/exist".to_string()),
            source_path: None,
            source_status: None,
        });

        let mut config = EscalationConfig::default();
        config.binary_path = Some("/also/missing".to_string());
        let runner = EscalationRunner::new(config);

        let resolved = runner.find_binary(&finding).unwrap();
        assert_eq!(resolved, crashpack_binary);
    }

    #[tokio::test]
    async fn detects_asan_instrumentation_markers() {
        let dir = unique_test_dir("asan-marker");
        let binary = dir.join("target-bin");
        fs::write(&binary, b"\0__asan_init\0").unwrap();

        let runner = EscalationRunner::new(EscalationConfig::default());
        assert!(runner
            .binary_looks_asan_instrumented(&binary)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rejects_non_asan_binaries() {
        let dir = unique_test_dir("non-asan-marker");
        let binary = dir.join("target-bin");
        fs::write(&binary, b"plain elf-ish bytes").unwrap();

        let runner = EscalationRunner::new(EscalationConfig::default());
        assert!(!runner
            .binary_looks_asan_instrumented(&binary)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn detects_lsan_instrumentation_markers() {
        let dir = unique_test_dir("lsan-marker");
        let binary = dir.join("target-bin");
        fs::write(&binary, b"\0__lsan_init\0").unwrap();

        let runner = EscalationRunner::new(EscalationConfig::default());
        assert!(runner
            .binary_looks_lsan_instrumented(&binary)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rejects_non_lsan_binaries() {
        let dir = unique_test_dir("non-lsan-marker");
        let binary = dir.join("target-bin");
        fs::write(&binary, b"plain elf-ish bytes").unwrap();

        let runner = EscalationRunner::new(EscalationConfig::default());
        assert!(!runner
            .binary_looks_lsan_instrumented(&binary)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn detects_ubsan_instrumentation_markers() {
        let dir = unique_test_dir("ubsan-marker");
        let binary = dir.join("target-bin");
        fs::write(&binary, b"\0__ubsan_handle_add_overflow\0").unwrap();

        let runner = EscalationRunner::new(EscalationConfig::default());
        assert!(runner
            .binary_looks_ubsan_instrumented(&binary)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rejects_non_ubsan_binaries() {
        let dir = unique_test_dir("non-ubsan-marker");
        let binary = dir.join("target-bin");
        fs::write(&binary, b"plain elf-ish bytes").unwrap();

        let runner = EscalationRunner::new(EscalationConfig::default());
        assert!(!runner
            .binary_looks_ubsan_instrumented(&binary)
            .await
            .unwrap());
    }
}
