//! Escalation runner - orchestrates tool execution

use crate::{
    EscalationConfig, EscalationError, EscalationResult, Finding, Result,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};
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
        let escalation_plan = finding.escalation.as_ref()
            .ok_or_else(|| EscalationError::Config("No escalation plan in finding".to_string()))?;

        // Check cooldown
        if self.is_in_cooldown(&escalation_plan.tool) {
            return Err(EscalationError::Config(format!(
                "Tool {} is in cooldown",
                escalation_plan.tool
            )));
        }

        log::info!("Escalating finding {} with tool {}", finding.id, escalation_plan.tool);

        let start_time = Instant::now();
        let escalation_id = Uuid::new_v4().to_string();

        let result = match escalation_plan.tool.as_str() {
            "asan" => self.run_asan_escalation(finding, &escalation_id).await,
            "valgrind" => self.run_valgrind_escalation(finding, &escalation_id).await,
            "gdb" => self.run_gdb_escalation(finding, &escalation_id).await,
            tool => Err(EscalationError::Config(format!("Unknown escalation tool: {}", tool))),
        };

        let duration = start_time.elapsed();
        let (success, output_path, error) = match result {
            Ok(path) => (true, Some(path), None),
            Err(err) => (false, None, Some(err.to_string())),
        };

        let escalation_result = EscalationResult {
            id: escalation_id,
            tool: escalation_plan.tool.clone(),
            success,
            duration_ms: duration.as_millis() as u64,
            output_path,
            error,
            findings_detected: Vec::new(), // Will be populated by tool-specific results
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Update cooldown
        self.update_cooldown(&escalation_plan.tool, escalation_plan.cooldown_ms);

        Ok(escalation_result)
    }

    /// Check if a tool is in cooldown
    fn is_in_cooldown(&self, tool: &str) -> bool {
        if let Some(last_run) = self.cooldowns.get(tool) {
            let cooldown_duration = std::time::Duration::from_millis(
                self.config.cooldowns.per_tool.get(tool)
                    .copied()
                    .unwrap_or(self.config.cooldowns.default_ms) as u64
            );
            last_run.elapsed() < cooldown_duration
        } else {
            false
        }
    }

    /// Update cooldown for a tool
    fn update_cooldown(&mut self, tool: &str, cooldown_ms: u32) {
        self.cooldowns.insert(tool.to_string(), Instant::now());
    }

    /// Run ASan escalation
    async fn run_asan_escalation(&self, finding: &Finding, escalation_id: &str) -> Result<String> {
        if !self.config.tools.asan.enabled {
            return Err(EscalationError::Config("ASan escalation is disabled".to_string()));
        }

        let output_dir = Path::new(&self.config.output_dir).join("asan");
        tokio::fs::create_dir_all(&output_dir).await?;

        // Find the source file for the finding
        let source_file = self.find_source_file(finding)?;
        let binary_name = format!("{}_{}", finding.class, escalation_id);
        let binary_path = output_dir.join(&binary_name);
        let output_file = output_dir.join(format!("{}.log", binary_name));

        // Compile with ASan
        self.compile_with_asan(&source_file, &binary_path).await?;

        // Run with ASan
        let runtime_flags = self.config.tools.asan.runtime_flags.join(":");
        let env_vars = vec![("ASAN_OPTIONS", runtime_flags.as_str())];

        let output = self.run_binary_with_env(&binary_path, &env_vars).await?;

        // Save output
        tokio::fs::write(&output_file, &output).await?;

        log::info!("ASan escalation completed: {}", output_file.display());
        Ok(output_file.to_string_lossy().to_string())
    }

    /// Run Valgrind escalation
    async fn run_valgrind_escalation(&self, finding: &Finding, escalation_id: &str) -> Result<String> {
        if !self.config.tools.valgrind.enabled {
            return Err(EscalationError::Config("Valgrind escalation is disabled".to_string()));
        }

        let output_dir = Path::new(&self.config.output_dir).join("valgrind");
        tokio::fs::create_dir_all(&output_dir).await?;

        // Find the binary for the finding
        let binary_path = self.find_binary(finding)?;
        let output_file = output_dir.join(format!("valgrind_{}.log", escalation_id));

        // Run with Valgrind
        let mut cmd = TokioCommand::new("valgrind");
        for flag in &self.config.tools.valgrind.flags {
            cmd.arg(flag);
        }
        cmd.arg(&binary_path);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.valgrind.timeout_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Valgrind execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        let full_output = format!("STDOUT:\n{}\nSTDERR:\n{}", output_str, error_str);

        // Save output
        tokio::fs::write(&output_file, &full_output).await?;

        log::info!("Valgrind escalation completed: {}", output_file.display());
        Ok(output_file.to_string_lossy().to_string())
    }

    /// Run GDB escalation
    async fn run_gdb_escalation(&self, finding: &Finding, escalation_id: &str) -> Result<String> {
        if !self.config.tools.gdb.enabled {
            return Err(EscalationError::Config("GDB escalation is disabled".to_string()));
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
        cmd.args(&["-batch", "-x", script_file.to_str().unwrap(), binary_path.to_str().unwrap()]);

        let timeout_duration = TokioDuration::from_millis(self.config.tools.gdb.timeout_ms);
        let output = timeout(timeout_duration, cmd.output()).await
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

    /// Find source file for a finding
    fn find_source_file(&self, finding: &Finding) -> Result<PathBuf> {
        // Try to find source file based on finding class
        let possible_paths = vec![
            format!("examples/{}.c", finding.class),
            format!("build/examples/{}.c", finding.class),
            format!("runtime/examples/{}.c", finding.class),
        ];

        for path in possible_paths {
            let path_buf = PathBuf::from(path);
            if path_buf.exists() {
                return Ok(path_buf);
            }
        }

        Err(EscalationError::Config(format!(
            "Could not find source file for finding class: {}",
            finding.class
        )))
    }

    /// Find binary for a finding
    fn find_binary(&self, finding: &Finding) -> Result<PathBuf> {
        // Try to find binary based on finding class
        let possible_paths = vec![
            format!("build/examples/{}", finding.class),
            format!("examples/{}", finding.class),
            format!("runtime/examples/{}", finding.class),
        ];

        for path in possible_paths {
            let path_buf = PathBuf::from(path);
            if path_buf.exists() {
                return Ok(path_buf);
            }
        }

        Err(EscalationError::Config(format!(
            "Could not find binary for finding class: {}",
            finding.class
        )))
    }

    /// Compile source with ASan
    async fn compile_with_asan(&self, source_file: &Path, output_file: &Path) -> Result<()> {
        let mut cmd = TokioCommand::new("clang");
        
        // Add ASan flags
        for flag in &self.config.tools.asan.compile_flags {
            cmd.arg(flag);
        }
        
        cmd.arg(source_file);
        cmd.arg("-o");
        cmd.arg(output_file);

        let timeout_duration = TokioDuration::from_millis(self.config.timeouts.compile_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Compilation timed out".to_string()))?
            .map_err(|e| EscalationError::Compilation(e.to_string()))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(EscalationError::Compilation(error.to_string()));
        }

        Ok(())
    }

    /// Run binary with environment variables
    async fn run_binary_with_env(&self, binary_path: &Path, env_vars: &[(&str, &str)]) -> Result<String> {
        let mut cmd = TokioCommand::new(binary_path);
        
        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let timeout_duration = TokioDuration::from_millis(self.config.timeouts.run_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Binary execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }
}
