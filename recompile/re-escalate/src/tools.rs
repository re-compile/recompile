//! Tool-specific escalation implementations

use crate::{EscalationConfig, EscalationError, Result};
use std::path::Path;
use tokio::process::Command as TokioCommand;
use tokio::time::{timeout, Duration};

/// ASan tool implementation
pub struct AsanTool {
    config: EscalationConfig,
}

impl AsanTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run ASan analysis on a source file
    pub async fn analyze(&self, source_file: &Path, output_dir: &Path) -> Result<String> {
        let binary_name = format!("asan_{}", uuid::Uuid::new_v4());
        let binary_path = output_dir.join(&binary_name);
        let output_file = output_dir.join(format!("{}.log", binary_name));

        // Compile with ASan
        self.compile_with_asan(source_file, &binary_path).await?;

        // Run with ASan
        let runtime_flags = self.config.tools.asan.runtime_flags.join(":");
        let env_vars = vec![("ASAN_OPTIONS", runtime_flags.as_str())];

        let output = self.run_binary_with_env(&binary_path, &env_vars).await?;

        // Parse ASan output for memory errors
        let parsed_output = self.parse_asan_output(&output)?;
        
        // Save both raw and parsed output
        tokio::fs::write(&output_file, &output).await?;
        
        let parsed_file = output_file.with_extension("parsed.json");
        tokio::fs::write(&parsed_file, &parsed_output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    async fn compile_with_asan(&self, source_file: &Path, output_file: &Path) -> Result<()> {
        let mut cmd = TokioCommand::new("clang");
        
        // Add ASan flags
        for flag in &self.config.tools.asan.compile_flags {
            cmd.arg(flag);
        }
        
        cmd.arg(source_file);
        cmd.arg("-o");
        cmd.arg(output_file);

        let timeout_duration = Duration::from_millis(self.config.timeouts.compile_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Compilation timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(EscalationError::ToolExecution(error.to_string()));
        }

        Ok(())
    }

    async fn run_binary_with_env(&self, binary_path: &Path, env_vars: &[(&str, &str)]) -> Result<String> {
        let mut cmd = TokioCommand::new(binary_path);
        
        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let timeout_duration = Duration::from_millis(self.config.timeouts.run_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Binary execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }

    /// Parse ASan output for memory errors
    fn parse_asan_output(&self, output: &str) -> Result<String> {
        let mut errors = Vec::new();
        
        // Parse ASan error patterns
        let error_patterns = [
            ("Heap buffer overflow", "heap-buffer-overflow"),
            ("Stack buffer overflow", "stack-buffer-overflow"),
            ("Use after free", "use-after-free"),
            ("Double free", "double-free"),
            ("Memory leak", "detected memory leaks"),
            ("Address sanitizer", "AddressSanitizer"),
        ];

        for (error_type, pattern) in &error_patterns {
            if output.contains(pattern) {
                let lines: Vec<&str> = output.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.contains(pattern) {
                        // Extract context around the error
                        let start = if i > 2 { i - 2 } else { 0 };
                        let end = if i + 5 < lines.len() { i + 5 } else { lines.len() };
                        let context: Vec<&str> = lines[start..end].to_vec();
                        
                        let error_info = AsanError {
                            error_type: error_type.to_string(),
                            pattern: pattern.to_string(),
                            context: context.join("\n"),
                            line_number: i + 1,
                        };
                        errors.push(error_info);
                    }
                }
            }
        }

        let total_errors = errors.len();
        let summary = if total_errors == 0 {
            "No ASan errors detected".to_string()
        } else {
            format!("Found {} ASan errors", total_errors)
        };

        let analysis = AsanAnalysis {
            total_errors,
            errors,
            summary,
        };

        serde_json::to_string_pretty(&analysis)
            .map_err(|e| EscalationError::OutputParsing(e.to_string()))
    }
}

/// Valgrind tool implementation
pub struct ValgrindTool {
    config: EscalationConfig,
}

impl ValgrindTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run Valgrind analysis on a binary
    pub async fn analyze(&self, binary_path: &Path, output_dir: &Path) -> Result<String> {
        let output_file = output_dir.join(format!("valgrind_{}.log", uuid::Uuid::new_v4()));

        // Run with Valgrind
        let mut cmd = TokioCommand::new("valgrind");
        for flag in &self.config.tools.valgrind.flags {
            cmd.arg(flag);
        }
        cmd.arg(binary_path);

        let timeout_duration = Duration::from_millis(self.config.tools.valgrind.timeout_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Valgrind execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        
        // Parse Valgrind output for errors
        let parsed_output = self.parse_valgrind_output(&output_str, &error_str)?;
        
        // Save both raw and parsed output
        let raw_output = format!("STDOUT:\n{}\nSTDERR:\n{}", output_str, error_str);
        tokio::fs::write(&output_file, &raw_output).await?;
        
        let parsed_file = output_file.with_extension("parsed.json");
        tokio::fs::write(&parsed_file, &parsed_output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    /// Parse Valgrind output for memory errors and leaks
    fn parse_valgrind_output(&self, stdout: &str, stderr: &str) -> Result<String> {
        let mut errors = Vec::new();
        let mut leaks = Vec::new();
        
        // Parse error patterns
        let error_patterns = [
            ("Invalid read", "Invalid read of size"),
            ("Invalid write", "Invalid write of size"),
            ("Use after free", "Invalid read of size"),
            ("Double free", "Invalid free()"),
            ("Memory leak", "definitely lost"),
            ("Possible leak", "possibly lost"),
            ("Still reachable", "still reachable"),
        ];

        let full_output = format!("{}\n{}", stdout, stderr);
        
        for (error_type, pattern) in &error_patterns {
            if full_output.contains(pattern) {
                let lines: Vec<&str> = full_output.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.contains(pattern) {
                        // Extract context around the error
                        let start = if i > 2 { i - 2 } else { 0 };
                        let end = if i + 3 < lines.len() { i + 3 } else { lines.len() };
                        let context: Vec<&str> = lines[start..end].to_vec();
                        
                        let error_info = ValgrindError {
                            error_type: error_type.to_string(),
                            pattern: pattern.to_string(),
                            context: context.join("\n"),
                            line_number: i + 1,
                        };
                        
                        if error_type.contains("leak") {
                            leaks.push(error_info);
                        } else {
                            errors.push(error_info);
                        }
                    }
                }
            }
        }

        let total_errors = errors.len();
        let total_leaks = leaks.len();
        let summary_text = if total_errors == 0 && total_leaks == 0 {
            "No Valgrind errors or leaks detected".to_string()
        } else {
            format!("Found {} errors and {} leaks", total_errors, total_leaks)
        };

        let summary = ValgrindSummary {
            total_errors,
            total_leaks,
            errors,
            leaks,
            summary: summary_text,
        };

        serde_json::to_string_pretty(&summary)
            .map_err(|e| EscalationError::OutputParsing(e.to_string()))
    }
}

#[derive(serde::Serialize)]
struct ValgrindError {
    error_type: String,
    pattern: String,
    context: String,
    line_number: usize,
}

#[derive(serde::Serialize)]
struct ValgrindSummary {
    total_errors: usize,
    total_leaks: usize,
    errors: Vec<ValgrindError>,
    leaks: Vec<ValgrindError>,
    summary: String,
}

/// TSan (Thread Sanitizer) tool implementation
pub struct TsanTool {
    config: EscalationConfig,
}

impl TsanTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run TSan analysis on a source file
    pub async fn analyze(&self, source_file: &Path, output_dir: &Path) -> Result<String> {
        let binary_name = format!("tsan_{}", uuid::Uuid::new_v4());
        let binary_path = output_dir.join(&binary_name);
        let output_file = output_dir.join(format!("{}.log", binary_name));

        // Compile with TSan
        self.compile_with_tsan(source_file, &binary_path).await?;

        // Run with TSan
        let runtime_flags = self.config.tools.asan.runtime_flags.join(":"); // Reuse ASan config for now
        let env_vars = vec![("TSAN_OPTIONS", runtime_flags.as_str())];

        let output = self.run_binary_with_env(&binary_path, &env_vars).await?;

        // Save output
        tokio::fs::write(&output_file, &output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    async fn compile_with_tsan(&self, source_file: &Path, output_file: &Path) -> Result<()> {
        let mut cmd = TokioCommand::new("clang");
        
        // Add TSan flags
        cmd.args(&["-fsanitize=thread", "-g", "-O1"]);
        
        cmd.arg(source_file);
        cmd.arg("-o");
        cmd.arg(output_file);

        let timeout_duration = Duration::from_millis(self.config.timeouts.compile_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Compilation timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(EscalationError::ToolExecution(error.to_string()));
        }

        Ok(())
    }

    async fn run_binary_with_env(&self, binary_path: &Path, env_vars: &[(&str, &str)]) -> Result<String> {
        let mut cmd = TokioCommand::new(binary_path);
        
        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let timeout_duration = Duration::from_millis(self.config.timeouts.run_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Binary execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }
}

/// MSan (Memory Sanitizer) tool implementation
pub struct MsanTool {
    config: EscalationConfig,
}

impl MsanTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run MSan analysis on a source file
    pub async fn analyze(&self, source_file: &Path, output_dir: &Path) -> Result<String> {
        let binary_name = format!("msan_{}", uuid::Uuid::new_v4());
        let binary_path = output_dir.join(&binary_name);
        let output_file = output_dir.join(format!("{}.log", binary_name));

        // Compile with MSan
        self.compile_with_msan(source_file, &binary_path).await?;

        // Run with MSan
        let runtime_flags = self.config.tools.asan.runtime_flags.join(":"); // Reuse ASan config for now
        let env_vars = vec![("MSAN_OPTIONS", runtime_flags.as_str())];

        let output = self.run_binary_with_env(&binary_path, &env_vars).await?;

        // Save output
        tokio::fs::write(&output_file, &output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    async fn compile_with_msan(&self, source_file: &Path, output_file: &Path) -> Result<()> {
        let mut cmd = TokioCommand::new("clang");
        
        // Add MSan flags
        cmd.args(&["-fsanitize=memory", "-g", "-O1"]);
        
        cmd.arg(source_file);
        cmd.arg("-o");
        cmd.arg(output_file);

        let timeout_duration = Duration::from_millis(self.config.timeouts.compile_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Compilation timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(EscalationError::ToolExecution(error.to_string()));
        }

        Ok(())
    }

    async fn run_binary_with_env(&self, binary_path: &Path, env_vars: &[(&str, &str)]) -> Result<String> {
        let mut cmd = TokioCommand::new(binary_path);
        
        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let timeout_duration = Duration::from_millis(self.config.timeouts.run_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Binary execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }
}

/// UBSan (Undefined Behavior Sanitizer) tool implementation
pub struct UbsanTool {
    config: EscalationConfig,
}

impl UbsanTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run UBSan analysis on a source file
    pub async fn analyze(&self, source_file: &Path, output_dir: &Path) -> Result<String> {
        let binary_name = format!("ubsan_{}", uuid::Uuid::new_v4());
        let binary_path = output_dir.join(&binary_name);
        let output_file = output_dir.join(format!("{}.log", binary_name));

        // Compile with UBSan
        self.compile_with_ubsan(source_file, &binary_path).await?;

        // Run with UBSan
        let runtime_flags = self.config.tools.asan.runtime_flags.join(":"); // Reuse ASan config for now
        let env_vars = vec![("UBSAN_OPTIONS", runtime_flags.as_str())];

        let output = self.run_binary_with_env(&binary_path, &env_vars).await?;

        // Save output
        tokio::fs::write(&output_file, &output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    async fn compile_with_ubsan(&self, source_file: &Path, output_file: &Path) -> Result<()> {
        let mut cmd = TokioCommand::new("clang");
        
        // Add UBSan flags
        cmd.args(&["-fsanitize=undefined", "-g", "-O1"]);
        
        cmd.arg(source_file);
        cmd.arg("-o");
        cmd.arg(output_file);

        let timeout_duration = Duration::from_millis(self.config.timeouts.compile_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Compilation timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(EscalationError::ToolExecution(error.to_string()));
        }

        Ok(())
    }

    async fn run_binary_with_env(&self, binary_path: &Path, env_vars: &[(&str, &str)]) -> Result<String> {
        let mut cmd = TokioCommand::new(binary_path);
        
        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let timeout_duration = Duration::from_millis(self.config.timeouts.run_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Binary execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }
}

/// LSan (Leak Sanitizer) tool implementation
pub struct LsanTool {
    config: EscalationConfig,
}

impl LsanTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run LSan analysis on a source file
    pub async fn analyze(&self, source_file: &Path, output_dir: &Path) -> Result<String> {
        let binary_name = format!("lsan_{}", uuid::Uuid::new_v4());
        let binary_path = output_dir.join(&binary_name);
        let output_file = output_dir.join(format!("{}.log", binary_name));

        // Compile with LSan
        self.compile_with_lsan(source_file, &binary_path).await?;

        // Run with LSan
        let runtime_flags = self.config.tools.asan.runtime_flags.join(":"); // Reuse ASan config for now
        let env_vars = vec![("LSAN_OPTIONS", runtime_flags.as_str())];

        let output = self.run_binary_with_env(&binary_path, &env_vars).await?;

        // Save output
        tokio::fs::write(&output_file, &output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    async fn compile_with_lsan(&self, source_file: &Path, output_file: &Path) -> Result<()> {
        let mut cmd = TokioCommand::new("clang");
        
        // Add LSan flags (LSan is part of ASan)
        cmd.args(&["-fsanitize=leak", "-g", "-O1"]);
        
        cmd.arg(source_file);
        cmd.arg("-o");
        cmd.arg(output_file);

        let timeout_duration = Duration::from_millis(self.config.timeouts.compile_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Compilation timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(EscalationError::ToolExecution(error.to_string()));
        }

        Ok(())
    }

    async fn run_binary_with_env(&self, binary_path: &Path, env_vars: &[(&str, &str)]) -> Result<String> {
        let mut cmd = TokioCommand::new(binary_path);
        
        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let timeout_duration = Duration::from_millis(self.config.timeouts.run_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("Binary execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }
}

/// GDB tool implementation
pub struct GdbTool {
    config: EscalationConfig,
}

impl GdbTool {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Run GDB analysis on a binary
    pub async fn analyze(&self, binary_path: &Path, output_dir: &Path) -> Result<String> {
        let output_file = output_dir.join(format!("gdb_{}.log", uuid::Uuid::new_v4()));

        // Create GDB script with dynamic breakpoints
        let gdb_script = self.generate_gdb_script(binary_path)?;
        let script_file = output_dir.join(format!("gdb_script_{}.gdb", uuid::Uuid::new_v4()));
        tokio::fs::write(&script_file, &gdb_script).await?;

        // Run GDB
        let mut cmd = TokioCommand::new("gdb");
        cmd.args(&["-batch", "-x", script_file.to_str().unwrap(), binary_path.to_str().unwrap()]);

        let timeout_duration = Duration::from_millis(self.config.tools.gdb.timeout_ms);
        let output = timeout(timeout_duration, cmd.output()).await
            .map_err(|_| EscalationError::Timeout("GDB execution timed out".to_string()))?
            .map_err(|e| EscalationError::ToolExecution(e.to_string()))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let error_str = String::from_utf8_lossy(&output.stderr);
        
        // Parse GDB output for debugging information
        let parsed_output = self.parse_gdb_output(&output_str, &error_str)?;
        
        // Save both raw and parsed output
        let raw_output = format!("STDOUT:\n{}\nSTDERR:\n{}", output_str, error_str);
        tokio::fs::write(&output_file, &raw_output).await?;
        
        let parsed_file = output_file.with_extension("parsed.json");
        tokio::fs::write(&parsed_file, &parsed_output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }

    /// Generate dynamic GDB script based on finding type
    fn generate_gdb_script(&self, binary_path: &Path) -> Result<String> {
        let mut script = Vec::new();
        
        // Basic setup
        script.push("set pagination off".to_string());
        script.push("set confirm off".to_string());
        script.push("set print pretty on".to_string());
        script.push("set print array on".to_string());
        script.push("set print array-indexes on".to_string());
        
        // Add dynamic breakpoints based on common memory issues
        script.push("break malloc".to_string());
        script.push("break free".to_string());
        script.push("break calloc".to_string());
        script.push("break realloc".to_string());
        
        // Add memory access breakpoints for common functions
        script.push("break memcpy".to_string());
        script.push("break memmove".to_string());
        script.push("break memset".to_string());
        script.push("break strcpy".to_string());
        script.push("break strcat".to_string());
        
        // Add conditional breakpoints for specific patterns
        script.push("break abort".to_string());
        script.push("break exit".to_string());
        
        // Add custom commands from config
        for command in &self.config.tools.gdb.commands {
            script.push(command.clone());
        }
        
        // Add information gathering commands
        script.push("info registers".to_string());
        script.push("info proc mappings".to_string());
        script.push("info threads".to_string());
        script.push("thread apply all bt".to_string());
        
        // Add memory inspection commands
        script.push("x/20x $rsp".to_string()); // Stack inspection
        script.push("x/20x $rbp".to_string()); // Base pointer inspection
        
        // Quit GDB
        script.push("quit".to_string());
        
        Ok(script.join("\n"))
    }

    /// Parse GDB output for debugging information
    fn parse_gdb_output(&self, stdout: &str, stderr: &str) -> Result<String> {
        let mut analysis = GdbAnalysis {
            breakpoints_hit: Vec::new(),
            stack_traces: Vec::new(),
            memory_regions: Vec::new(),
            register_values: Vec::new(),
            errors: Vec::new(),
            summary: String::new(),
        };

        let full_output = format!("{}\n{}", stdout, stderr);
        let lines: Vec<&str> = full_output.lines().collect();

        // Parse breakpoint hits
        for (i, line) in lines.iter().enumerate() {
            if line.contains("Breakpoint") && line.contains("hit") {
                if let Some(bp_info) = self.extract_breakpoint_info(line, &lines, i) {
                    analysis.breakpoints_hit.push(bp_info);
                }
            }
        }

        // Parse stack traces
        let mut in_stack_trace = false;
        let mut current_trace = Vec::new();
        for line in &lines {
            if line.contains("#0") || line.contains("Thread") {
                if !current_trace.is_empty() {
                    analysis.stack_traces.push(current_trace.join("\n"));
                    current_trace.clear();
                }
                in_stack_trace = true;
            }
            if in_stack_trace {
                current_trace.push(*line);
                if line.contains("at ") && line.contains(".c:") || line.contains(".cpp:") {
                    // End of frame
                }
            }
            if line.trim().is_empty() && in_stack_trace {
                in_stack_trace = false;
            }
        }
        if !current_trace.is_empty() {
            analysis.stack_traces.push(current_trace.join("\n"));
        }

        // Parse memory regions
        for line in &lines {
            if line.contains("0x") && line.contains("-") && line.contains("rw") {
                if let Some(memory_info) = self.extract_memory_info(line) {
                    analysis.memory_regions.push(memory_info);
                }
            }
        }

        // Parse register values
        for line in &lines {
            if line.contains("0x") && (line.contains("rax") || line.contains("rbx") || line.contains("rcx") || line.contains("rdx")) {
                analysis.register_values.push(line.to_string());
            }
        }

        // Parse errors
        for line in &lines {
            if line.to_lowercase().contains("error") || line.to_lowercase().contains("warning") {
                analysis.errors.push(line.to_string());
            }
        }

        // Generate summary
        analysis.summary = format!(
            "GDB Analysis: {} breakpoints hit, {} stack traces, {} memory regions, {} errors",
            analysis.breakpoints_hit.len(),
            analysis.stack_traces.len(),
            analysis.memory_regions.len(),
            analysis.errors.len()
        );

        serde_json::to_string_pretty(&analysis)
            .map_err(|e| EscalationError::OutputParsing(e.to_string()))
    }

    /// Extract breakpoint information from GDB output
    fn extract_breakpoint_info(&self, line: &str, lines: &[&str], index: usize) -> Option<GdbBreakpoint> {
        // Simple parsing - in practice, you'd want more robust regex-based parsing
        if let Some(bp_num) = line.split_whitespace().nth(1) {
            let context = if index + 1 < lines.len() {
                lines[index + 1].to_string()
            } else {
                "No context available".to_string()
            };
            
            Some(GdbBreakpoint {
                number: bp_num.to_string(),
                location: line.to_string(),
                context,
            })
        } else {
            None
        }
    }

    /// Extract memory region information from GDB output
    fn extract_memory_info(&self, line: &str) -> Option<GdbMemoryRegion> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            Some(GdbMemoryRegion {
                address_range: parts[0].to_string(),
                permissions: parts[1].to_string(),
                description: parts[2..].join(" "),
            })
        } else {
            None
        }
    }
}

#[derive(serde::Serialize)]
struct GdbAnalysis {
    breakpoints_hit: Vec<GdbBreakpoint>,
    stack_traces: Vec<String>,
    memory_regions: Vec<GdbMemoryRegion>,
    register_values: Vec<String>,
    errors: Vec<String>,
    summary: String,
}

#[derive(serde::Serialize)]
struct GdbBreakpoint {
    number: String,
    location: String,
    context: String,
}

#[derive(serde::Serialize)]
struct GdbMemoryRegion {
    address_range: String,
    permissions: String,
    description: String,
}

#[derive(serde::Serialize)]
struct AsanError {
    error_type: String,
    pattern: String,
    context: String,
    line_number: usize,
}

#[derive(serde::Serialize)]
struct AsanAnalysis {
    total_errors: usize,
    errors: Vec<AsanError>,
    summary: String,
}
