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

        // Save output
        tokio::fs::write(&output_file, &output).await?;

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
        let full_output = format!("STDOUT:\n{}\nSTDERR:\n{}", output_str, error_str);

        // Save output
        tokio::fs::write(&output_file, &full_output).await?;

        Ok(output_file.to_string_lossy().to_string())
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

        // Create GDB script
        let gdb_script = self.config.tools.gdb.commands.join("\n");
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
        let full_output = format!("STDOUT:\n{}\nSTDERR:\n{}", output_str, error_str);

        // Save output
        tokio::fs::write(&output_file, &full_output).await?;

        Ok(output_file.to_string_lossy().to_string())
    }
}
