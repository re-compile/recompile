//! Crashpack writer for generating all artifacts

use crate::{BinaryInfo, Environment, Finding, Manifest, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Writer for crashpack artifacts
pub struct CrashpackWriter {
    base_dir: PathBuf,
}

impl CrashpackWriter {
    /// Create a new crashpack writer
    pub fn new(base_dir: &Path) -> Result<Self> {
        let base_dir = base_dir.to_path_buf();

        // Create directory structure
        fs::create_dir_all(&base_dir)?;
        fs::create_dir_all(base_dir.join("env"))?;
        fs::create_dir_all(base_dir.join("bins"))?;
        fs::create_dir_all(base_dir.join("sanitizer"))?;
        fs::create_dir_all(base_dir.join("harnesses"))?;
        fs::create_dir_all(base_dir.join("gdb"))?;
        fs::create_dir_all(base_dir.join("inputs"))?;
        fs::create_dir_all(base_dir.join("symbols"))?;
        fs::create_dir_all(base_dir.join("escalations"))?;
        fs::create_dir_all(base_dir.join("escalations/asan"))?;
        fs::create_dir_all(base_dir.join("escalations/valgrind"))?;
        fs::create_dir_all(base_dir.join("escalations/gdb"))?;

        Ok(Self { base_dir })
    }

    /// Write findings.json
    pub fn write_findings(&self, findings: &[Finding]) -> Result<()> {
        let findings_path = self.base_dir.join("findings.json");
        let json = serde_json::to_string_pretty(findings)?;
        fs::write(findings_path, json)?;
        Ok(())
    }

    /// Write environment information
    pub fn write_environment(&self, env: &Environment) -> Result<()> {
        // Write uname.txt
        let uname_path = self.base_dir.join("env/uname.txt");
        fs::write(uname_path, &env.system.uname)?;

        // Write kernel.txt
        let kernel_path = self.base_dir.join("env/kernel.txt");
        fs::write(kernel_path, &env.system.kernel)?;

        // Write tool-versions.txt
        let tools_path = self.base_dir.join("env/tool-versions.txt");
        let tools_content = format!(
            "recc: {}\nclang: {}\nllvm-symbolizer: {}\nasan: {}\nvalgrind: {}\ngdb: {}\n",
            env.tools.recc_version,
            env.tools.clang_version.as_deref().unwrap_or("unknown"),
            env.tools
                .llvm_symbolizer_version
                .as_deref()
                .unwrap_or("unknown"),
            env.tools.asan_version.as_deref().unwrap_or("unknown"),
            env.tools.valgrind_version.as_deref().unwrap_or("unknown"),
            env.tools.gdb_version.as_deref().unwrap_or("unknown")
        );
        fs::write(tools_path, tools_content)?;

        // Write runtime environment
        let runtime_path = self.base_dir.join("env/runtime.json");
        let runtime_json = serde_json::to_string_pretty(&env.runtime)?;
        fs::write(runtime_path, runtime_json)?;

        Ok(())
    }

    /// Write binary information
    pub fn write_binaries(&self, binaries: &[BinaryInfo]) -> Result<()> {
        for binary in binaries {
            let binary_path = self.base_dir.join("bins").join(
                Path::new(&binary.path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            );

            // Copy binary if it exists
            if Path::new(&binary.path).exists() {
                fs::copy(&binary.path, &binary_path)?;
            }

            // Write binary metadata
            let metadata_path = binary_path.with_extension("json");
            let metadata_json = serde_json::to_string_pretty(binary)?;
            fs::write(metadata_path, metadata_json)?;
        }
        Ok(())
    }

    /// Write manifest.json
    pub fn write_manifest(&self, manifest: &Manifest) -> Result<()> {
        let manifest_path = self.base_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(manifest)?;
        fs::write(manifest_path, manifest_json)?;
        Ok(())
    }

    /// Write console.log (copy from build/.re/console.log if it exists)
    pub fn write_console_log(&self) -> Result<()> {
        let console_log_path = self.base_dir.join("console.log");

        // Try to copy from build/.re/console.log
        let source_console = Path::new("build/.re/console.log");
        if source_console.exists() {
            fs::copy(source_console, &console_log_path)?;
        } else {
            // Create empty console log
            fs::write(&console_log_path, "# Console log not available\n")?;
        }

        Ok(())
    }

    /// Write repro.sh script
    pub fn write_repro_script(&self, findings: &[Finding], binaries: &[BinaryInfo]) -> Result<()> {
        let repro_path = self.base_dir.join("repro.sh");
        let repro_binary = primary_repro_binary(binaries);

        let mut script = String::new();
        script.push_str("#!/bin/bash\n");
        script.push_str("set -euo pipefail\n\n");
        script.push_str("# RECC Crashpack Repro Script\n");
        script.push_str("# Generated automatically\n\n");
        if let Some(binary) = &repro_binary {
            script.push_str(&format!("RE_TARGET={}\n", shell_quote(binary)));
            script.push_str("if [[ ! -x \"$RE_TARGET\" ]]; then\n");
            script.push_str(
                "  echo \"captured binary is missing or not executable: $RE_TARGET\" >&2\n",
            );
            script.push_str("  exit 2\n");
            script.push_str("fi\n\n");
        } else {
            script.push_str("echo \"no binary was captured in this crashpack\" >&2\n");
            script.push_str("exit 2\n");
        }

        // Add environment setup
        script.push_str("export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1\n");
        script.push_str("export UBSAN_OPTIONS=abort_on_error=1\n");
        script.push_str("export MSAN_OPTIONS=abort_on_error=1\n\n");

        // Add repro commands for each finding
        for (i, finding) in findings.iter().enumerate() {
            script.push_str(&format!("# Finding {}: {}\n", i + 1, finding.class));
            script.push_str(&format!(
                "# Confidence: {}, Severity: {}\n",
                finding.confidence, finding.severity
            ));

            if let Some(escalation) = &finding.escalation {
                match escalation.tool.as_str() {
                    "asan" => {
                        script.push_str(&format!("# ASan escalation for {}\n", finding.class));
                        script.push_str("echo \"Running with AddressSanitizer...\"\n");
                        script.push_str(
                            "RE_SANITIZE=address \"$RE_TARGET\" 2>&1 | tee sanitizer/asan.log\n",
                        );
                    }
                    "valgrind" => {
                        script.push_str(&format!("# Valgrind escalation for {}\n", finding.class));
                        script.push_str("echo \"Running with Valgrind...\"\n");
                        script.push_str("valgrind --error-exitcode=99 --leak-check=full --track-origins=yes \"$RE_TARGET\" 2>&1 | tee sanitizer/valgrind.log\n");
                    }
                    "gdb" => {
                        script.push_str(&format!("# GDB escalation for {}\n", finding.class));
                        script.push_str("echo \"Running with GDB...\"\n");
                        script.push_str("gdb -batch -ex run -ex bt -ex 'info reg' \"$RE_TARGET\" 2>&1 | tee gdb/backtrace.txt\n");
                    }
                    _ => {
                        script
                            .push_str(&format!("# Unknown escalation tool: {}\n", escalation.tool));
                    }
                }
            } else {
                script.push_str("# No escalation planned\n");
            }
            script.push_str("\n");
        }

        // Make script executable
        fs::write(&repro_path, script)?;
        fs::set_permissions(&repro_path, fs::Permissions::from_mode(0o755))?;

        Ok(())
    }

    /// Write build.json with build information
    pub fn write_build_info(&self, build_info: &serde_json::Value) -> Result<()> {
        let build_path = self.base_dir.join("build.json");
        let build_json = serde_json::to_string_pretty(build_info)?;
        fs::write(build_path, build_json)?;
        Ok(())
    }

    /// Write env.txt with environment variables
    pub fn write_env_txt(
        &self,
        env_vars: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let env_path = self.base_dir.join("env.txt");
        let mut env_content = String::new();

        for (key, value) in env_vars {
            env_content.push_str(&format!("{}={}\n", key, value));
        }

        fs::write(env_path, env_content)?;
        Ok(())
    }
}

fn primary_repro_binary(binaries: &[BinaryInfo]) -> Option<String> {
    binaries.iter().find_map(|binary| {
        Path::new(&binary.path)
            .file_name()
            .map(|name| format!("./bins/{}", name.to_string_lossy()))
    })
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repro_binary_uses_copied_binary_basename() {
        let binaries = vec![BinaryInfo {
            path: "/tmp/project/build/server".to_string(),
            build_id: None,
            debug_info: true,
            size: 42,
            sha256: None,
        }];

        assert_eq!(
            primary_repro_binary(&binaries).as_deref(),
            Some("./bins/server")
        );
    }

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(
            shell_quote("./bins/my app's test"),
            "'./bins/my app'\"'\"'s test'"
        );
    }
}
