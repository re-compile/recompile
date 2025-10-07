//! Environment and system information capture

use crate::{Environment, SystemInfo, RuntimeInfo, ToolVersions, BinaryInfo, CrashpackError, Result};
use std::collections::HashMap;
use std::process::Command;
use std::path::Path;

impl Environment {
    /// Capture current environment information
    pub fn capture() -> Result<Self> {
        Ok(Self {
            system: SystemInfo::capture()?,
            runtime: RuntimeInfo::capture()?,
            tools: ToolVersions::capture()?,
        })
    }
}

impl SystemInfo {
    /// Capture system information
    pub fn capture() -> Result<Self> {
        let uname_output = Command::new("uname")
            .args(&["-a"])
            .output()
            .map_err(|e| CrashpackError::Environment(format!("Failed to run uname: {}", e)))?;
        
        let uname = String::from_utf8_lossy(&uname_output.stdout).trim().to_string();
        
        let kernel_output = Command::new("uname")
            .args(&["-r"])
            .output()
            .map_err(|e| CrashpackError::Environment(format!("Failed to get kernel version: {}", e)))?;
        
        let kernel = String::from_utf8_lossy(&kernel_output.stdout).trim().to_string();
        
        let arch_output = Command::new("uname")
            .args(&["-m"])
            .output()
            .map_err(|e| CrashpackError::Environment(format!("Failed to get architecture: {}", e)))?;
        
        let architecture = String::from_utf8_lossy(&arch_output.stdout).trim().to_string();
        
        let hostname_output = Command::new("hostname")
            .output()
            .map_err(|e| CrashpackError::Environment(format!("Failed to get hostname: {}", e)))?;
        
        let hostname = String::from_utf8_lossy(&hostname_output.stdout).trim().to_string();

        Ok(Self {
            uname,
            kernel,
            architecture,
            hostname,
        })
    }
}

impl RuntimeInfo {
    /// Capture runtime information
    pub fn capture() -> Result<Self> {
        let argv = std::env::args().collect();
        let env: HashMap<String, String> = std::env::vars().collect();
        let cwd = std::env::current_dir()
            .map_err(|e| CrashpackError::Environment(format!("Failed to get current directory: {}", e)))?
            .to_string_lossy()
            .to_string();
        let pid = std::process::id();
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            argv,
            env,
            cwd,
            pid,
            start_time,
        })
    }
}

impl ToolVersions {
    /// Capture tool versions
    pub fn capture() -> Result<Self> {
        Ok(Self {
            recc_version: env!("CARGO_PKG_VERSION").to_string(),
            clang_version: get_tool_version("clang", &["--version"]),
            llvm_symbolizer_version: get_tool_version("llvm-symbolizer", &["--version"]),
            asan_version: get_tool_version("clang", &["--version"]), // ASan is part of clang
            valgrind_version: get_tool_version("valgrind", &["--version"]),
            gdb_version: get_tool_version("gdb", &["--version"]),
        })
    }
}

impl BinaryInfo {
    /// Analyze a binary file
    pub fn analyze<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        if !path.exists() {
            return Ok(Self {
                path: path_str,
                build_id: None,
                debug_info: false,
                size: 0,
                sha256: None,
            });
        }

        let metadata = std::fs::metadata(path)
            .map_err(|e| CrashpackError::Binary(format!("Failed to get metadata for {}: {}", path_str, e)))?;
        
        let size = metadata.len();
        
        // Try to get build ID using readelf
        let build_id = get_build_id(path);
        
        // Check for debug info
        let debug_info = has_debug_info(path);
        
        // Calculate SHA256
        let sha256 = calculate_sha256(path);

        Ok(Self {
            path: path_str,
            build_id,
            debug_info,
            size,
            sha256,
        })
    }
}

/// Get version of a tool
fn get_tool_version(tool: &str, args: &[&str]) -> Option<String> {
    Command::new(tool)
        .args(args)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                // Extract version from first line
                version.lines().next().map(|line| line.trim().to_string())
            } else {
                None
            }
        })
}

/// Get build ID from binary
fn get_build_id(path: &Path) -> Option<String> {
    Command::new("readelf")
        .args(&["-n", path.to_str()?])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("Build ID:") {
                        return line.split_whitespace().last().map(|s| s.to_string());
                    }
                }
            }
            None
        })
}

/// Check if binary has debug info
fn has_debug_info(path: &Path) -> bool {
    Command::new("readelf")
        .args(&["-S", path.to_str().unwrap_or("")])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                Some(output_str.contains(".debug_info") || output_str.contains(".debug_line"))
            } else {
                None
            }
        })
        .unwrap_or(false)
}

/// Calculate SHA256 of a file
fn calculate_sha256(path: &Path) -> Option<String> {
    use std::fs::File;
    use std::io::Read;
    
    let mut file = File::open(path).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();
    Some(format!("{:x}", result))
}

// Add sha2 dependency to Cargo.toml
// sha2 = "0.10"
