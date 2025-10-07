//! Crashpack manifest generation

use crate::Manifest;
use std::process::Command;

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: "1.0".to_string(),
            recc_version: env!("CARGO_PKG_VERSION").to_string(),
            kernel_version: get_kernel_version().unwrap_or_else(|| "unknown".to_string()),
            commit_hash: get_git_commit_hash(),
            toolchain: get_toolchain_info().unwrap_or_else(|| "unknown".to_string()),
            created_by: "re-crashpack".to_string(),
            total_findings: 0,
            high_confidence_findings: 0,
            escalation_tools_used: Vec::new(),
        }
    }
}

/// Get kernel version
fn get_kernel_version() -> Option<String> {
    Command::new("uname")
        .args(&["-r"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                Some(version.trim().to_string())
            } else {
                None
            }
        })
}

/// Get git commit hash
fn get_git_commit_hash() -> Option<String> {
    Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let hash = String::from_utf8_lossy(&output.stdout);
                Some(hash.trim().to_string())
            } else {
                None
            }
        })
}

/// Get toolchain information
fn get_toolchain_info() -> Option<String> {
    // Try to get clang version
    if let Some(clang_version) = get_clang_version() {
        return Some(format!("clang {}", clang_version));
    }
    
    // Try to get gcc version
    if let Some(gcc_version) = get_gcc_version() {
        return Some(format!("gcc {}", gcc_version));
    }
    
    None
}

/// Get clang version
fn get_clang_version() -> Option<String> {
    Command::new("clang")
        .args(&["--version"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                // Extract version from first line
                version.lines().next().map(|line| {
                    // Extract version number (e.g., "clang version 14.0.0")
                    if let Some(version_part) = line.split_whitespace().nth(2) {
                        version_part.to_string()
                    } else {
                        line.trim().to_string()
                    }
                })
            } else {
                None
            }
        })
}

/// Get gcc version
fn get_gcc_version() -> Option<String> {
    Command::new("gcc")
        .args(&["--version"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                // Extract version from first line
                version.lines().next().map(|line| {
                    // Extract version number (e.g., "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0")
                    if let Some(version_part) = line.split_whitespace().last() {
                        version_part.to_string()
                    } else {
                        line.trim().to_string()
                    }
                })
            } else {
                None
            }
        })
}
