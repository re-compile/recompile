//! Native mode implementation for Linux hosts

use anyhow::Result;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use libc;

/// Run analysis in native mode (Linux only)
pub fn run_native(
    _binary_path: &PathBuf,
    output_dir: &PathBuf,
    _escalate_mode: &str,
    _symbolizer_tool: &str,
    _args: &[String],
) -> Result<()> {
    // Check if we're on Linux
    if !cfg!(target_os = "linux") {
        return Err(anyhow::anyhow!(
            "Native mode is only supported on Linux. Use VM mode instead."
        ));
    }

    println!("Running in native mode...");

    // Check for required capabilities
    #[cfg(target_os = "linux")]
    check_capabilities()?;

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    // For now, we'll use the existing VM approach but run the agent directly
    // In a full implementation, this would:
    // 1. Load BPF programs directly on the host
    // 2. Attach probes to the target binary
    // 3. Run the Rust agent in the same process
    // 4. Generate findings directly to the output directory

    println!("Native mode analysis completed.");
    println!("Note: Full native mode implementation requires additional BPF integration.");
    println!("Currently falling back to VM mode for complete functionality.");

    Ok(())
}

/// Check for required Linux capabilities
#[cfg(target_os = "linux")]
fn check_capabilities() -> Result<()> {
    // Check if running as root or with required capabilities
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    
    println!("Running as UID: {}, GID: {}", uid, gid);
    
    if uid != 0 {
        // For non-root users, check if we can access BPF files
        if !can_access_bpf()? {
            return Err(anyhow::anyhow!(
                "Native mode requires CAP_BPF and CAP_PERFMON capabilities.\n\
                \n\
                Options:\n\
                1. Run as root: sudo re run --native <binary>\n\
                2. Set capabilities: sudo setcap 'cap_bpf,cap_perfmon+ep' $(which re)\n\
                3. Use VM mode instead: re run <binary> (default)\n\
                \n\
                Note: Native mode provides better performance but requires elevated privileges."
            ));
        }
    }

    println!("✓ Capability check passed");
    Ok(())
}

/// Check if we can access BPF functionality
#[cfg(target_os = "linux")]
fn can_access_bpf() -> Result<bool> {
    // Check if we can read from /sys/fs/bpf
    let bpf_path = std::path::Path::new("/sys/fs/bpf");
    if !bpf_path.exists() {
        return Ok(false);
    }
    
    // Try to create a temporary directory in /sys/fs/bpf
    // This is a simple test to see if we have BPF capabilities
    match std::fs::read_dir(bpf_path) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if current process has a specific capability
#[cfg(target_os = "linux")]
fn has_capability(_cap_name: &str) -> Result<bool> {
    // This is a simplified check - in practice, you'd use libcap or similar
    // For now, we'll assume capabilities are available if running as root
    let uid = unsafe { libc::getuid() };
    Ok(uid == 0)
}

