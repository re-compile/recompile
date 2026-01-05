//! Native mode implementation for Linux hosts
//!
//! This module implements direct eBPF-based analysis without a VM.
//! It invokes the C agent (re-mini) to attach probes and monitor the target binary.

use anyhow::Result;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use libc;

/// Run analysis in native mode (Linux only)
///
/// # Arguments
/// * `binary_path` - Path to the target binary to analyze
/// * `output_dir` - Directory for crashpack output
/// * `escalate_mode` - Escalation mode: "auto", "always", or "never"
/// * `symbolizer_tool` - Symbolizer to use: "llvm-symbolizer" or "addr2line"
/// * `args` - Arguments to pass to the target binary
pub fn run_native(
    binary_path: &PathBuf,
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

    // TODO: Implement native mode execution
    // The implementation should:
    // 1. Locate BPF objects (heap_tracker.bpf.o, copy_checker.bpf.o, sentinel_extra.bpf.o)
    // 2. Locate the C agent binary (re-mini)
    // 3. Detect libc path for the target binary
    // 4. Launch re-mini with appropriate arguments:
    //    re-mini --heap <heap_tracker.o> --obj <copy_checker.o> --sentinel <sentinel.o> \
    //            --binary <target> --libc <libc.so> --out <findings_path>
    // 5. Wait for agent to attach probes
    // 6. Fork/exec the target binary (or have re-mini do it)
    // 7. Collect findings from the output file
    // 8. Optionally run escalation (ASan, etc.)
    // 9. Generate crashpack

    println!("Binary: {}", binary_path.display());
    println!("Output: {}", output_dir.display());
    println!();
    println!("⚠️  Native mode is not yet fully implemented.");
    println!();
    println!("To test the eBPF pipeline manually:");
    println!("  1. Build re-mini: cd runtime/agent && clang -O2 -g -o re-mini re-mini.c -lelf -lz -lbpf -ldl");
    println!("  2. Run: sudo ./re-mini --heap runtime/bpf/heap_tracker.bpf.o \\");
    println!("            --obj runtime/bpf/copy_checker.bpf.o --binary {} \\", binary_path.display());
    println!("            --libc /lib/x86_64-linux-gnu/libc.so.6 --out /dev/stdout &");
    println!("  3. Execute the binary in another terminal");

    Ok(())
}

/// Check for required Linux capabilities (CAP_BPF, CAP_PERFMON)
#[cfg(target_os = "linux")]
fn check_capabilities() -> Result<()> {
    // Check if running as root or with required capabilities
    let uid = unsafe { libc::getuid() };

    println!("Running as UID: {}", uid);
    
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

    // Try to read the BPF filesystem
    // This is a simple test to see if we have BPF capabilities
    match std::fs::read_dir(bpf_path) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

