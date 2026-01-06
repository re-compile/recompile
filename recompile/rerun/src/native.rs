//! Native mode implementation for Linux hosts
//!
//! This module implements direct eBPF-based analysis without a VM.
//! It invokes the C agent (re-mini) to attach probes and monitor the target binary.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use std::io::{BufRead, BufReader};
use std::fs::File;

#[cfg(target_os = "linux")]
use libc;

/// Configuration for native mode execution
struct NativeConfig {
    re_mini_path: PathBuf,
    heap_tracker_path: PathBuf,
    copy_checker_path: PathBuf,
    sentinel_path: Option<PathBuf>,
    libc_path: PathBuf,
    findings_path: PathBuf,
}

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
    args: &[String],
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

    // Resolve the binary path to absolute
    let binary_abs = std::fs::canonicalize(binary_path)
        .with_context(|| format!("Binary not found: {}", binary_path.display()))?;

    // Locate required components
    let config = locate_components(output_dir)?;

    println!("Configuration:");
    println!("  Binary:       {}", binary_abs.display());
    println!("  Agent:        {}", config.re_mini_path.display());
    println!("  Heap tracker: {}", config.heap_tracker_path.display());
    println!("  Copy checker: {}", config.copy_checker_path.display());
    println!("  Libc:         {}", config.libc_path.display());
    println!("  Findings:     {}", config.findings_path.display());
    println!();

    // Start the re-mini agent
    println!("Starting re-mini agent...");
    let mut agent = start_agent(&config, &binary_abs)?;

    // Give the agent time to attach probes
    std::thread::sleep(Duration::from_millis(500));

    // Check if agent is still running
    match agent.try_wait() {
        Ok(Some(status)) => {
            return Err(anyhow::anyhow!(
                "Agent exited prematurely with status: {}",
                status
            ));
        }
        Ok(None) => {
            println!("✓ Agent running (PID: {})", agent.id());
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to check agent status: {}", e));
        }
    }

    // Run the target binary
    println!("\nRunning target binary...");
    let target_status = Command::new(&binary_abs)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to execute: {}", binary_abs.display()))?;

    println!("\nTarget exited with status: {}", target_status);

    // Give agent time to process final events
    std::thread::sleep(Duration::from_millis(500));

    // Terminate the agent
    println!("Stopping agent...");
    let _ = agent.kill();
    let _ = agent.wait();

    // Read and display findings
    println!("\n=== Findings ===");
    if config.findings_path.exists() {
        display_findings(&config.findings_path)?;
    } else {
        println!("No findings file created.");
        println!("(Agent may not have detected any issues, or eBPF may not be available)");
    }

    // Copy findings to crashpack directory
    let crashpack_findings = output_dir.join("findings.json");
    if config.findings_path.exists() {
        std::fs::copy(&config.findings_path, &crashpack_findings)?;
        println!("\nFindings saved to: {}", crashpack_findings.display());
    }

    Ok(())
}

/// Locate all required components for native mode
fn locate_components(output_dir: &Path) -> Result<NativeConfig> {
    // Try to find components relative to the executable, then in known paths
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    // Look for re-mini agent
    let re_mini_path = find_file_in_paths(
        "re-mini",
        &[
            // Relative to current directory
            PathBuf::from("runtime/agent/re-mini"),
            PathBuf::from("recompile/runtime/agent/re-mini"),
            PathBuf::from("../runtime/agent/re-mini"),
            // Relative to executable
            exe_dir.as_ref().map(|d| d.join("../runtime/agent/re-mini")).unwrap_or_default(),
            // System paths
            PathBuf::from("/usr/local/bin/re-mini"),
            PathBuf::from("/usr/bin/re-mini"),
        ],
    ).ok_or_else(|| anyhow::anyhow!(
        "Could not find re-mini agent. Build it with:\n\
         cd runtime/agent && clang -O2 -g -o re-mini re-mini.c -lelf -lz -lbpf -ldl"
    ))?;

    // Look for BPF objects
    let bpf_search_paths = vec![
        PathBuf::from("runtime/bpf"),
        PathBuf::from("recompile/runtime/bpf"),
        PathBuf::from("../runtime/bpf"),
        exe_dir.as_ref().map(|d| d.join("../runtime/bpf")).unwrap_or_default(),
        PathBuf::from("/usr/local/share/recompile/bpf"),
    ];

    let heap_tracker_path = find_file_in_paths(
        "heap_tracker.bpf.o",
        &bpf_search_paths.iter().map(|p| p.join("heap_tracker.bpf.o")).collect::<Vec<_>>(),
    ).ok_or_else(|| anyhow::anyhow!(
        "Could not find heap_tracker.bpf.o. Build BPF objects with:\n\
         cd runtime/bpf && make"
    ))?;

    let copy_checker_path = find_file_in_paths(
        "copy_checker.bpf.o",
        &bpf_search_paths.iter().map(|p| p.join("copy_checker.bpf.o")).collect::<Vec<_>>(),
    ).ok_or_else(|| anyhow::anyhow!(
        "Could not find copy_checker.bpf.o. Build BPF objects with:\n\
         cd runtime/bpf && make"
    ))?;

    // Sentinel is optional
    let sentinel_path = find_file_in_paths(
        "sentinel_extra.bpf.o",
        &bpf_search_paths.iter().map(|p| p.join("sentinel_extra.bpf.o")).collect::<Vec<_>>(),
    );

    // Detect libc path
    let libc_path = detect_libc()?;

    // Findings output path
    let findings_path = output_dir.join("re-findings.jsonl");

    Ok(NativeConfig {
        re_mini_path,
        heap_tracker_path,
        copy_checker_path,
        sentinel_path,
        libc_path,
        findings_path,
    })
}

/// Find a file in a list of paths
fn find_file_in_paths(name: &str, paths: &[PathBuf]) -> Option<PathBuf> {
    for path in paths {
        if path.exists() && path.is_file() {
            return Some(path.clone());
        }
    }

    // Also check if it's in PATH (for executables)
    if let Ok(output) = Command::new("which").arg(name).output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                return Some(PathBuf::from(path_str));
            }
        }
    }

    None
}

/// Detect the path to libc
fn detect_libc() -> Result<PathBuf> {
    // Common libc paths for x86_64 Linux
    let common_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/lib/libc.so.6",
    ];

    for path in &common_paths {
        if Path::new(path).exists() {
            return Ok(PathBuf::from(path));
        }
    }

    // Try using ldd on a simple binary to find libc
    if let Ok(output) = Command::new("ldd").arg("/bin/ls").output() {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("libc.so") {
                    // Parse line like: "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)"
                    if let Some(path_start) = line.find("=> ") {
                        let remainder = &line[path_start + 3..];
                        if let Some(path_end) = remainder.find(' ') {
                            let path = &remainder[..path_end];
                            if Path::new(path).exists() {
                                return Ok(PathBuf::from(path));
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Could not detect libc path. Set RE_LIBC environment variable."
    ))
}

/// Start the re-mini agent process
fn start_agent(config: &NativeConfig, binary_path: &Path) -> Result<Child> {
    let mut cmd = Command::new(&config.re_mini_path);

    cmd.arg("--heap").arg(&config.heap_tracker_path)
       .arg("--obj").arg(&config.copy_checker_path)
       .arg("--binary").arg(binary_path)
       .arg("--libc").arg(&config.libc_path)
       .arg("--out").arg(&config.findings_path);

    // Add sentinel if available
    if let Some(ref sentinel) = config.sentinel_path {
        cmd.arg("--sentinel").arg(sentinel);
    }

    cmd.stdin(Stdio::null())
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let child = cmd.spawn()
        .with_context(|| format!("Failed to start agent: {}", config.re_mini_path.display()))?;

    Ok(child)
}

/// Display findings from the findings file
fn display_findings(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0;

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("RE:FINDING:") {
            // Parse and pretty-print the JSON
            let json_str = line.trim_start_matches("RE:FINDING:").trim();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
                count += 1;
                println!("\n--- Finding #{} ---", count);
                println!("  Kind:     {}", json.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown"));
                println!("  Severity: {}", json.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown"));
                if let Some(msg) = json.get("message").and_then(|v| v.as_str()) {
                    println!("  Message:  {}", msg);
                }
                if let Some(hints) = json.get("fixHints").and_then(|v| v.as_array()) {
                    for hint in hints {
                        if let Some(h) = hint.as_str() {
                            println!("  Hint:     {}", h);
                        }
                    }
                }
            } else {
                println!("{}", json_str);
            }
        } else if line.starts_with("RE:") {
            // Other agent output
            println!("{}", line);
        }
    }

    if count == 0 {
        println!("No findings detected.");
    } else {
        println!("\nTotal findings: {}", count);
    }

    Ok(())
}

/// Check for required Linux capabilities (CAP_BPF, CAP_PERFMON)
#[cfg(target_os = "linux")]
fn check_capabilities() -> Result<()> {
    // Check if running as root or with required capabilities
    let uid = unsafe { libc::getuid() };

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

    println!("✓ Running as UID {} - capability check passed", uid);
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
