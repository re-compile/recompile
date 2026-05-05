//! Native mode implementation for Linux hosts
//!
//! This module implements direct eBPF-based analysis without a VM.
//! It invokes the C agent (re-mini) to attach probes and monitor the target binary.

use crate::summary::{print_findings_summary, read_findings};
use anyhow::{Context, Result};
use re_crashpack::{BinaryInfo, Manifest};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

const GENERATED_OUTPUT_FILES: &[&str] = &[
    "analysis.json",
    "console.log",
    "findings.json",
    "manifest.json",
    "re-findings.jsonl",
];

const GENERATED_OUTPUT_DIRS: &[&str] = &[".re", "bins", "escalations"];

#[cfg(target_os = "linux")]
use libc;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;

/// Configuration for native mode execution
struct NativeConfig {
    re_mini_path: PathBuf,
    heap_tracker_path: PathBuf,
    copy_checker_path: PathBuf,
    sentinel_path: Option<PathBuf>,
    libc_path: PathBuf,
    debug_findings_path: PathBuf,
    crashpack_dir: PathBuf,
    console_log_path: PathBuf,
}

#[derive(Serialize)]
struct NativeRunMetadata {
    binary_path: String,
    source_path: Option<String>,
    args: Vec<String>,
}

struct TargetProcess {
    pid: u32,
}

impl TargetProcess {
    fn id(&self) -> u32 {
        self.pid
    }

    #[cfg(target_os = "linux")]
    fn wait(self) -> Result<ExitStatus> {
        wait_for_exit(self.pid)
    }

    #[cfg(not(target_os = "linux"))]
    fn wait(self) -> Result<ExitStatus> {
        let _ = self;
        Err(anyhow::anyhow!("Native mode is only supported on Linux"))
    }
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

    #[cfg(target_os = "linux")]
    check_pid_namespace()?;

    prepare_output_dir(output_dir)?;

    // Resolve the binary path to absolute
    let binary_abs = std::fs::canonicalize(binary_path)
        .with_context(|| format!("Binary not found: {}", binary_path.display()))?;

    // Locate required components
    let config = locate_components(output_dir)?;
    write_analysis_metadata(&config.crashpack_dir, &binary_abs, args)?;

    println!("Configuration:");
    println!("  Binary:       {}", binary_abs.display());
    println!("  Agent:        {}", config.re_mini_path.display());
    println!("  Heap tracker: {}", config.heap_tracker_path.display());
    println!("  Copy checker: {}", config.copy_checker_path.display());
    println!("  Libc:         {}", config.libc_path.display());
    println!("  Debug log:    {}", config.debug_findings_path.display());
    println!("  Crashpack:    {}", config.crashpack_dir.display());
    println!();

    // Start the target in a stopped state so probes are attached before main executes.
    println!("Starting target in paused state...");
    let target = start_target_paused(&binary_abs, args)?;
    println!("✓ Target paused (PID: {})", target.id());

    // Start the re-mini agent
    println!("Starting re-mini agent...");
    let mut agent = start_agent(&config, &binary_abs, target.id())?;

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

    // Resume the target now that probes are attached.
    println!("\nRunning target binary...");
    resume_target(target.id())?;
    let target_status = target
        .wait()
        .with_context(|| format!("Failed while waiting for {}", binary_abs.display()))?;

    println!("\nTarget exited with status: {}", target_status);
    append_console_log(
        &config.console_log_path,
        &format!("target_exit_status={}\n", target_status),
    )?;

    // Give agent time to process final events
    std::thread::sleep(Duration::from_millis(500));

    // Terminate the agent
    println!("Stopping agent...");
    let _ = agent.kill();
    let _ = agent.wait();

    let findings_path = finalize_findings(&config.crashpack_dir, &binary_abs)?;

    // Read and display findings
    println!("\n=== Findings ===");
    display_findings(&findings_path)?;

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
            exe_dir
                .as_ref()
                .map(|d| d.join("../runtime/agent/re-mini"))
                .unwrap_or_default(),
            // System paths
            PathBuf::from("/usr/local/bin/re-mini"),
            PathBuf::from("/usr/bin/re-mini"),
        ],
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "Could not find re-mini agent. Build it with:\n\
         cd runtime/agent && clang -O2 -g -o re-mini re-mini.c -lelf -lz -lbpf -ldl"
        )
    })?;

    // Look for BPF objects
    let bpf_search_paths = vec![
        PathBuf::from("runtime/bpf"),
        PathBuf::from("recompile/runtime/bpf"),
        PathBuf::from("../runtime/bpf"),
        exe_dir
            .as_ref()
            .map(|d| d.join("../runtime/bpf"))
            .unwrap_or_default(),
        PathBuf::from("/usr/local/share/recompile/bpf"),
    ];

    let heap_tracker_path = find_file_in_paths(
        "heap_tracker.bpf.o",
        &bpf_search_paths
            .iter()
            .map(|p| p.join("heap_tracker.bpf.o"))
            .collect::<Vec<_>>(),
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "Could not find heap_tracker.bpf.o. Build BPF objects with:\n\
         cd runtime/bpf && make"
        )
    })?;

    let copy_checker_path = find_file_in_paths(
        "copy_checker.bpf.o",
        &bpf_search_paths
            .iter()
            .map(|p| p.join("copy_checker.bpf.o"))
            .collect::<Vec<_>>(),
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "Could not find copy_checker.bpf.o. Build BPF objects with:\n\
         cd runtime/bpf && make"
        )
    })?;

    // Sentinel tracepoints are optional and should only be enabled when tracefs is available.
    let sentinel_path = find_file_in_paths(
        "sentinel_extra.bpf.o",
        &bpf_search_paths
            .iter()
            .map(|p| p.join("sentinel_extra.bpf.o"))
            .collect::<Vec<_>>(),
    )
    .filter(|_| tracefs_has_syscall_tracepoints());

    // Detect libc path
    let libc_path = detect_libc()?;

    // Findings output path
    let debug_findings_path = output_dir.join("re-findings.jsonl");
    let console_log_path = output_dir.join("console.log");

    Ok(NativeConfig {
        re_mini_path,
        heap_tracker_path,
        copy_checker_path,
        sentinel_path,
        libc_path,
        debug_findings_path,
        crashpack_dir: output_dir.to_path_buf(),
        console_log_path,
    })
}

fn prepare_output_dir(output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    for file_name in GENERATED_OUTPUT_FILES {
        let path = output_dir.join(file_name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to remove stale {}", path.display()));
            }
        }
    }

    for dir_name in GENERATED_OUTPUT_DIRS {
        let path = output_dir.join(dir_name);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to remove stale {}", path.display()));
            }
        }
    }

    Ok(())
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

fn tracefs_has_syscall_tracepoints() -> bool {
    [
        "/sys/kernel/tracing/events/syscalls/sys_enter_read/id",
        "/sys/kernel/debug/tracing/events/syscalls/sys_enter_read/id",
    ]
    .iter()
    .any(|path| Path::new(path).exists())
}

/// Detect the path to libc
fn detect_libc() -> Result<PathBuf> {
    // Common libc paths for Linux
    let common_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/aarch64-linux-gnu/libc.so.6",
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
fn start_agent(config: &NativeConfig, binary_path: &Path, target_pid: u32) -> Result<Child> {
    let mut cmd = Command::new(&config.re_mini_path);
    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.console_log_path)
        .with_context(|| format!("Failed to open {}", config.console_log_path.display()))?;
    let stderr_log = stdout_log
        .try_clone()
        .with_context(|| format!("Failed to clone {}", config.console_log_path.display()))?;

    cmd.arg("--heap")
        .arg(&config.heap_tracker_path)
        .arg("--obj")
        .arg(&config.copy_checker_path)
        .arg("--binary")
        .arg(binary_path)
        .arg("--pid")
        .arg(target_pid.to_string())
        .arg("--libc")
        .arg(&config.libc_path)
        .arg("--out")
        .arg(&config.debug_findings_path)
        .arg("--crashpack")
        .arg(&config.crashpack_dir);

    // Add sentinel if available
    if let Some(ref sentinel) = config.sentinel_path {
        cmd.arg("--sentinel").arg(sentinel);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log));

    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to start agent: {}", config.re_mini_path.display()))?;

    Ok(child)
}

#[cfg(target_os = "linux")]
fn start_target_paused(binary_path: &Path, args: &[String]) -> Result<TargetProcess> {
    let binary_cstr = CString::new(binary_path.as_os_str().as_bytes()).with_context(|| {
        format!(
            "Binary path contains interior NUL: {}",
            binary_path.display()
        )
    })?;
    let arg_cstrs = args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).context("Argument contains interior NUL"))
        .collect::<Result<Vec<_>>>()?;

    let mut argv = Vec::with_capacity(arg_cstrs.len() + 2);
    argv.push(binary_cstr.as_ptr());
    argv.extend(arg_cstrs.iter().map(|arg| arg.as_ptr()));
    argv.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow::anyhow!(
            "Failed to fork target {}: {}",
            binary_path.display(),
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        unsafe {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) != 0
            {
                libc::_exit(126);
            }
            libc::execv(binary_cstr.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    wait_for_exec_stop(pid)?;
    Ok(TargetProcess { pid: pid as u32 })
}

#[cfg(target_os = "linux")]
fn wait_for_exec_stop(pid: libc::pid_t) -> Result<()> {
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            if libc::WIFSTOPPED(status) {
                return Ok(());
            }

            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(anyhow::anyhow!(
                    "Target {} exited before post-exec stop: {}",
                    pid,
                    ExitStatus::from_raw(status)
                ));
            }
        }

        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(anyhow::anyhow!(
                "Failed to wait for target {} to stop: {}",
                pid,
                err
            ));
        }
    }
}

#[cfg(target_os = "linux")]
fn resume_target(pid: u32) -> Result<()> {
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid as i32,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "Failed to resume target {}: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn start_target_paused(_binary_path: &Path, _args: &[String]) -> Result<TargetProcess> {
    Err(anyhow::anyhow!("Native mode is only supported on Linux"))
}

#[cfg(not(target_os = "linux"))]
fn resume_target(_pid: u32) -> Result<()> {
    Err(anyhow::anyhow!("Native mode is only supported on Linux"))
}

#[cfg(target_os = "linux")]
fn wait_for_exit(pid: u32) -> Result<ExitStatus> {
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        if rc == pid as i32 {
            return Ok(ExitStatus::from_raw(status));
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(anyhow::anyhow!(
                "Failed to wait for target {}: {}",
                pid,
                err
            ));
        }
    }
}

fn finalize_findings(crashpack_dir: &Path, binary_path: &Path) -> Result<PathBuf> {
    let findings_path = crashpack_dir.join("findings.json");
    let copied_binary_path = write_binary_artifacts(crashpack_dir, binary_path)?;
    let findings = if findings_path.exists() {
        let content = std::fs::read_to_string(&findings_path)
            .with_context(|| format!("Failed to read {}", findings_path.display()))?;
        let mut findings = parse_findings_content(&content)
            .with_context(|| format!("Failed to normalize {}", findings_path.display()))?;
        attach_finding_provenance(&mut findings, binary_path, &copied_binary_path);
        findings
    } else {
        Vec::new()
    };

    std::fs::write(&findings_path, serde_json::to_vec_pretty(&findings)?)
        .with_context(|| format!("Failed to rewrite {}", findings_path.display()))?;
    write_manifest(crashpack_dir, &findings)?;

    println!("\nFindings saved to: {}", findings_path.display());
    Ok(findings_path)
}

fn write_analysis_metadata(
    crashpack_dir: &Path,
    binary_path: &Path,
    args: &[String],
) -> Result<()> {
    let metadata = NativeRunMetadata {
        binary_path: binary_path.display().to_string(),
        source_path: None,
        args: args.to_vec(),
    };
    let metadata_path = crashpack_dir.join("analysis.json");
    std::fs::write(metadata_path, serde_json::to_vec_pretty(&metadata)?)?;
    Ok(())
}

fn append_console_log(console_log_path: &Path, line: &str) -> Result<()> {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(console_log_path)
        .with_context(|| format!("Failed to open {}", console_log_path.display()))?;
    log.write_all(line.as_bytes())
        .with_context(|| format!("Failed to write {}", console_log_path.display()))?;
    Ok(())
}

fn parse_findings_content(content: &str) -> Result<Vec<Value>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(findings) = serde_json::from_str::<Vec<Value>>(trimmed) {
        return Ok(findings);
    }

    if let Ok(finding) = serde_json::from_str::<Value>(trimmed) {
        if finding.is_object() {
            return Ok(vec![finding]);
        }
    }

    let mut findings = Vec::new();
    for line in trimmed.lines() {
        let candidate = line.trim();
        if candidate.is_empty() {
            continue;
        }

        let json = candidate
            .strip_prefix("RE:FINDING:")
            .map(str::trim)
            .unwrap_or(candidate);
        findings.push(
            serde_json::from_str::<Value>(json)
                .with_context(|| format!("Failed to parse finding line: {}", json))?,
        );
    }

    Ok(findings)
}

fn write_manifest(crashpack_dir: &Path, findings: &[Value]) -> Result<()> {
    let mut manifest = Manifest::default();
    manifest.created_by = "rerun-native".to_string();
    manifest.total_findings = findings.len();
    manifest.high_confidence_findings = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.get("confidence").and_then(|value| value.as_str()),
                Some("high" | "certain")
            )
        })
        .count();
    manifest.escalation_tools_used = findings
        .iter()
        .filter_map(|finding| {
            finding
                .get("escalation")
                .and_then(|value| value.get("tool"))
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let manifest_path = crashpack_dir.join("manifest.json");
    std::fs::write(manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

fn write_binary_artifacts(crashpack_dir: &Path, binary_path: &Path) -> Result<PathBuf> {
    let binary_info = BinaryInfo::analyze(binary_path).map_err(|error| {
        anyhow::anyhow!("Failed to analyze {}: {}", binary_path.display(), error)
    })?;
    let bins_dir = crashpack_dir.join("bins");
    std::fs::create_dir_all(&bins_dir)?;

    let file_name = binary_path.file_name().ok_or_else(|| {
        anyhow::anyhow!("Binary path has no file name: {}", binary_path.display())
    })?;
    let copied_binary = bins_dir.join(file_name);
    std::fs::copy(binary_path, &copied_binary)
        .with_context(|| format!("Failed to copy binary to {}", copied_binary.display()))?;

    let metadata_path = copied_binary.with_extension("json");
    std::fs::write(metadata_path, serde_json::to_vec_pretty(&binary_info)?)?;
    Ok(copied_binary)
}

fn attach_finding_provenance(
    findings: &mut [Value],
    original_binary_path: &Path,
    copied_binary_path: &Path,
) {
    for finding in findings {
        let Some(object) = finding.as_object_mut() else {
            continue;
        };
        let source_path = extract_source_path(object);

        let provenance_value = object
            .entry("provenance".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !provenance_value.is_object() {
            *provenance_value = Value::Object(Map::new());
        }
        let provenance = provenance_value
            .as_object_mut()
            .expect("provenance object inserted above");

        provenance
            .entry("binary_path".to_string())
            .or_insert_with(|| Value::String(copied_binary_path.display().to_string()));
        provenance
            .entry("original_binary_path".to_string())
            .or_insert_with(|| Value::String(original_binary_path.display().to_string()));

        if !provenance.contains_key("source_path") {
            if let Some(source_path) = source_path {
                provenance.insert("source_path".to_string(), Value::String(source_path));
            }
        }
    }
}

fn extract_source_path(finding: &Map<String, Value>) -> Option<String> {
    if let Some(source_path) = finding
        .get("evidence")
        .and_then(|value| value.get("alloc_site"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "unknown")
    {
        return Some(source_path.to_string());
    }

    finding
        .get("primaryLocation")
        .and_then(|value| value.get("uri"))
        .and_then(|value| value.as_str())
        .and_then(|uri| uri.strip_prefix("file://"))
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "unknown")
        .map(str::to_string)
}

/// Display findings from the findings file
fn display_findings(path: &Path) -> Result<()> {
    let findings = read_findings(path)?;
    print_findings_summary(&findings);
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

#[cfg(target_os = "linux")]
fn running_in_container() -> Result<bool> {
    if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
        return Ok(true);
    }

    let cgroup = std::fs::read_to_string("/proc/1/cgroup")
        .or_else(|_| std::fs::read_to_string("/proc/self/cgroup"))
        .unwrap_or_default();

    Ok(["docker", "containerd", "kubepods", "libpod", "podman"]
        .iter()
        .any(|marker| cgroup.contains(marker)))
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

#[cfg(target_os = "linux")]
fn check_pid_namespace() -> Result<()> {
    if std::env::var_os("RECOMPILE_ALLOW_PID_NAMESPACE").is_some() {
        return Ok(());
    }

    if !running_in_container()? {
        return Ok(());
    }

    let init_comm = std::fs::read_to_string("/proc/1/comm")
        .ok()
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let init_cmdline = std::fs::read("/proc/1/cmdline")
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
        .unwrap_or_default();
    let proc_count = std::fs::read_dir("/proc")
        .ok()
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .chars()
                        .all(|c| c.is_ascii_digit())
                })
                .count()
        })
        .unwrap_or(0);

    let container_init = matches!(
        init_comm.as_str(),
        "bash" | "sh" | "timeout" | "recompile-bootstrap"
    ) || init_cmdline.contains("recompile-bootstrap")
        || init_cmdline.contains(" bash")
        || init_cmdline.starts_with("bash ")
        || init_cmdline.contains(" sh")
        || init_cmdline.starts_with("sh ");

    if container_init || proc_count < 64 {
        return Err(anyhow::anyhow!(
            "Native mode is running in Docker without a shared host PID namespace.\n\
             Docker-native eBPF tracing is only supported with a shared host PID namespace.\n\
             \n\
             Start the container with:\n\
             docker run --rm -it --privileged --pid=host -v \"$PWD\":/workspace/recompile recompile-bootstrap:host bash\n\
             \n\
             Set RECOMPILE_ALLOW_PID_NAMESPACE=1 only if you are deliberately debugging this unsupported setup."
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_output_dir_removes_generated_artifacts_only() {
        let base =
            std::env::temp_dir().join(format!("rerun-output-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".re")).unwrap();
        std::fs::create_dir_all(base.join("bins")).unwrap();
        std::fs::write(base.join("findings.json"), "[{}]").unwrap();
        std::fs::write(base.join("re-findings.jsonl"), "stale\n").unwrap();
        std::fs::write(base.join(".re").join("last_finding.json"), "{}").unwrap();
        std::fs::write(base.join("notes.txt"), "keep").unwrap();

        prepare_output_dir(&base).unwrap();

        assert!(!base.join("findings.json").exists());
        assert!(!base.join("re-findings.jsonl").exists());
        assert!(!base.join(".re").exists());
        assert!(!base.join("bins").exists());
        assert_eq!(
            std::fs::read_to_string(base.join("notes.txt")).unwrap(),
            "keep"
        );

        std::fs::remove_dir_all(base).unwrap();
    }
}
