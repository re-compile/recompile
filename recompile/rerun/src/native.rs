//! Native mode implementation for Linux hosts
//!
//! This module implements direct eBPF-based analysis without a VM.
//! It invokes the C agent (re-mini) to attach probes and monitor the target binary.

use crate::dependencies::{
    capture_binary_dependency_metadata, BinaryDependencyMetadata, DependencyStatus,
};
use crate::issue_groups::{annotate_findings_with_issue_groups, IssueGroupReport};
use crate::summary::{print_findings_summary, read_findings};
use anyhow::{Context, Result};
use re_crashpack::{BinaryInfo, Manifest};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const GENERATED_OUTPUT_FILES: &[&str] = &[
    "analysis.json",
    "console.log",
    "dependencies.json",
    "evidence-pack.json",
    "findings.json",
    "issue-groups.json",
    "manifest.json",
    "re-findings.jsonl",
];

const GENERATED_OUTPUT_DIRS: &[&str] = &[".re", "bins", "escalations", "logs", "replay"];
#[cfg(target_os = "linux")]
const AGENT_TERMINATION_GRACE_MS: u64 = 10_000;
#[cfg(target_os = "linux")]
const AGENT_TERMINATION_POLL_MS: u64 = 50;

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
    logs_dir: PathBuf,
    target_stdout_path: PathBuf,
    target_stderr_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeCapabilityDiagnostic {
    pub component: String,
    pub status: String,
    pub detail: String,
    pub remediation: Option<String>,
}

#[derive(Serialize)]
struct NativeRunMetadata {
    binary_path: String,
    source_path: Option<String>,
    args: Vec<String>,
    cwd: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct NativeRunOptions {
    pub cwd: Option<PathBuf>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct NativeRunResult {
    pub binary_path: PathBuf,
    pub output_dir: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub crashed: bool,
    pub timed_out: bool,
    pub duration_ms: u128,
    pub findings_count: usize,
    pub findings_by_class: BTreeMap<String, u64>,
    pub issue_group_count: usize,
}

#[allow(dead_code)]
enum TargetWaitResult {
    Exited(ExitStatus),
    TimedOut,
}

struct TargetProcess {
    pid: u32,
}

#[derive(Debug, Clone)]
struct CrashObservation {
    exit_code: Option<i32>,
    signal: Option<i32>,
    crashed: bool,
    duration_ms: u128,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    console_log_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl TargetProcess {
    fn id(&self) -> u32 {
        self.pid
    }

    #[cfg(target_os = "linux")]
    fn wait_timeout(self, timeout: Option<Duration>) -> Result<TargetWaitResult> {
        wait_for_exit_with_timeout(self.pid, timeout)
    }

    #[cfg(not(target_os = "linux"))]
    fn wait_timeout(self, _timeout: Option<Duration>) -> Result<TargetWaitResult> {
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
    run_native_with_options(
        binary_path,
        output_dir,
        _escalate_mode,
        _symbolizer_tool,
        args,
        NativeRunOptions::default(),
    )?;
    Ok(())
}

pub fn run_native_with_options(
    binary_path: &PathBuf,
    output_dir: &PathBuf,
    _escalate_mode: &str,
    _symbolizer_tool: &str,
    args: &[String],
    options: NativeRunOptions,
) -> Result<NativeRunResult> {
    // Check if we're on Linux
    if !cfg!(target_os = "linux") {
        return Err(anyhow::anyhow!(
            "Native mode is only supported on Linux. Use the documented Linux Docker-native environment or a Linux host."
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
    let cwd_abs = options
        .cwd
        .as_ref()
        .map(|cwd| {
            std::fs::canonicalize(cwd)
                .with_context(|| format!("Working directory not found: {}", cwd.display()))
        })
        .transpose()?;

    // Locate required components
    let config = locate_components(output_dir)?;
    write_analysis_metadata(&config.crashpack_dir, &binary_abs, args, cwd_abs.as_deref())?;

    println!("Configuration:");
    println!("  Binary:       {}", binary_abs.display());
    println!("  Agent:        {}", config.re_mini_path.display());
    println!("  Heap tracker: {}", config.heap_tracker_path.display());
    println!("  Copy checker: {}", config.copy_checker_path.display());
    println!("  Libc:         {}", config.libc_path.display());
    if let Some(cwd) = &cwd_abs {
        println!("  Cwd:          {}", cwd.display());
    }
    println!("  Debug log:    {}", config.debug_findings_path.display());
    println!("  Crashpack:    {}", config.crashpack_dir.display());
    println!("  Target logs:  {}", config.logs_dir.display());
    println!();

    // Start the target in a stopped state so probes are attached before main executes.
    println!("Starting target in paused state...");
    let target = start_target_paused(
        &binary_abs,
        args,
        cwd_abs.as_deref(),
        &config.target_stdout_path,
        &config.target_stderr_path,
    )?;
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
    let started = Instant::now();
    let wait_result = target
        .wait_timeout(options.timeout)
        .with_context(|| format!("Failed while waiting for {}", binary_abs.display()))?;
    let duration_ms = started.elapsed().as_millis();

    let (target_status, timed_out) = match wait_result {
        TargetWaitResult::Exited(status) => {
            println!("\nTarget exited with status: {}", status);
            append_console_log(
                &config.console_log_path,
                &format!("target_exit_status={}\n", status),
            )?;
            (Some(status), false)
        }
        TargetWaitResult::TimedOut => {
            let timeout_ms = options
                .timeout
                .map(|timeout| timeout.as_millis())
                .unwrap_or_default();
            println!("\nTarget timed out after {}ms", timeout_ms);
            append_console_log(
                &config.console_log_path,
                &format!("target_timeout_ms={}\n", timeout_ms),
            )?;
            (None, true)
        }
    };

    // Give agent time to process final events
    std::thread::sleep(Duration::from_millis(500));

    // Terminate the agent
    println!("Stopping agent...");
    terminate_agent_gracefully(&mut agent);

    let crash_observation = CrashObservation {
        exit_code: target_status.as_ref().and_then(ExitStatus::code),
        signal: exit_signal(target_status.as_ref()),
        crashed: target_status
            .as_ref()
            .map(|status| !status.success())
            .unwrap_or(timed_out),
        duration_ms,
        args: args.to_vec(),
        cwd: cwd_abs.clone(),
        console_log_path: config.console_log_path.clone(),
        stdout_path: config.target_stdout_path.clone(),
        stderr_path: config.target_stderr_path.clone(),
    };

    let (findings_path, issue_group_count) =
        finalize_findings_with_crash(&config.crashpack_dir, &binary_abs, Some(&crash_observation))?;
    let findings = read_findings(&findings_path)?;
    let findings_by_class = class_counts(&findings);

    // Read and display findings
    println!("\n=== Findings ===");
    print_findings_summary(&findings);

    Ok(NativeRunResult {
        binary_path: binary_abs,
        output_dir: output_dir.clone(),
        args: args.to_vec(),
        cwd: cwd_abs,
        exit_code: crash_observation.exit_code,
        signal: crash_observation.signal,
        crashed: crash_observation.crashed,
        timed_out,
        duration_ms,
        findings_count: findings.len(),
        findings_by_class,
        issue_group_count,
    })
}

pub(crate) fn prepare_tool_only_crashpack(
    binary_path: &Path,
    output_dir: &Path,
    args: &[String],
    options: &NativeRunOptions,
) -> Result<()> {
    prepare_output_dir(output_dir)?;
    let binary_abs = std::fs::canonicalize(binary_path)
        .with_context(|| format!("Binary not found: {}", binary_path.display()))?;
    let cwd_abs = options
        .cwd
        .as_ref()
        .map(|cwd| {
            std::fs::canonicalize(cwd)
                .with_context(|| format!("Working directory not found: {}", cwd.display()))
        })
        .transpose()?;
    write_analysis_metadata(output_dir, &binary_abs, args, cwd_abs.as_deref())?;
    finalize_findings(output_dir, &binary_abs)?;
    append_console_log(
        &output_dir.join("console.log"),
        "native_tracing=unavailable tool_only_fallback=enabled\n",
    )?;
    Ok(())
}

pub fn native_capability_diagnostics() -> Vec<NativeCapabilityDiagnostic> {
    native_capability_diagnostics_impl()
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
    let logs_dir = output_dir.join("logs");
    let target_stdout_path = logs_dir.join("target.stdout.log");
    let target_stderr_path = logs_dir.join("target.stderr.log");
    std::fs::create_dir_all(&logs_dir)
        .with_context(|| format!("Failed to create {}", logs_dir.display()))?;

    Ok(NativeConfig {
        re_mini_path,
        heap_tracker_path,
        copy_checker_path,
        sentinel_path,
        libc_path,
        debug_findings_path,
        crashpack_dir: output_dir.to_path_buf(),
        console_log_path,
        logs_dir,
        target_stdout_path,
        target_stderr_path,
    })
}

fn native_capability_diagnostics_impl() -> Vec<NativeCapabilityDiagnostic> {
    let mut diagnostics = Vec::new();

    #[cfg(not(target_os = "linux"))]
    {
        diagnostics.push(NativeCapabilityDiagnostic {
            component: "linux".to_string(),
            status: "unsupported".to_string(),
            detail: format!(
                "native eBPF tracing is not supported on {}",
                std::env::consts::OS
            ),
            remediation: Some(
                "Run inside the documented Linux Docker-native environment or on a Linux host."
                    .to_string(),
            ),
        });
        return diagnostics;
    }

    #[cfg(target_os = "linux")]
    {
        diagnostics.push(ok_diag("linux", "running on Linux"));

        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            diagnostics.push(ok_diag("privilege", "running as uid 0"));
        } else if can_access_bpf().unwrap_or(false) {
            diagnostics.push(ok_diag(
                "privilege",
                "non-root process can read /sys/fs/bpf",
            ));
        } else {
            diagnostics.push(NativeCapabilityDiagnostic {
                component: "privilege".to_string(),
                status: "unavailable".to_string(),
                detail: format!("uid {uid} cannot access BPF resources"),
                remediation: Some(
                    "Use the privileged Docker command from the README or grant CAP_BPF/CAP_PERFMON."
                        .to_string(),
                ),
            });
        }

        let bpf_path = Path::new("/sys/fs/bpf");
        if bpf_path.exists() {
            diagnostics.push(ok_diag("bpf_fs", "/sys/fs/bpf exists"));
        } else {
            diagnostics.push(NativeCapabilityDiagnostic {
                component: "bpf_fs".to_string(),
                status: "missing".to_string(),
                detail: "/sys/fs/bpf is not mounted".to_string(),
                remediation: Some("Mount bpffs or use the supported Docker image.".to_string()),
            });
        }

        if Path::new("/sys/kernel/btf/vmlinux").exists() {
            diagnostics.push(ok_diag("btf", "/sys/kernel/btf/vmlinux exists"));
        } else {
            diagnostics.push(NativeCapabilityDiagnostic {
                component: "btf".to_string(),
                status: "missing".to_string(),
                detail: "kernel BTF vmlinux metadata is unavailable".to_string(),
                remediation: Some(
                    "Install the host kernel BTF/debug package or use the bootstrap image on a BTF-enabled Linux host."
                        .to_string(),
                ),
            });
        }

        match ptrace_diagnostic() {
            Some(diag) => diagnostics.push(diag),
            None => diagnostics.push(ok_diag(
                "ptrace",
                "ptrace policy did not report a hard block",
            )),
        }

        match check_pid_namespace() {
            Ok(()) => diagnostics.push(ok_diag(
                "pid_namespace",
                "host PID namespace is available or not required",
            )),
            Err(error) => diagnostics.push(NativeCapabilityDiagnostic {
                component: "pid_namespace".to_string(),
                status: "unavailable".to_string(),
                detail: error.to_string(),
                remediation: Some(
                    "Run Docker with --privileged --pid=host for native eBPF tracing.".to_string(),
                ),
            }),
        }

        if let Some(path) = find_file_in_paths("re-mini", &re_mini_candidates()) {
            diagnostics.push(ok_diag("re-mini", format!("found {}", path.display())));
        } else {
            diagnostics.push(NativeCapabilityDiagnostic {
                component: "re-mini".to_string(),
                status: "missing".to_string(),
                detail: "native C agent binary was not found".to_string(),
                remediation: Some("Run `make agent` before native tracing.".to_string()),
            });
        }

        diagnostics.extend(bpf_object_diagnostics());

        match detect_libc() {
            Ok(path) => diagnostics.push(ok_diag("libc", format!("found {}", path.display()))),
            Err(error) => diagnostics.push(NativeCapabilityDiagnostic {
                component: "libc".to_string(),
                status: "missing".to_string(),
                detail: error.to_string(),
                remediation: Some("Install glibc runtime metadata or set RE_LIBC.".to_string()),
            }),
        }

        for tool in ["valgrind", "gdb", "clang"] {
            if let Some(path) = find_file_in_paths(tool, &[PathBuf::from(tool)]) {
                diagnostics.push(ok_diag(tool, format!("found {}", path.display())));
            } else {
                diagnostics.push(NativeCapabilityDiagnostic {
                    component: tool.to_string(),
                    status: "missing".to_string(),
                    detail: format!("{tool} was not found in PATH"),
                    remediation: Some(format!(
                        "Install {tool} in the host/container for tool-only fallback or escalation."
                    )),
                });
            }
        }

        diagnostics
    }
}

#[cfg(target_os = "linux")]
fn ok_diag(component: impl Into<String>, detail: impl Into<String>) -> NativeCapabilityDiagnostic {
    NativeCapabilityDiagnostic {
        component: component.into(),
        status: "ok".to_string(),
        detail: detail.into(),
        remediation: None,
    }
}

#[cfg(target_os = "linux")]
fn ptrace_diagnostic() -> Option<NativeCapabilityDiagnostic> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    if status.lines().any(|line| line.trim() == "Seccomp:\t2") {
        return Some(NativeCapabilityDiagnostic {
            component: "ptrace".to_string(),
            status: "warning".to_string(),
            detail: "process is running under seccomp filter mode; ptrace may be blocked"
                .to_string(),
            remediation: Some(
                "Use the documented privileged Docker run command if target pausing fails."
                    .to_string(),
            ),
        });
    }

    let ptrace_scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok()?;
    let trimmed = ptrace_scope.trim();
    if trimmed == "0" || trimmed == "1" {
        Some(ok_diag(
            "ptrace",
            format!("kernel yama ptrace_scope={trimmed}"),
        ))
    } else {
        Some(NativeCapabilityDiagnostic {
            component: "ptrace".to_string(),
            status: "warning".to_string(),
            detail: format!("kernel yama ptrace_scope={trimmed} may block tracing"),
            remediation: Some(
                "Use a tracing-capable Linux host/container or relax ptrace policy for this run."
                    .to_string(),
            ),
        })
    }
}

#[cfg(target_os = "linux")]
fn re_mini_candidates() -> Vec<PathBuf> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));
    vec![
        PathBuf::from("runtime/agent/re-mini"),
        PathBuf::from("recompile/runtime/agent/re-mini"),
        PathBuf::from("../runtime/agent/re-mini"),
        exe_dir
            .as_ref()
            .map(|d| d.join("../runtime/agent/re-mini"))
            .unwrap_or_default(),
        PathBuf::from("/usr/local/bin/re-mini"),
        PathBuf::from("/usr/bin/re-mini"),
    ]
}

#[cfg(target_os = "linux")]
fn bpf_object_diagnostics() -> Vec<NativeCapabilityDiagnostic> {
    let bpf_search_paths = vec![
        PathBuf::from("runtime/bpf"),
        PathBuf::from("recompile/runtime/bpf"),
        PathBuf::from("../runtime/bpf"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("../runtime/bpf")))
            .unwrap_or_default(),
        PathBuf::from("/usr/local/share/recompile/bpf"),
    ];

    ["heap_tracker.bpf.o", "copy_checker.bpf.o"]
        .into_iter()
        .map(|name| {
            let candidates = bpf_search_paths
                .iter()
                .map(|path| path.join(name))
                .collect::<Vec<_>>();
            if let Some(path) = find_file_in_paths(name, &candidates) {
                ok_diag(name, format!("found {}", path.display()))
            } else {
                NativeCapabilityDiagnostic {
                    component: name.to_string(),
                    status: "missing".to_string(),
                    detail: format!("{name} was not found"),
                    remediation: Some("Run `make bpf` before native tracing.".to_string()),
                }
            }
        })
        .collect()
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
fn terminate_agent_gracefully(agent: &mut Child) {
    let pid = agent.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    // Stack symbolization can still be in-flight after the target exits. SIGTERM
    // asks the agent to stop polling, but it should be allowed to finish the
    // current ring-buffer callback before we fall back to SIGKILL.
    for _ in 0..(AGENT_TERMINATION_GRACE_MS / AGENT_TERMINATION_POLL_MS) {
        match agent.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(AGENT_TERMINATION_POLL_MS)),
            Err(_) => return,
        }
    }

    let _ = agent.kill();
    let _ = agent.wait();
}

#[cfg(not(target_os = "linux"))]
fn terminate_agent_gracefully(agent: &mut Child) {
    let _ = agent.kill();
    let _ = agent.wait();
}

#[cfg(target_os = "linux")]
fn start_target_paused(
    binary_path: &Path,
    args: &[String],
    cwd: Option<&Path>,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<TargetProcess> {
    let binary_cstr = CString::new(binary_path.as_os_str().as_bytes()).with_context(|| {
        format!(
            "Binary path contains interior NUL: {}",
            binary_path.display()
        )
    })?;
    let cwd_cstr = cwd
        .map(|cwd| {
            CString::new(cwd.as_os_str().as_bytes())
                .with_context(|| format!("cwd contains interior NUL: {}", cwd.display()))
        })
        .transpose()?;
    let arg_cstrs = args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).context("Argument contains interior NUL"))
        .collect::<Result<Vec<_>>>()?;
    let stdout_cstr = CString::new(stdout_path.as_os_str().as_bytes()).with_context(|| {
        format!(
            "stdout log path contains interior NUL: {}",
            stdout_path.display()
        )
    })?;
    let stderr_cstr = CString::new(stderr_path.as_os_str().as_bytes()).with_context(|| {
        format!(
            "stderr log path contains interior NUL: {}",
            stderr_path.display()
        )
    })?;

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
            redirect_child_fd(stdout_cstr.as_ptr(), libc::STDOUT_FILENO);
            redirect_child_fd(stderr_cstr.as_ptr(), libc::STDERR_FILENO);
            if let Some(cwd_cstr) = cwd_cstr.as_ref() {
                if libc::chdir(cwd_cstr.as_ptr()) != 0 {
                    libc::_exit(125);
                }
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

#[cfg(target_os = "linux")]
unsafe fn redirect_child_fd(path: *const libc::c_char, fd: libc::c_int) {
    let out_fd = libc::open(
        path,
        libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC,
        0o644,
    );
    if out_fd < 0 {
        libc::_exit(124);
    }
    if libc::dup2(out_fd, fd) < 0 {
        libc::_exit(124);
    }
    libc::close(out_fd);
}

#[cfg(not(target_os = "linux"))]
fn start_target_paused(
    _binary_path: &Path,
    _args: &[String],
    _cwd: Option<&Path>,
    _stdout_path: &Path,
    _stderr_path: &Path,
) -> Result<TargetProcess> {
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

#[cfg(target_os = "linux")]
fn wait_for_exit_with_timeout(pid: u32, timeout: Option<Duration>) -> Result<TargetWaitResult> {
    let Some(timeout) = timeout else {
        return wait_for_exit(pid).map(TargetWaitResult::Exited);
    };

    let started = Instant::now();
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if rc == pid as i32 {
            return Ok(TargetWaitResult::Exited(ExitStatus::from_raw(status)));
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

        if started.elapsed() >= timeout {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            let _ = wait_for_exit(pid);
            return Ok(TargetWaitResult::TimedOut);
        }

        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(crate) fn finalize_findings(
    crashpack_dir: &Path,
    binary_path: &Path,
) -> Result<(PathBuf, usize)> {
    finalize_findings_with_crash(crashpack_dir, binary_path, None)
}

fn finalize_findings_with_crash(
    crashpack_dir: &Path,
    binary_path: &Path,
    crash: Option<&CrashObservation>,
) -> Result<(PathBuf, usize)> {
    let findings_path = crashpack_dir.join("findings.json");
    let copied_binary_path = write_binary_artifacts(crashpack_dir, binary_path)?;
    let mut findings = if findings_path.exists() {
        let content = std::fs::read_to_string(&findings_path)
            .with_context(|| format!("Failed to read {}", findings_path.display()))?;
        let mut findings = parse_findings_content(&content)
            .with_context(|| format!("Failed to normalize {}", findings_path.display()))?;
        attach_finding_provenance(&mut findings, binary_path, &copied_binary_path);
        findings
    } else {
        Vec::new()
    };
    if findings.is_empty() {
        if let Some(crash_finding) = crash
            .and_then(|crash| crash_observation_finding(crash, binary_path, &copied_binary_path))
        {
            findings.push(crash_finding);
        }
    }
    let issue_groups = annotate_findings_with_issue_groups(&mut findings);

    std::fs::write(&findings_path, serde_json::to_vec_pretty(&findings)?)
        .with_context(|| format!("Failed to rewrite {}", findings_path.display()))?;
    write_issue_groups(crashpack_dir, &issue_groups)?;
    write_manifest(crashpack_dir, &findings)?;
    let dependency_metadata = write_dependency_metadata(crashpack_dir, binary_path)?;
    copy_local_dynamic_dependencies(crashpack_dir, &dependency_metadata)?;
    write_agent_evidence_pack(
        crashpack_dir,
        binary_path,
        &copied_binary_path,
        &findings,
        &issue_groups,
    )?;

    println!("\nFindings saved to: {}", findings_path.display());
    Ok((findings_path, issue_groups.group_count()))
}

fn write_analysis_metadata(
    crashpack_dir: &Path,
    binary_path: &Path,
    args: &[String],
    cwd: Option<&Path>,
) -> Result<()> {
    let metadata = NativeRunMetadata {
        binary_path: binary_path.display().to_string(),
        source_path: None,
        args: args.to_vec(),
        cwd: cwd.map(|cwd| cwd.display().to_string()),
    };
    let metadata_path = crashpack_dir.join("analysis.json");
    std::fs::write(metadata_path, serde_json::to_vec_pretty(&metadata)?)?;
    Ok(())
}

fn class_counts(findings: &[Value]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        let class = finding_string(finding, &["class"])
            .or_else(|| finding_string(finding, &["kind"]))
            .unwrap_or_else(|| "unknown".to_string());
        *counts.entry(class).or_default() += 1;
    }
    counts
}

fn crash_observation_finding(
    crash: &CrashObservation,
    original_binary_path: &Path,
    copied_binary_path: &Path,
) -> Option<Value> {
    if !crash.crashed {
        return None;
    }
    let signal = crash.signal?;
    let signal_name = observed_signal_name(signal)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let binary_name = original_binary_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("target");
    let cwd = crash
        .cwd
        .as_ref()
        .map(|cwd| cwd.display().to_string())
        .unwrap_or_else(|| ".".to_string());
    let stdout_path = crash.stdout_path.display().to_string();
    let stderr_path = crash.stderr_path.display().to_string();
    let console_log_path = crash.console_log_path.display().to_string();
    let crashpack_dir = crash
        .console_log_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .display()
        .to_string();

    Some(json!({
        "schema_version": "1.0",
        "id": format!("F-unclassified-crash-{}", timestamp),
        "origin": "runtime",
        "kind": "unclassified_crash",
        "class": "unclassified_crash",
        "severity": "error",
        "confidence": "observed",
        "timestamp": timestamp,
        "pid": 0,
        "message": format!(
            "{} terminated with {}. Treat this as crash evidence, not a precise memory-bug diagnosis.",
            binary_name,
            signal_name
        ),
        "primaryLocation": {
            "uri": "file://unknown",
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 1}
            }
        },
        "evidence": {
            "api": "crash_observed",
            "crash": {
                "signal": signal,
                "signal_name": signal_name,
                "exit_code": crash.exit_code,
                "duration_ms": crash.duration_ms,
                "binary_path": original_binary_path.display().to_string(),
                "captured_binary_path": copied_binary_path.display().to_string(),
                "args": crash.args.clone(),
                "cwd": cwd,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "console_log_path": console_log_path
            },
            "stacks": {
                "crash": []
            },
            "event_sequence": [{
                "source": "runtime",
                "event": "target_exit_signal",
                "signal": signal,
                "signal_name": signal_name,
                "exit_code": crash.exit_code,
                "duration_ms": crash.duration_ms
            }]
        },
        "provenance": {
            "binary_path": copied_binary_path.display().to_string(),
            "original_binary_path": original_binary_path.display().to_string(),
            "source_status": "unresolved"
        },
        "fixHints": [
            "Replay the crashpack and inspect target stdout/stderr before assigning a precise memory class.",
            "Run under gdb or a sanitizer build if the signal alone is not enough to locate the fault."
        ],
        "next_commands": [
            format!("rerun summarize {} --format json", crashpack_dir),
            format!("rerun replay {} --format json", crashpack_dir)
        ],
        "escalation": {
            "tool": "gdb",
            "reason": "signal_only_crash_needs_stack_confirmation",
            "estimated_cost": "medium",
            "cooldown_ms": 0
        },
        "related": []
    }))
}

fn observed_signal_name(signal: i32) -> Option<&'static str> {
    match signal {
        #[cfg(target_os = "linux")]
        libc::SIGSEGV => Some("SIGSEGV"),
        #[cfg(target_os = "linux")]
        libc::SIGABRT => Some("SIGABRT"),
        #[cfg(target_os = "linux")]
        libc::SIGBUS => Some("SIGBUS"),
        #[cfg(target_os = "linux")]
        libc::SIGFPE => Some("SIGFPE"),
        #[cfg(not(target_os = "linux"))]
        11 => Some("SIGSEGV"),
        #[cfg(not(target_os = "linux"))]
        6 => Some("SIGABRT"),
        #[cfg(not(target_os = "linux"))]
        7 => Some("SIGBUS"),
        #[cfg(not(target_os = "linux"))]
        8 => Some("SIGFPE"),
        _ => None,
    }
}

fn exit_signal(status: Option<&ExitStatus>) -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        status.and_then(ExitStatusExt::signal)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = status;
        None
    }
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

fn write_dependency_metadata(
    crashpack_dir: &Path,
    binary_path: &Path,
) -> Result<BinaryDependencyMetadata> {
    let metadata = capture_binary_dependency_metadata(binary_path);
    let metadata_path = crashpack_dir.join("dependencies.json");
    std::fs::write(&metadata_path, serde_json::to_vec_pretty(&metadata)?)
        .with_context(|| format!("Failed to write {}", metadata_path.display()))?;
    Ok(metadata)
}

fn copy_local_dynamic_dependencies(
    crashpack_dir: &Path,
    metadata: &BinaryDependencyMetadata,
) -> Result<()> {
    let bins_lib_dir = crashpack_dir.join("bins").join("lib");
    for dependency in &metadata.dynamic_dependencies {
        if dependency.status != DependencyStatus::Resolved {
            continue;
        }
        let Some(path) = dependency.path.as_deref().map(Path::new) else {
            continue;
        };
        if is_system_library_path(path) {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        std::fs::create_dir_all(&bins_lib_dir)
            .with_context(|| format!("Failed to create {}", bins_lib_dir.display()))?;
        let destination = bins_lib_dir.join(file_name);
        std::fs::copy(path, &destination).with_context(|| {
            format!(
                "Failed to copy dynamic dependency {} to {}",
                path.display(),
                destination.display()
            )
        })?;
    }
    Ok(())
}

fn is_system_library_path(path: &Path) -> bool {
    path.starts_with("/lib")
        || path.starts_with("/lib64")
        || path.starts_with("/usr/lib")
        || path.starts_with("/usr/lib64")
}

fn write_issue_groups(crashpack_dir: &Path, issue_groups: &IssueGroupReport) -> Result<()> {
    let issue_groups_path = crashpack_dir.join("issue-groups.json");
    std::fs::write(&issue_groups_path, serde_json::to_vec_pretty(issue_groups)?)
        .with_context(|| format!("Failed to write {}", issue_groups_path.display()))?;
    Ok(())
}

fn write_agent_evidence_pack(
    crashpack_dir: &Path,
    original_binary_path: &Path,
    copied_binary_path: &Path,
    findings: &[Value],
    issue_groups: &IssueGroupReport,
) -> Result<()> {
    let pack = build_agent_evidence_pack(
        crashpack_dir,
        original_binary_path,
        copied_binary_path,
        findings,
        issue_groups,
    );
    let pack_path = crashpack_dir.join("evidence-pack.json");
    std::fs::write(&pack_path, serde_json::to_vec_pretty(&pack)?)
        .with_context(|| format!("Failed to write {}", pack_path.display()))?;
    Ok(())
}

fn build_agent_evidence_pack(
    crashpack_dir: &Path,
    original_binary_path: &Path,
    copied_binary_path: &Path,
    findings: &[Value],
    issue_groups: &IssueGroupReport,
) -> Value {
    let mut class_counts = BTreeMap::<String, usize>::new();
    let mut resolved_sources = 0usize;
    let mut unresolved_sources = 0usize;

    let agent_findings = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            let class = finding_string(finding, &["class"])
                .or_else(|| finding_string(finding, &["kind"]))
                .unwrap_or_else(|| "unknown".to_string());
            *class_counts.entry(class.clone()).or_default() += 1;

            match finding_string(finding, &["provenance", "source_status"]).as_deref() {
                Some("resolved") => resolved_sources += 1,
                Some("unresolved") => unresolved_sources += 1,
                _ => {}
            }

            json!({
                "index": index,
                "id": finding_string(finding, &["id"]).unwrap_or_else(|| format!("finding-{}", index + 1)),
                "origin": finding_string(finding, &["origin"]).unwrap_or_else(|| "ebpf".to_string()),
                "fingerprint": finding.get("fingerprint").cloned().unwrap_or(Value::Null),
                "issue_group_id": finding.get("issue_group_id").cloned().unwrap_or(Value::Null),
                "class": class,
                "severity": finding_string(finding, &["severity"]).unwrap_or_else(|| "unknown".to_string()),
                "confidence": finding_string(finding, &["confidence"]).unwrap_or_else(|| "unknown".to_string()),
                "source": {
                    "status": finding_string(finding, &["provenance", "source_status"]).unwrap_or_else(|| "unknown".to_string()),
                    "path": finding.get("provenance")
                        .and_then(|value| value.get("source_path"))
                        .cloned()
                        .unwrap_or(Value::Null),
                },
                "operation": finding_string(finding, &["evidence", "memory", "operation"])
                    .or_else(|| finding_string(finding, &["evidence", "resource", "operation"]))
                    .or_else(|| finding_string(finding, &["evidence", "api"]))
                    .unwrap_or_else(|| "unknown".to_string()),
                "memory": finding.get("evidence")
                    .and_then(|value| value.get("memory"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "resource": finding.get("evidence")
                    .and_then(|value| value.get("resource"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "crash": finding.get("evidence")
                    .and_then(|value| value.get("crash"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "stacks": finding.get("evidence")
                    .and_then(|value| value.get("stacks"))
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                "alloc_site": finding.get("evidence")
                    .and_then(|value| value.get("alloc_site"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "tool": finding.get("evidence")
                    .and_then(|value| value.get("tool"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "escalation_plan": finding.get("escalation").cloned().unwrap_or(Value::Null),
                "raw_finding": finding,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": "1.0",
        "purpose": "agent_runtime_evidence",
        "artifacts": {
            "crashpack_dir": crashpack_dir.display().to_string(),
            "evidence_pack": crashpack_dir.join("evidence-pack.json").display().to_string(),
            "findings": crashpack_dir.join("findings.json").display().to_string(),
            "manifest": crashpack_dir.join("manifest.json").display().to_string(),
            "analysis": crashpack_dir.join("analysis.json").display().to_string(),
            "dependencies": crashpack_dir.join("dependencies.json").display().to_string(),
            "issue_groups": crashpack_dir.join("issue-groups.json").display().to_string(),
            "console_log": crashpack_dir.join("console.log").display().to_string(),
            "debug_stream": crashpack_dir.join("re-findings.jsonl").display().to_string(),
        },
        "binary": {
            "original_path": original_binary_path.display().to_string(),
            "captured_path": copied_binary_path.display().to_string(),
        },
        "summary": {
            "total_findings": findings.len(),
            "class_counts": class_counts,
            "source_resolved": resolved_sources,
            "source_unresolved": unresolved_sources,
            "issue_group_count": issue_groups.group_count(),
        },
        "issue_groups": issue_groups.groups,
        "findings": agent_findings,
    })
}

fn finding_string(finding: &Value, path: &[&str]) -> Option<String> {
    let mut current = finding;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(str::to_string)
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
        let source_path = extract_source_path(object, original_binary_path);

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

        if let Some(source_path) = source_path {
            provenance
                .entry("source_path".to_string())
                .or_insert_with(|| Value::String(source_path));
            provenance.insert(
                "source_status".to_string(),
                Value::String("resolved".to_string()),
            );
        } else {
            provenance
                .entry("source_status".to_string())
                .or_insert_with(|| Value::String("unresolved".to_string()));
        }
    }
}

fn extract_source_path(
    finding: &Map<String, Value>,
    original_binary_path: &Path,
) -> Option<String> {
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
        .or_else(|| source_path_from_stack_summaries(finding))
        .or_else(|| source_path_from_binary_offset_frames(finding, original_binary_path))
}

fn source_path_from_stack_summaries(finding: &Map<String, Value>) -> Option<String> {
    stack_frame_strings(finding).find_map(|frame| source_path_from_stack_summary(&frame))
}

fn source_path_from_stack_summary(frame: &str) -> Option<String> {
    let start = frame.rfind('(')?;
    let end = frame.rfind(')')?;
    if end <= start {
        return None;
    }

    source_path_from_location(&frame[start + 1..end])
}

fn source_path_from_binary_offset_frames(
    finding: &Map<String, Value>,
    original_binary_path: &Path,
) -> Option<String> {
    stack_frame_strings(finding).find_map(|frame| {
        let (binary_path, offset) = binary_offset_frame(&frame)?;
        let candidate_binary = if binary_path.exists() {
            binary_path
        } else {
            original_binary_path.to_path_buf()
        };
        symbolize_binary_offset(&candidate_binary, offset)
            .ok()
            .flatten()
    })
}

fn stack_frame_strings(finding: &Map<String, Value>) -> impl Iterator<Item = String> + '_ {
    ["call", "alloc"].into_iter().flat_map(|stack_name| {
        finding
            .get("evidence")
            .and_then(|value| value.get("stacks"))
            .and_then(|value| value.get(stack_name))
            .and_then(|value| value.as_array())
            .into_iter()
            .flat_map(|frames| frames.iter())
            .filter_map(|frame| frame.as_str().map(str::trim))
            .filter(|frame| !frame.is_empty())
            .map(str::to_string)
    })
}

fn binary_offset_frame(frame: &str) -> Option<(PathBuf, &str)> {
    let (path, offset) = frame.rsplit_once("+0x")?;
    if path.trim().is_empty() || offset.trim().is_empty() {
        return None;
    }

    Some((PathBuf::from(path.trim()), offset.trim()))
}

fn symbolize_binary_offset(binary_path: &Path, offset_hex: &str) -> Result<Option<String>> {
    if !binary_path.exists() {
        return Ok(None);
    }

    let offset = format!("0x{}", offset_hex.trim_start_matches("0x"));
    if let Ok(output) = Command::new("llvm-symbolizer")
        .arg(format!("--obj={}", binary_path.display()))
        .arg(&offset)
        .output()
    {
        if output.status.success() {
            if let Some(source_path) = parse_symbolizer_output(&output.stdout) {
                return Ok(Some(source_path));
            }
        }
    }

    if let Ok(output) = Command::new("addr2line")
        .args(["-f", "-C", "-e"])
        .arg(binary_path)
        .arg(&offset)
        .output()
    {
        if output.status.success() {
            if let Some(source_path) = parse_symbolizer_output(&output.stdout) {
                return Ok(Some(source_path));
            }
        }
    }

    Ok(None)
}

fn parse_symbolizer_output(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    text.lines().find_map(source_path_from_location)
}

fn source_path_from_location(location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() || location == "??" || location.starts_with("??:") {
        return None;
    }

    let without_column = strip_trailing_numeric_component(location);
    if without_column == location {
        return None;
    }
    let without_line = strip_trailing_numeric_component(without_column);
    let source_path = without_line.trim();
    if source_path.is_empty() || source_path == "??" {
        return None;
    }

    Some(source_path.to_string())
}

fn strip_trailing_numeric_component(value: &str) -> &str {
    let Some((head, tail)) = value.rsplit_once(':') else {
        return value;
    };
    if !tail.is_empty() && tail.chars().all(|ch| ch.is_ascii_digit()) {
        head
    } else {
        value
    }
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
                3. Use the documented Linux Docker-native command with --privileged --pid=host\n\
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
    use serde_json::json;

    #[test]
    fn prepare_output_dir_removes_generated_artifacts_only() {
        let base =
            std::env::temp_dir().join(format!("rerun-output-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".re")).unwrap();
        std::fs::create_dir_all(base.join("bins")).unwrap();
        std::fs::create_dir_all(base.join("logs")).unwrap();
        std::fs::create_dir_all(base.join("replay")).unwrap();
        std::fs::write(base.join("evidence-pack.json"), "{}").unwrap();
        std::fs::write(base.join("findings.json"), "[{}]").unwrap();
        std::fs::write(base.join("re-findings.jsonl"), "stale\n").unwrap();
        std::fs::write(base.join(".re").join("last_finding.json"), "{}").unwrap();
        std::fs::write(base.join("logs").join("target.stdout.log"), "stale\n").unwrap();
        std::fs::write(base.join("replay").join("results.json"), "{}").unwrap();
        std::fs::write(base.join("notes.txt"), "keep").unwrap();

        prepare_output_dir(&base).unwrap();

        assert!(!base.join("evidence-pack.json").exists());
        assert!(!base.join("findings.json").exists());
        assert!(!base.join("re-findings.jsonl").exists());
        assert!(!base.join(".re").exists());
        assert!(!base.join("bins").exists());
        assert!(!base.join("logs").exists());
        assert!(!base.join("replay").exists());
        assert_eq!(
            std::fs::read_to_string(base.join("notes.txt")).unwrap(),
            "keep"
        );

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn copies_local_dynamic_dependencies_for_replay_layout() {
        let base = std::env::temp_dir().join(format!("rerun-dynamic-deps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let source_dir = base.join("source");
        let crashpack_dir = base.join("crashpack");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(crashpack_dir.join("bins")).unwrap();
        let local_lib = source_dir.join("libprojectbug.so");
        std::fs::write(&local_lib, b"shared-lib").unwrap();

        let metadata = BinaryDependencyMetadata {
            schema_version: "1.0".to_string(),
            purpose: "binary_dependency_metadata".to_string(),
            binary_path: "/tmp/app".to_string(),
            file_size: None,
            readelf: crate::dependencies::ToolStatus {
                tool: "readelf".to_string(),
                status: crate::dependencies::ToolAvailability::Available,
                error: None,
            },
            ldd: crate::dependencies::ToolStatus {
                tool: "ldd".to_string(),
                status: crate::dependencies::ToolAvailability::Available,
                error: None,
            },
            elf: crate::dependencies::ElfMetadata::default(),
            dynamic_dependencies: vec![
                crate::dependencies::DynamicDependency {
                    name: "libprojectbug.so".to_string(),
                    path: Some(local_lib.display().to_string()),
                    status: DependencyStatus::Resolved,
                },
                crate::dependencies::DynamicDependency {
                    name: "libc.so.6".to_string(),
                    path: Some("/lib/aarch64-linux-gnu/libc.so.6".to_string()),
                    status: DependencyStatus::Resolved,
                },
            ],
        };

        copy_local_dynamic_dependencies(&crashpack_dir, &metadata).unwrap();

        assert_eq!(
            std::fs::read(crashpack_dir.join("bins/lib/libprojectbug.so")).unwrap(),
            b"shared-lib"
        );
        assert!(!crashpack_dir.join("bins/lib/libc.so.6").exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn source_path_from_stack_summary_strips_line_and_column() {
        assert_eq!(
            source_path_from_stack_summary("main (/tmp/project/example.c:18:3)").as_deref(),
            Some("/tmp/project/example.c")
        );
        assert_eq!(
            source_path_from_stack_summary("main (/tmp/project/example.c:18)").as_deref(),
            Some("/tmp/project/example.c")
        );
    }

    #[test]
    fn source_path_ignores_unknown_symbolizer_locations() {
        assert_eq!(source_path_from_location("??:0"), None);
        assert_eq!(source_path_from_location("??"), None);
        assert_eq!(source_path_from_location("main"), None);
    }

    #[test]
    fn parse_symbolizer_output_skips_function_names() {
        assert_eq!(
            parse_symbolizer_output(b"main\n/tmp/project/example.c:18:3\n").as_deref(),
            Some("/tmp/project/example.c")
        );
    }

    #[test]
    fn binary_offset_frame_parses_module_and_offset() {
        let (path, offset) = binary_offset_frame("/tmp/app+0x770").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/app"));
        assert_eq!(offset, "770");
    }

    #[test]
    fn extract_source_path_uses_stack_summary_when_primary_is_unknown() {
        let finding = json!({
            "evidence": {
                "alloc_site": "",
                "stacks": {
                    "call": [
                        "0xffffab0a6ec0",
                        "main (/workspace/recompile/examples/invalid_free.c:14)",
                        "/workspace/recompile/build/examples/invalid_free+0x770"
                    ],
                    "alloc": []
                }
            },
            "primaryLocation": {"uri": "file://unknown"}
        });
        let object = finding.as_object().unwrap();

        assert_eq!(
            extract_source_path(
                object,
                Path::new("/workspace/recompile/build/examples/invalid_free")
            )
            .as_deref(),
            Some("/workspace/recompile/examples/invalid_free.c")
        );
    }

    #[test]
    fn attach_provenance_marks_unresolved_source_explicitly() {
        let mut findings = vec![json!({
            "class": "invalid_free",
            "evidence": {
                "alloc_site": "",
                "stacks": {
                    "call": ["/tmp/app+0x770"],
                    "alloc": []
                }
            }
        })];

        attach_finding_provenance(&mut findings, Path::new("/tmp/app"), Path::new("/tmp/copy"));

        let provenance = findings[0].get("provenance").unwrap();
        assert_eq!(
            provenance.get("source_status").and_then(Value::as_str),
            Some("unresolved")
        );
        assert!(provenance.get("source_path").is_none());
    }

    #[test]
    fn agent_evidence_pack_summarizes_findings_for_agents() {
        let mut findings = vec![json!({
            "id": "F-1",
            "class": "heap_overflow",
            "severity": "error",
            "confidence": "high",
            "evidence": {
                "memory": {
                    "operation": "memcpy",
                    "ptr": 4096,
                    "size": 64,
                    "alloc_size": 16
                },
                "stacks": {
                    "call": ["copy (/tmp/project/src/app.c:12)"],
                    "alloc": ["make_buffer (/tmp/project/src/app.c:6)"]
                },
                "alloc_site": "/tmp/project/src/app.c"
            },
            "provenance": {
                "source_status": "resolved",
                "source_path": "/tmp/project/src/app.c"
            },
            "escalation": {
                "tool": "valgrind",
                "reason": "len>alloc_size"
            }
        })];
        let issue_groups = annotate_findings_with_issue_groups(&mut findings);

        let pack = build_agent_evidence_pack(
            Path::new("/tmp/crashpack"),
            Path::new("/tmp/project/build/app"),
            Path::new("/tmp/crashpack/bins/app"),
            &findings,
            &issue_groups,
        );

        assert_eq!(
            pack.pointer("/summary/total_findings")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            pack.pointer("/summary/class_counts/heap_overflow")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            pack.pointer("/summary/source_resolved")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            pack.pointer("/findings/0/operation")
                .and_then(Value::as_str),
            Some("memcpy")
        );
        assert_eq!(
            pack.pointer("/findings/0/source/path")
                .and_then(Value::as_str),
            Some("/tmp/project/src/app.c")
        );
        assert_eq!(
            pack.pointer("/artifacts/findings").and_then(Value::as_str),
            Some("/tmp/crashpack/findings.json")
        );
        assert_eq!(
            pack.pointer("/artifacts/dependencies")
                .and_then(Value::as_str),
            Some("/tmp/crashpack/dependencies.json")
        );
        assert_eq!(
            pack.pointer("/artifacts/issue_groups")
                .and_then(Value::as_str),
            Some("/tmp/crashpack/issue-groups.json")
        );
        assert_eq!(
            pack.pointer("/summary/issue_group_count")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            pack.pointer("/findings/0/issue_group_id")
                .and_then(Value::as_str),
            pack.pointer("/issue_groups/0/id").and_then(Value::as_str)
        );
    }
}
