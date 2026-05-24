//! CLI command handlers

use anyhow::Result;
use clap::ArgMatches;
use re_crashpack::EscalationPlan as FindingEscalationPlan;
use re_escalate::{EscalationConfig, EscalationResult, EscalationRunner, Finding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::native::{
    finalize_findings, native_capability_diagnostics, prepare_tool_only_crashpack, run_native,
    run_native_with_options, NativeCapabilityDiagnostic, NativeRunOptions, NativeRunResult,
};
use crate::observation::{
    ObservationArtifacts, ObservationDiagnostic, ObservationRunSummary, ObservationTargetSummary,
    TargetExitSummary, TargetStatus,
};
use crate::summary::{print_findings_summary, read_findings};

#[derive(Deserialize)]
struct NativeRunMetadata {
    binary_path: String,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Serialize)]
struct ReplayResult {
    schema_version: String,
    crashpack: String,
    binary_path: String,
    args: Vec<String>,
    ran: bool,
    exit_success: bool,
    exit_code: Option<i32>,
    duration_ms: u128,
    stdout: String,
    stderr: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct CrashpackFindingSnapshot {
    count: u64,
    class_counts: BTreeMap<String, u64>,
    issue_group_count: u64,
}

#[derive(Debug, Clone)]
struct ToolDetection {
    class: String,
    summary: String,
    line: Option<u64>,
    call_frame: Option<String>,
    alloc_frame: Option<String>,
    free_frame: Option<String>,
}

/// Handle the 'run' command
pub fn handle_run_command(matches: &ArgMatches) -> Result<()> {
    let binary = matches.get_one::<String>("binary").unwrap();
    let binary_path = PathBuf::from(binary);

    let vm_mode = matches.get_flag("vm");
    let native_mode = !vm_mode;
    let escalate_mode = matches.get_one::<String>("escalate").unwrap();
    let output_dir = matches
        .get_one::<String>("output")
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("build/crashpack"));
    let symbolizer_tool = matches.get_one::<String>("symbolizer").unwrap();
    let args: Vec<String> = matches
        .get_many::<String>("args")
        .map(|args| args.map(|s| s.to_string()).collect())
        .unwrap_or_default();

    println!("re:compile runtime observer v0.1.0");
    println!("Analyzing binary: {}", binary_path.display());
    println!(
        "Mode: {}",
        if native_mode {
            "native"
        } else {
            "VM (deferred)"
        }
    );
    println!("Escalation: {}", escalate_mode);
    println!("Symbolizer: {}", symbolizer_tool);
    println!("Output: {}", output_dir.display());

    if vm_mode {
        return Err(anyhow::anyhow!(
            "VM mode is deferred and not part of the supported workflow.\n\
             Use `re run --native <binary>` on Linux, or run inside the documented Docker-native environment."
        ));
    }

    run_native(
        &binary_path,
        &output_dir,
        escalate_mode,
        symbolizer_tool,
        &args,
    )?;

    println!(
        "Analysis completed. Results saved to: {}",
        output_dir.display()
    );
    Ok(())
}

/// Handle the 'observe' command
pub fn handle_observe_command(matches: &ArgMatches) -> Result<()> {
    let binary_path = PathBuf::from(matches.get_one::<String>("binary").unwrap());
    let output_root = PathBuf::from(matches.get_one::<String>("output").unwrap());
    let cwd = matches.get_one::<String>("cwd").map(PathBuf::from);
    let timeout_ms = matches.get_one::<u64>("timeout-ms").copied();
    let native_only = matches.get_flag("native-only");
    let deep = matches.get_flag("deep");
    let args: Vec<String> = matches
        .get_many::<String>("args")
        .map(|args| args.map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let target_name = observation_target_name(&binary_path);
    let target_dir = output_root.join("targets").join(&target_name);
    fs::create_dir_all(&target_dir)?;
    let native_diagnostics = observation_diagnostics_from_native(native_capability_diagnostics());

    println!("re:compile runtime observer v0.1.0");
    println!("Observing binary: {}", binary_path.display());
    println!("Output root: {}", output_root.display());
    println!("Target output: {}", target_dir.display());
    if let Some(cwd) = &cwd {
        println!("Cwd: {}", cwd.display());
    }
    if let Some(timeout_ms) = timeout_ms {
        println!("Timeout: {}ms", timeout_ms);
    }
    if native_only {
        println!("Escalation: native-only");
    } else if deep {
        println!("Escalation: deep");
    } else {
        println!("Escalation: confirm");
    }

    let started = Instant::now();
    let run_options = NativeRunOptions {
        cwd: cwd.clone(),
        timeout: timeout_ms.map(Duration::from_millis),
    };
    let native_result = run_native_with_options(
        &binary_path,
        &target_dir,
        "never",
        "llvm",
        &args,
        run_options.clone(),
    );

    let mut used_tool_only_fallback = false;
    let mut target = match native_result {
        Ok(result) => {
            let mut target =
                observation_target_from_native_result(&target_name, timeout_ms, result);
            target.diagnostics = native_diagnostics.clone();
            target
        }
        Err(error) => {
            let native_error = error.to_string();
            let mut target = observation_target_from_error(
                &target_name,
                &binary_path,
                &args,
                cwd.as_deref(),
                &output_root,
                timeout_ms,
                native_error.clone(),
                started.elapsed().as_millis(),
            );
            target.diagnostics = native_diagnostics.clone();
            if !native_only && native_error_allows_tool_only_fallback(&native_error) {
                used_tool_only_fallback = true;
                run_observe_tool_only_fallback(
                    &mut target,
                    &binary_path,
                    &target_dir,
                    &args,
                    &run_options,
                    deep,
                    timeout_ms,
                )?;
            }
            target
        }
    };

    if !native_only && !used_tool_only_fallback && !had_observation_error(target.status) {
        let escalation_results = run_observe_escalation(&target, deep)?;
        if !escalation_results.is_empty() {
            write_escalation_results(
                &PathBuf::from(&target.artifacts.crashpack),
                &escalation_results,
            )?;
            let escalation_summaries = escalation_results
                .iter()
                .map(observation_escalation_summary)
                .collect::<Vec<_>>();
            if target.status == TargetStatus::Clean
                && escalation_summaries
                    .iter()
                    .any(|summary| summary.confirmed || !summary.findings_detected.is_empty())
            {
                target.status = TargetStatus::Findings;
            }
            target.escalation = escalation_summaries;
            if let Some(snapshot) = promote_tool_findings_to_crashpack(
                &PathBuf::from(&target.artifacts.crashpack),
                &escalation_results,
            )? {
                target.findings_count = snapshot.count;
                target.findings_by_class = snapshot.class_counts;
                target.issue_group_count = snapshot.issue_group_count;
            }
        }
    }

    let had_error = had_observation_error(target.status);
    let summary = ObservationRunSummary::new(
        output_root.display().to_string(),
        vec![target],
        vec![format!(
            "jq . {}",
            output_root.join("run-summary.json").display()
        )],
    );
    write_observation_summary(&output_root, &summary)?;

    println!(
        "Observation summary saved to: {}",
        output_root.join("run-summary.json").display()
    );

    if had_error {
        return Err(anyhow::anyhow!(
            "Observation completed with target status {}",
            summary.targets[0].status.as_str()
        ));
    }

    Ok(())
}

/// Handle the 'escalate' command
pub fn handle_escalate_command(matches: &ArgMatches) -> Result<()> {
    let crashpack_path = matches.get_one::<String>("crashpack").unwrap();
    let tool = matches.get_one::<String>("tool").unwrap();
    let check_clean = matches.get_flag("check-clean");
    let scan_binary = matches.get_flag("scan-binary");
    let crashpack_dir = PathBuf::from(crashpack_path);
    let findings_path = crashpack_dir.join("findings.json");

    println!("Running escalation analysis on: {}", crashpack_path);
    println!("Tool: {}", tool);

    if !findings_path.exists() {
        return Err(anyhow::anyhow!(
            "No findings.json found in {}",
            crashpack_dir.display()
        ));
    }

    let analysis = load_analysis_metadata(&crashpack_dir)?;
    let mut config = EscalationConfig::default();
    config.output_dir = crashpack_dir.join("escalations").display().to_string();
    config.binary_path = Some(analysis.binary_path.clone());
    config.source_file = analysis.source_path.clone();
    config.cwd = analysis.cwd.clone();
    config.args = analysis.args.clone();

    if scan_binary {
        if tool == "all" {
            return Err(anyhow::anyhow!(
                "--scan-binary requires an explicit tool, such as --tool valgrind, --tool asan, --tool lsan, or --tool ubsan"
            ));
        }
        return run_binary_escalation_scan(&crashpack_dir, tool, config);
    }

    let findings = load_findings(&findings_path)?;
    if findings.is_empty() {
        if !check_clean {
            println!("No findings to escalate.");
            return Ok(());
        }
        if tool == "all" {
            return Err(anyhow::anyhow!(
                "--check-clean requires an explicit tool, such as --tool valgrind, --tool asan, --tool lsan, or --tool ubsan"
            ));
        }

        return run_binary_escalation_scan(&crashpack_dir, tool, config);
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let results = runtime.block_on(async move {
        let mut runner = EscalationRunner::new(config);
        let mut results = Vec::new();
        for mut finding in findings {
            if tool != "all" {
                let mut plan = finding.escalation.unwrap_or(FindingEscalationPlan {
                    tool: tool.to_string(),
                    reason: "manual_override".to_string(),
                    estimated_cost: "unknown".to_string(),
                    cooldown_ms: 0,
                });
                plan.tool = tool.to_string();
                finding.escalation = Some(plan);
            }

            if let Some(plan) = &finding.escalation {
                println!("Escalating finding {} with tool {}", finding.id, plan.tool);
                let result = runner.escalate(&finding).await?;
                if result.success {
                    println!(
                        "✓ Escalation successful: {} ({}ms)",
                        result.tool, result.duration_ms
                    );
                    if result.confirmed {
                        println!("  Confirmed: {}", result.findings_detected.join(", "));
                    } else {
                        println!("  Confirmed: no");
                    }
                    if let Some(output_path) = &result.output_path {
                        println!("  Output: {}", output_path);
                    }
                } else {
                    println!(
                        "✗ Escalation failed: {} ({}ms)",
                        result.tool, result.duration_ms
                    );
                    if let Some(error) = &result.error {
                        println!("  Error: {}", error);
                    }
                }
                results.push(result);
            } else {
                println!("Skipping {}: no escalation plan", finding.id);
            }
        }

        Ok::<Vec<EscalationResult>, anyhow::Error>(results)
    })?;

    write_escalation_results(&crashpack_dir, &results)?;
    let _ = promote_tool_findings_to_crashpack(&crashpack_dir, &results)?;
    println!("Escalation analysis completed.");
    Ok(())
}

fn run_binary_escalation_scan(
    crashpack_dir: &PathBuf,
    tool: &str,
    config: EscalationConfig,
) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let mut runner = EscalationRunner::new(config);
        runner.check_clean_binary(tool).await
    })?;

    if result.success {
        println!(
            "✓ Binary escalation scan ran: {} ({}ms)",
            result.tool, result.duration_ms
        );
        if result.confirmed {
            println!("  Confirmed: {}", result.findings_detected.join(", "));
        } else {
            println!("  Confirmed: no");
        }
        if let Some(output_path) = &result.output_path {
            println!("  Output: {}", output_path);
        }
    } else {
        println!(
            "✗ Binary escalation scan failed: {} ({}ms)",
            result.tool, result.duration_ms
        );
        if let Some(error) = &result.error {
            println!("  Error: {}", error);
        }
    }

    let results = vec![result];
    write_escalation_results(crashpack_dir, &results)?;
    let _ = promote_tool_findings_to_crashpack(crashpack_dir, &results)?;
    println!("Escalation analysis completed.");
    Ok(())
}

fn write_escalation_results(crashpack_dir: &PathBuf, results: &[EscalationResult]) -> Result<()> {
    let results_path = crashpack_dir.join("escalations").join("results.json");
    if let Some(parent) = results_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&results_path, serde_json::to_vec_pretty(results)?)?;
    println!("Escalation results saved to: {}", results_path.display());
    Ok(())
}

fn promote_tool_findings_to_crashpack(
    crashpack_dir: &PathBuf,
    results: &[EscalationResult],
) -> Result<Option<CrashpackFindingSnapshot>> {
    let findings_path = crashpack_dir.join("findings.json");
    if !findings_path.exists() {
        return Ok(None);
    }

    let analysis = load_analysis_metadata(crashpack_dir)?;
    let mut findings = read_json_file(&findings_path)?
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON array", findings_path.display()))?;
    let mut known_classes = findings
        .iter()
        .filter_map(finding_class)
        .collect::<BTreeSet<_>>();

    let mut changed = enrich_gdb_crash_findings(&mut findings, results);
    for result in results.iter().filter(|result| {
        result.tool != "gdb"
            && result.success
            && result.confirmed
            && !result.findings_detected.is_empty()
    }) {
        for (index, detection) in tool_detections(result).into_iter().enumerate() {
            if known_classes.contains(&detection.class) {
                continue;
            }
            known_classes.insert(detection.class.clone());
            findings.push(tool_backed_finding(result, &detection, index, &analysis));
            changed = true;
        }
    }

    if !changed {
        return Ok(None);
    }

    fs::write(&findings_path, serde_json::to_vec_pretty(&findings)?)?;
    let (_, issue_group_count) =
        finalize_findings(crashpack_dir, Path::new(&analysis.binary_path))?;
    let refreshed = read_json_file(&findings_path)?
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON array", findings_path.display()))?;

    Ok(Some(CrashpackFindingSnapshot {
        count: refreshed.len() as u64,
        class_counts: class_counts_for_values(&refreshed),
        issue_group_count: issue_group_count as u64,
    }))
}

fn enrich_gdb_crash_findings(findings: &mut [Value], results: &[EscalationResult]) -> bool {
    let mut changed = false;
    for result in results
        .iter()
        .filter(|result| result.tool == "gdb" && result.success && result.confirmed)
    {
        let Some(report) = read_gdb_report(result) else {
            continue;
        };
        let crash_frames = report
            .get("crash_frames")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if crash_frames.is_empty() {
            continue;
        }

        for finding in findings.iter_mut().filter(|finding| {
            finding_class(finding).as_deref() == Some("unclassified_crash")
                && finding
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id == result.finding_id)
        }) {
            ensure_object_path(finding, &["evidence", "stacks"])
                .insert("crash".to_string(), Value::Array(crash_frames.clone()));
            ensure_object_path(finding, &["evidence", "tool"]).insert(
                "gdb".to_string(),
                json!({
                    "result_id": result.id,
                    "report_path": result.report_path,
                    "stdout_path": result.stdout_path,
                    "stderr_path": result.stderr_path,
                    "command": result.command,
                    "exit_code": result.exit_code,
                    "signal_name": report.get("signal_name").cloned().unwrap_or(Value::Null),
                    "signal_line": report.get("signal_line").cloned().unwrap_or(Value::Null),
                    "registers": report.get("registers").cloned().unwrap_or_else(|| json!([]))
                }),
            );
            let next_commands = finding
                .get_mut("next_commands")
                .and_then(Value::as_array_mut);
            if let Some(commands) = next_commands {
                if let Some(report_path) = &result.report_path {
                    let command = format!("cat {}", report_path);
                    if !commands
                        .iter()
                        .any(|value| value.as_str() == Some(&command))
                    {
                        commands.push(Value::String(command));
                    }
                }
            }
            changed = true;
        }
    }
    changed
}

fn read_gdb_report(result: &EscalationResult) -> Option<Value> {
    let report_path = result.report_path.as_deref()?;
    let content = fs::read_to_string(report_path).ok()?;
    serde_json::from_str(&content).ok()
}

fn ensure_object_path<'a>(
    value: &'a mut Value,
    path: &[&str],
) -> &'a mut serde_json::Map<String, Value> {
    let mut current = value;
    for key in path {
        if !current.is_object() {
            *current = json!({});
        }
        let object = current.as_object_mut().expect("object just initialized");
        current = object
            .entry((*key).to_string())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        *current = json!({});
    }
    current.as_object_mut().expect("object just initialized")
}

fn tool_detections(result: &EscalationResult) -> Vec<ToolDetection> {
    if let Some(report_path) = result.report_path.as_deref() {
        if let Ok(content) = fs::read_to_string(report_path) {
            if let Ok(report) = serde_json::from_str::<Value>(&content) {
                if let Some(detected) = report.get("detected").and_then(Value::as_array) {
                    let detections = detected
                        .iter()
                        .filter_map(|value| {
                            let mut detection = ToolDetection {
                                class: value.get("class")?.as_str()?.to_string(),
                                summary: value
                                    .get("summary")
                                    .and_then(Value::as_str)
                                    .unwrap_or("tool-backed finding")
                                    .to_string(),
                                line: value.get("line").and_then(Value::as_u64),
                                call_frame: None,
                                alloc_frame: None,
                                free_frame: None,
                            };
                            attach_tool_frames(result, &mut detection);
                            Some(detection)
                        })
                        .collect::<Vec<_>>();
                    if !detections.is_empty() {
                        return detections;
                    }
                }
            }
        }
    }

    result
        .findings_detected
        .iter()
        .map(|class| ToolDetection {
            class: class.clone(),
            summary: format!("{} detected {}", result.tool, class),
            line: None,
            call_frame: None,
            alloc_frame: None,
            free_frame: None,
        })
        .collect()
}

fn attach_tool_frames(result: &EscalationResult, detection: &mut ToolDetection) {
    let Some(output) = read_tool_output(result) else {
        return;
    };
    let lines = output.lines().collect::<Vec<_>>();
    let start = detection
        .line
        .and_then(|line| usize::try_from(line.saturating_sub(1)).ok())
        .unwrap_or(0)
        .min(lines.len().saturating_sub(1));
    let window_end = (start + 24).min(lines.len());
    let window = &lines[start..window_end];

    match result.tool.as_str() {
        "valgrind" => attach_valgrind_frames(window, detection),
        "asan" => attach_asan_frames(window, detection),
        "lsan" => attach_lsan_frames(window, detection),
        "ubsan" => attach_ubsan_frames(window, detection),
        _ => {}
    }
}

fn read_tool_output(result: &EscalationResult) -> Option<String> {
    let mut parts = Vec::new();
    for path in [result.stdout_path.as_deref(), result.stderr_path.as_deref()]
        .into_iter()
        .flatten()
    {
        if let Ok(content) = fs::read_to_string(path) {
            if !content.trim().is_empty() {
                parts.push(content);
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

fn attach_valgrind_frames(lines: &[&str], detection: &mut ToolDetection) {
    let source_frames = lines
        .iter()
        .filter_map(|line| stable_valgrind_frame(line))
        .collect::<Vec<_>>();
    if detection.call_frame.is_none() {
        detection.call_frame = source_frames.first().cloned();
    }

    let free_marker = lines
        .iter()
        .position(|line| line.contains("free'd") || line.contains("freed"));
    if let Some(marker) = free_marker {
        detection.free_frame = lines
            .iter()
            .skip(marker)
            .filter_map(|line| stable_valgrind_frame(line))
            .next();
    }

    let alloc_marker = lines
        .iter()
        .position(|line| line.contains("alloc'd") || line.contains("allocated"));
    if let Some(marker) = alloc_marker {
        detection.alloc_frame = lines
            .iter()
            .skip(marker)
            .filter_map(|line| stable_valgrind_frame(line))
            .next();
    }
}

fn attach_asan_frames(lines: &[&str], detection: &mut ToolDetection) {
    if detection.call_frame.is_none() {
        detection.call_frame = lines.iter().find_map(|line| {
            stable_asan_summary_frame(line).or_else(|| stable_asan_stack_frame(line))
        });
    }
    let free_marker = lines.iter().position(|line| {
        line.contains("freed by thread") || line.contains("previously allocated by thread")
    });
    if let Some(marker) = free_marker {
        detection.free_frame = lines
            .iter()
            .skip(marker)
            .find_map(|line| stable_asan_stack_frame(line));
    }
}

fn attach_lsan_frames(lines: &[&str], detection: &mut ToolDetection) {
    if detection.call_frame.is_none() {
        detection.call_frame = lines.iter().find_map(|line| {
            stable_asan_summary_frame(line).or_else(|| stable_asan_stack_frame(line))
        });
    }

    let alloc_marker = lines
        .iter()
        .position(|line| line.contains("allocated from:"));
    if let Some(marker) = alloc_marker {
        detection.alloc_frame = lines
            .iter()
            .skip(marker)
            .find_map(|line| stable_asan_stack_frame(line));
    }
}

fn attach_ubsan_frames(lines: &[&str], detection: &mut ToolDetection) {
    if detection.call_frame.is_none() {
        detection.call_frame = lines
            .iter()
            .find_map(|line| stable_ubsan_location(line).or_else(|| stable_asan_stack_frame(line)));
    }
}

fn stable_valgrind_frame(line: &str) -> Option<String> {
    let normalized = strip_valgrind_prefix(line).trim();
    let frame = normalized
        .strip_prefix("at ")
        .or_else(|| normalized.strip_prefix("by "))?
        .trim();
    if frame.contains("vg_replace_") || !frame.contains('(') || !frame.contains(')') {
        return None;
    }
    Some(frame.to_string())
}

fn strip_valgrind_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("==") {
        return trimmed;
    }
    let Some(rest) = trimmed.get(2..) else {
        return trimmed;
    };
    let Some(end) = rest.find("==") else {
        return trimmed;
    };
    &rest[end + 2..]
}

fn stable_asan_stack_frame(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with('#') {
        return None;
    }
    let in_split = trimmed.split_once(" in ").map(|(_, tail)| tail)?;
    let location = in_split
        .rsplit_once(' ')
        .map(|(_, tail)| tail)
        .unwrap_or(in_split)
        .trim();
    if location.contains(':') {
        Some(location.to_string())
    } else {
        None
    }
}

fn stable_asan_summary_frame(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.contains("SUMMARY: AddressSanitizer:")
        && !trimmed.contains("SUMMARY: LeakSanitizer:")
    {
        return None;
    }
    trimmed
        .split_whitespace()
        .find(|token| token.matches(':').count() >= 1 && token.chars().any(|ch| ch == '.'))
        .map(|token| {
            token
                .trim_matches(|ch: char| ch == ',' || ch == ';')
                .to_string()
        })
}

fn stable_ubsan_location(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.contains("runtime error:") {
        return None;
    }
    let location = trimmed.split_once(": runtime error:")?.0;
    if location.contains(':') {
        Some(location.to_string())
    } else {
        None
    }
}

fn tool_backed_finding(
    result: &EscalationResult,
    detection: &ToolDetection,
    index: usize,
    analysis: &NativeRunMetadata,
) -> Value {
    let summary = detection.summary.trim();
    json!({
        "schema_version": "1.0",
        "id": format!("F-{}-{}-{}-{}", result.tool, detection.class, result.id, index + 1),
        "origin": result.tool,
        "class": detection.class,
        "confidence": "tool_confirmed",
        "severity": severity_for_tool_class(&detection.class),
        "timestamp": result.timestamp,
        "pid": 0,
        "message": summary,
        "evidence": {
            "api": result.tool,
            "tool": {
                "name": result.tool,
                "result_id": result.id,
                "finding_id": result.finding_id,
                "summary": summary,
                "line": detection.line,
                "call_frame": detection.call_frame,
                "alloc_frame": detection.alloc_frame,
                "free_frame": detection.free_frame,
                "report_path": result.report_path,
                "stdout_path": result.stdout_path,
                "stderr_path": result.stderr_path,
                "command": result.command,
                "exit_code": result.exit_code
            },
            "stacks": {
                "alloc": detection.alloc_frame.iter().cloned().collect::<Vec<_>>(),
                "free": detection.free_frame.iter().cloned().collect::<Vec<_>>(),
                "call": detection.call_frame.iter().cloned().chain(std::iter::once(summary.to_string())).collect::<Vec<_>>()
            },
            "event_sequence": [{
                "source": "escalation",
                "tool": result.tool,
                "class": detection.class,
                "summary": summary
            }]
        },
        "provenance": {
            "original_binary_path": analysis.binary_path,
            "source_status": "unresolved"
        },
        "related": []
    })
}

fn severity_for_tool_class(class: &str) -> &'static str {
    match class {
        "use_after_free" | "double_free" => "critical",
        "heap_overflow" | "stack_overflow" | "global_overflow" | "invalid_free" => "error",
        "signed_integer_overflow"
        | "shift_out_of_bounds"
        | "null_pointer_use"
        | "misaligned_pointer"
        | "bounds"
        | "undefined_behavior" => "error",
        "memory_leak" | "fd_leak" => "warning",
        _ => "warning",
    }
}

fn finding_class(finding: &Value) -> Option<String> {
    finding
        .get("class")
        .or_else(|| finding.get("kind"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn class_counts_for_values(findings: &[Value]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        if let Some(class) = finding_class(finding) {
            *counts.entry(class).or_default() += 1;
        }
    }
    counts
}

fn write_observation_summary(output_root: &Path, summary: &ObservationRunSummary) -> Result<()> {
    fs::create_dir_all(output_root)?;
    let summary_path = output_root.join("run-summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(summary)?)?;
    Ok(())
}

fn had_observation_error(status: TargetStatus) -> bool {
    matches!(
        status,
        TargetStatus::Failed | TargetStatus::Timeout | TargetStatus::Skipped
    )
}

fn observation_diagnostics_from_native(
    diagnostics: Vec<NativeCapabilityDiagnostic>,
) -> Vec<ObservationDiagnostic> {
    diagnostics
        .into_iter()
        .map(|diagnostic| ObservationDiagnostic {
            component: diagnostic.component,
            status: diagnostic.status,
            detail: diagnostic.detail,
            remediation: diagnostic.remediation,
        })
        .collect()
}

fn native_error_allows_tool_only_fallback(error: &str) -> bool {
    let known_setup_failures = [
        "Native mode is only supported on Linux",
        "Native mode requires CAP_BPF",
        "without a shared host PID namespace",
        "Could not find re-mini agent",
        "Could not find heap_tracker.bpf.o",
        "Could not find copy_checker.bpf.o",
        "Could not detect libc path",
        "Failed to start agent",
        "Agent exited prematurely",
        "Failed to resume target",
        "Target exited before post-exec stop",
    ];
    known_setup_failures
        .iter()
        .any(|needle| error.contains(needle))
}

fn run_observe_tool_only_fallback(
    target: &mut ObservationTargetSummary,
    binary_path: &Path,
    target_dir: &Path,
    args: &[String],
    options: &NativeRunOptions,
    deep: bool,
    timeout_ms: Option<u64>,
) -> Result<()> {
    println!("Native tracing unavailable; attempting tool-only fallback...");
    prepare_tool_only_crashpack(binary_path, target_dir, args, options)?;
    target.error = Some(format!(
        "native tracing unavailable; used tool-only fallback: {}",
        target
            .error
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    ));
    target.timeout_ms = timeout_ms;
    target.replay_command = Some(format!(
        "rerun replay {} --format json",
        target_dir.display()
    ));
    target.summarize_command = Some(format!(
        "rerun summarize {} --format json",
        target_dir.display()
    ));
    target.next_commands = vec![
        format!("rerun summarize {} --format json", target_dir.display()),
        format!("rerun replay {} --format json", target_dir.display()),
        format!(
            "rerun escalate {} --tool valgrind --scan-binary",
            target_dir.display()
        ),
    ];

    let tools = if deep {
        vec!["valgrind", "asan", "lsan", "ubsan"]
    } else {
        vec!["valgrind"]
    };
    let results = run_observe_binary_scans(target_dir, &tools)?;
    if !results.is_empty() {
        write_escalation_results(&target_dir.to_path_buf(), &results)?;
        target.escalation = results.iter().map(observation_escalation_summary).collect();
        if let Some(snapshot) =
            promote_tool_findings_to_crashpack(&target_dir.to_path_buf(), &results)?
        {
            target.findings_count = snapshot.count;
            target.findings_by_class = snapshot.class_counts;
            target.issue_group_count = snapshot.issue_group_count;
        }
    }

    target.status = fallback_target_status(target, &results);
    Ok(())
}

fn run_observe_binary_scans(crashpack_dir: &Path, tools: &[&str]) -> Result<Vec<EscalationResult>> {
    let analysis = load_analysis_metadata(&crashpack_dir.to_path_buf())?;
    let mut config = EscalationConfig::default();
    config.output_dir = crashpack_dir.join("escalations").display().to_string();
    config.binary_path = Some(analysis.binary_path.clone());
    config.source_file = analysis.source_path.clone();
    config.cwd = analysis.cwd.clone();
    config.args = analysis.args.clone();

    let runtime = tokio::runtime::Runtime::new()?;
    let mut results = Vec::new();
    for tool in tools {
        let result = runtime.block_on(async {
            let mut runner = EscalationRunner::new(config.clone());
            runner
                .check_clean_binary(tool)
                .await
                .unwrap_or_else(|error| {
                    observe_escalation_failure("tool-only-fallback", tool, error.to_string())
                })
        });
        results.push(result);
    }
    Ok(results)
}

fn fallback_target_status(
    target: &ObservationTargetSummary,
    results: &[EscalationResult],
) -> TargetStatus {
    if target.findings_count > 0
        || results
            .iter()
            .any(|result| result.confirmed || !result.findings_detected.is_empty())
    {
        return TargetStatus::Findings;
    }
    if results
        .iter()
        .any(|result| escalation_status(result) == TargetStatus::Clean)
    {
        return TargetStatus::Clean;
    }
    if results
        .iter()
        .any(|result| escalation_status(result) == TargetStatus::ToolUnavailable)
    {
        return TargetStatus::ToolUnavailable;
    }
    if results
        .iter()
        .all(|result| escalation_status(result) == TargetStatus::NotApplicable)
    {
        return TargetStatus::NotApplicable;
    }
    TargetStatus::Failed
}

fn run_observe_escalation(
    target: &ObservationTargetSummary,
    deep: bool,
) -> Result<Vec<EscalationResult>> {
    if target.findings_count == 0 && !deep {
        return Ok(Vec::new());
    }

    let crashpack_dir = PathBuf::from(&target.artifacts.crashpack);
    let analysis = load_analysis_metadata(&crashpack_dir)?;
    let mut config = EscalationConfig::default();
    config.output_dir = crashpack_dir.join("escalations").display().to_string();
    config.binary_path = Some(analysis.binary_path.clone());
    config.source_file = analysis.source_path.clone();
    config.cwd = analysis.cwd.clone();
    config.args = analysis.args.clone();

    let runtime = tokio::runtime::Runtime::new()?;
    let mut results = Vec::new();

    if target.findings_count > 0 {
        let findings_path = crashpack_dir.join("findings.json");
        let findings = load_findings(&findings_path)?;
        let mut finding_results = runtime.block_on(async {
            let mut results = Vec::new();
            for mut finding in findings {
                let tool = observe_tool_for_finding(&finding);
                let mut plan = finding.escalation.unwrap_or(FindingEscalationPlan {
                    tool: tool.to_string(),
                    reason: "observe_confirm".to_string(),
                    estimated_cost: "medium".to_string(),
                    cooldown_ms: 0,
                });
                plan.tool = tool.to_string();
                finding.escalation = Some(plan);
                let mut runner = EscalationRunner::new(config.clone());
                let result = runner.escalate(&finding).await.unwrap_or_else(|error| {
                    observe_escalation_failure(&finding.id, tool, error.to_string())
                });
                results.push(result);
            }
            Ok::<Vec<EscalationResult>, anyhow::Error>(results)
        })?;
        results.append(&mut finding_results);
    } else if deep && !binary_has_sanitizer_runtime(&analysis.binary_path) {
        let valgrind_result = runtime.block_on(async {
            let mut runner = EscalationRunner::new(config.clone());
            runner
                .check_clean_binary("valgrind")
                .await
                .unwrap_or_else(|error| {
                    observe_escalation_failure("clean-run", "valgrind", error.to_string())
                })
        });
        results.push(valgrind_result);
    }

    if deep {
        let asan_result = runtime.block_on(async {
            let mut runner = EscalationRunner::new(config.clone());
            runner
                .check_clean_binary("asan")
                .await
                .unwrap_or_else(|error| {
                    observe_escalation_failure("clean-run", "asan", error.to_string())
                })
        });
        results.push(asan_result);

        let lsan_result = runtime.block_on(async {
            let mut runner = EscalationRunner::new(config.clone());
            runner
                .check_clean_binary("lsan")
                .await
                .unwrap_or_else(|error| {
                    observe_escalation_failure("clean-run", "lsan", error.to_string())
                })
        });
        results.push(lsan_result);

        let ubsan_result = runtime.block_on(async {
            let mut runner = EscalationRunner::new(config);
            runner
                .check_clean_binary("ubsan")
                .await
                .unwrap_or_else(|error| {
                    observe_escalation_failure("clean-run", "ubsan", error.to_string())
                })
        });
        results.push(ubsan_result);
    }

    Ok(results)
}

fn observe_tool_for_finding(finding: &Finding) -> &'static str {
    if finding.class == "unclassified_crash" {
        "gdb"
    } else {
        "valgrind"
    }
}

fn binary_has_sanitizer_runtime(binary_path: &str) -> bool {
    let Ok(bytes) = fs::read(binary_path) else {
        return false;
    };
    let haystack = String::from_utf8_lossy(&bytes);
    haystack.contains("__asan_")
        || haystack.contains("libasan")
        || haystack.contains("AddressSanitizer")
        || haystack.contains("__lsan_")
        || haystack.contains("liblsan")
        || haystack.contains("LeakSanitizer")
        || haystack.contains("__ubsan_")
        || haystack.contains("libubsan")
        || haystack.contains("UndefinedBehaviorSanitizer")
}

fn observe_escalation_failure(finding_id: &str, tool: &str, error: String) -> EscalationResult {
    EscalationResult {
        id: format!("observe-{}-failed", tool),
        finding_id: finding_id.to_string(),
        tool: tool.to_string(),
        success: false,
        tool_available: true,
        duration_ms: 0,
        output_path: None,
        stdout_path: None,
        stderr_path: None,
        report_path: None,
        command: Vec::new(),
        exit_code: None,
        confirmed: false,
        error: Some(error),
        findings_detected: Vec::new(),
        timestamp: current_unix_timestamp(),
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn observation_escalation_summary(
    result: &EscalationResult,
) -> crate::observation::ObservationEscalationSummary {
    crate::observation::ObservationEscalationSummary {
        tool: result.tool.clone(),
        status: escalation_status(result),
        confirmed: result.confirmed,
        findings_detected: result.findings_detected.clone(),
        artifact_path: result
            .report_path
            .clone()
            .or_else(|| result.output_path.clone()),
        error: result.error.clone(),
    }
}

fn escalation_status(result: &EscalationResult) -> TargetStatus {
    if (result.tool == "asan" || result.tool == "lsan" || result.tool == "ubsan")
        && !result.success
        && result
            .error
            .as_deref()
            .map(|error| error.contains("-fsanitize="))
            .unwrap_or(false)
    {
        return TargetStatus::NotApplicable;
    }
    if !result.tool_available {
        return TargetStatus::ToolUnavailable;
    }
    if !result.success {
        return TargetStatus::Failed;
    }
    if result.confirmed {
        TargetStatus::Findings
    } else {
        TargetStatus::Clean
    }
}

fn observation_target_from_native_result(
    target_name: &str,
    timeout_ms: Option<u64>,
    result: NativeRunResult,
) -> ObservationTargetSummary {
    let target_dir = result.output_dir.clone();
    let status = if result.timed_out {
        TargetStatus::Timeout
    } else if result.findings_count > 0 {
        TargetStatus::Findings
    } else {
        TargetStatus::Clean
    };
    let mut target = ObservationTargetSummary::new(
        target_name,
        result.binary_path.display().to_string(),
        result.args,
        result
            .cwd
            .as_ref()
            .map(|cwd| cwd.display().to_string())
            .unwrap_or_else(|| ".".to_string()),
        status,
        TargetExitSummary {
            code: result.exit_code,
            signal: result.signal,
            crashed: result.crashed,
        },
        ObservationArtifacts::target_defaults(target_dir.display().to_string()),
    );
    target.duration_ms = Some(u128_to_u64(result.duration_ms));
    target.timeout_ms = timeout_ms;
    target.findings_count = result.findings_count as u64;
    target.findings_by_class = result.findings_by_class;
    target.issue_group_count = result.issue_group_count as u64;
    target.replay_command = Some(format!(
        "rerun replay {} --format json",
        target_dir.display()
    ));
    target.summarize_command = Some(format!(
        "rerun summarize {} --format json",
        target_dir.display()
    ));
    target.next_commands = vec![
        format!("rerun summarize {} --format json", target_dir.display()),
        format!("rerun replay {} --format json", target_dir.display()),
    ];
    if result.timed_out {
        target.error = Some("target timed out".to_string());
    }
    target
}

#[allow(clippy::too_many_arguments)]
fn observation_target_from_error(
    target_name: &str,
    binary_path: &Path,
    args: &[String],
    cwd: Option<&Path>,
    output_root: &Path,
    timeout_ms: Option<u64>,
    error: String,
    duration_ms: u128,
) -> ObservationTargetSummary {
    let target_dir = output_root.join("targets").join(target_name);
    let mut target = ObservationTargetSummary::new(
        target_name,
        binary_path.display().to_string(),
        args.to_vec(),
        cwd.map(|cwd| cwd.display().to_string())
            .unwrap_or_else(|| ".".to_string()),
        TargetStatus::Failed,
        TargetExitSummary::not_run(),
        ObservationArtifacts::target_defaults(target_dir.display().to_string()),
    );
    target.error = Some(error);
    target.duration_ms = Some(u128_to_u64(duration_ms));
    target.timeout_ms = timeout_ms;
    target.next_commands = vec![format!(
        "jq . {}",
        output_root.join("run-summary.json").display()
    )];
    target
}

fn observation_target_name(binary_path: &Path) -> String {
    let raw = binary_path
        .file_stem()
        .or_else(|| binary_path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("target");
    let sanitized = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "target".to_string()
    } else {
        sanitized
    }
}

fn u128_to_u64(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}

/// Handle the 'crashpack' command
pub fn handle_crashpack_command(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("open", sub_matches)) => {
            let path = sub_matches.get_one::<String>("path").unwrap();
            open_crashpack(path)?;
        }
        Some(("validate", sub_matches)) => {
            let path = sub_matches.get_one::<String>("path").unwrap();
            validate_crashpack(path)?;
        }
        _ => {
            eprintln!("Use 're crashpack open <path>' or 're crashpack validate <path>'");
        }
    }
    Ok(())
}

/// Handle the 'summarize' command
pub fn handle_summarize_command(matches: &ArgMatches) -> Result<()> {
    let crashpack_path = PathBuf::from(matches.get_one::<String>("crashpack").unwrap());
    let format = matches.get_one::<String>("format").unwrap();
    if format != "json" {
        return Err(anyhow::anyhow!("unsupported summarize format: {}", format));
    }

    let summary = summarize_crashpack(&crashpack_path)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

/// Handle the 'replay' command
pub fn handle_replay_command(matches: &ArgMatches) -> Result<()> {
    let crashpack_path = PathBuf::from(matches.get_one::<String>("crashpack").unwrap());
    let format = matches.get_one::<String>("format").unwrap();
    if format != "json" {
        return Err(anyhow::anyhow!("unsupported replay format: {}", format));
    }

    let result = replay_crashpack(&crashpack_path)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn replay_crashpack(crashpack_path: &PathBuf) -> Result<ReplayResult> {
    if !crashpack_path.exists() {
        return Err(anyhow::anyhow!(
            "Crashpack not found: {}",
            crashpack_path.display()
        ));
    }

    let analysis = load_analysis_metadata(crashpack_path)?;
    let binary_path = select_replay_binary(crashpack_path, &analysis.binary_path);
    let executable_path = fs::canonicalize(&binary_path).unwrap_or_else(|_| binary_path.clone());
    let started = Instant::now();
    let mut command = Command::new(&executable_path);
    command.args(&analysis.args);
    if let Some(cwd) = analysis.cwd.as_deref() {
        command.current_dir(cwd);
    }
    let output = command.output();
    let duration_ms = started.elapsed().as_millis();

    let result = match output {
        Ok(output) => ReplayResult {
            schema_version: "1.0".to_string(),
            crashpack: crashpack_path.display().to_string(),
            binary_path: executable_path.display().to_string(),
            args: analysis.args,
            ran: true,
            exit_success: output.status.success(),
            exit_code: output.status.code(),
            duration_ms,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            error: None,
        },
        Err(error) => ReplayResult {
            schema_version: "1.0".to_string(),
            crashpack: crashpack_path.display().to_string(),
            binary_path: executable_path.display().to_string(),
            args: analysis.args,
            ran: false,
            exit_success: false,
            exit_code: None,
            duration_ms,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(error.to_string()),
        },
    };

    write_replay_result(crashpack_path, &result)?;
    Ok(result)
}

fn select_replay_binary(crashpack_path: &Path, analysis_binary_path: &str) -> PathBuf {
    if let Some(file_name) = Path::new(analysis_binary_path).file_name() {
        let captured = crashpack_path.join("bins").join(file_name);
        if captured.exists() {
            return captured;
        }
    }

    let evidence_pack_path = crashpack_path.join("evidence-pack.json");
    if let Ok(evidence_pack) = read_json_file(&evidence_pack_path) {
        if let Some(captured_path) = evidence_pack
            .pointer("/binary/captured_path")
            .and_then(Value::as_str)
        {
            let captured = PathBuf::from(captured_path);
            if captured.exists() {
                return captured;
            }
        }
    }

    PathBuf::from(analysis_binary_path)
}

fn write_replay_result(crashpack_path: &PathBuf, result: &ReplayResult) -> Result<()> {
    let replay_dir = crashpack_path.join("replay");
    fs::create_dir_all(&replay_dir)?;
    let results_path = replay_dir.join("results.json");
    fs::write(&results_path, serde_json::to_vec_pretty(result)?)?;
    Ok(())
}

fn summarize_crashpack(crashpack_path: &PathBuf) -> Result<Value> {
    let evidence_pack_path = crashpack_path.join("evidence-pack.json");
    let evidence_pack = read_json_file(&evidence_pack_path)?;
    let escalation_results_path = crashpack_path.join("escalations").join("results.json");
    let escalation_results = if escalation_results_path.exists() {
        read_json_file(&escalation_results_path)?
            .as_array()
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} must contain a JSON array",
                    escalation_results_path.display()
                )
            })?
    } else {
        Vec::new()
    };

    Ok(build_agent_summary(
        crashpack_path,
        &evidence_pack,
        &escalation_results,
    ))
}

fn read_json_file(path: &PathBuf) -> Result<Value> {
    let content = fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("Failed to read {}: {}", path.display(), error))?;
    serde_json::from_str::<Value>(&content)
        .map_err(|error| anyhow::anyhow!("Failed to parse {}: {}", path.display(), error))
}

fn build_agent_summary(
    crashpack_path: &PathBuf,
    evidence_pack: &Value,
    escalation_results: &[Value],
) -> Value {
    let findings = evidence_pack
        .get("findings")
        .and_then(Value::as_array)
        .map(|findings| {
            findings
                .iter()
                .map(|finding| compact_agent_finding(finding, escalation_results))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let escalation_summary = summarize_escalation_results(crashpack_path, escalation_results);

    json!({
        "schema_version": "1.0",
        "purpose": "agent_summary",
        "crashpack": crashpack_path.display().to_string(),
        "artifacts": evidence_pack.get("artifacts").cloned().unwrap_or_else(|| json!({})),
        "binary": evidence_pack.get("binary").cloned().unwrap_or_else(|| json!({})),
        "summary": {
            "total_findings": evidence_pack.pointer("/summary/total_findings").cloned().unwrap_or(Value::Null),
            "class_counts": evidence_pack.pointer("/summary/class_counts").cloned().unwrap_or_else(|| json!({})),
            "source_resolved": evidence_pack.pointer("/summary/source_resolved").cloned().unwrap_or(Value::Null),
            "source_unresolved": evidence_pack.pointer("/summary/source_unresolved").cloned().unwrap_or(Value::Null),
            "issue_group_count": evidence_pack.pointer("/summary/issue_group_count").cloned().unwrap_or(Value::Null),
            "escalation_total_runs": escalation_summary.pointer("/total_runs").cloned().unwrap_or(Value::Null),
            "escalation_confirmed_runs": escalation_summary.pointer("/confirmed_runs").cloned().unwrap_or(Value::Null),
            "escalation_detected_classes": escalation_summary.pointer("/detected_classes").cloned().unwrap_or_else(|| json!([])),
        },
        "issue_groups": evidence_pack.get("issue_groups").cloned().unwrap_or_else(|| json!([])),
        "findings": findings,
        "escalation": escalation_summary,
    })
}

fn compact_agent_finding(finding: &Value, escalation_results: &[Value]) -> Value {
    let finding_id = finding.get("id").and_then(Value::as_str);
    let linked_escalation = finding_id
        .and_then(|id| {
            escalation_results.iter().find(|result| {
                result
                    .get("finding_id")
                    .and_then(Value::as_str)
                    .map(|value| value == id)
                    .unwrap_or(false)
            })
        })
        .map(compact_escalation_result)
        .unwrap_or(Value::Null);

    json!({
        "id": finding.get("id").cloned().unwrap_or(Value::Null),
        "origin": finding.get("origin").cloned().unwrap_or(Value::Null),
        "fingerprint": finding.get("fingerprint").cloned().unwrap_or(Value::Null),
        "issue_group_id": finding.get("issue_group_id").cloned().unwrap_or(Value::Null),
        "class": finding.get("class").cloned().unwrap_or(Value::Null),
        "severity": finding.get("severity").cloned().unwrap_or(Value::Null),
        "confidence": finding.get("confidence").cloned().unwrap_or(Value::Null),
        "source": finding.get("source").cloned().unwrap_or(Value::Null),
        "operation": finding.get("operation").cloned().unwrap_or(Value::Null),
        "memory": finding.get("memory").cloned().unwrap_or(Value::Null),
        "crash": finding.get("crash").cloned().unwrap_or(Value::Null),
        "stacks": finding.get("stacks").cloned().unwrap_or(Value::Null),
        "alloc_site": finding.get("alloc_site").cloned().unwrap_or(Value::Null),
        "tool": finding.get("tool").cloned().unwrap_or(Value::Null),
        "escalation_plan": finding.get("escalation_plan").cloned().unwrap_or(Value::Null),
        "escalation_result": linked_escalation,
    })
}

fn summarize_escalation_results(crashpack_path: &PathBuf, results: &[Value]) -> Value {
    let mut tools = BTreeSet::<String>::new();
    let mut detected_classes = BTreeSet::<String>::new();
    let mut by_finding = BTreeMap::<String, Value>::new();
    let mut confirmed_runs = 0usize;
    let compact_results = results
        .iter()
        .map(|result| {
            if let Some(tool) = result.get("tool").and_then(Value::as_str) {
                tools.insert(tool.to_string());
            }
            if result
                .get("confirmed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                confirmed_runs += 1;
            }
            if let Some(classes) = result.get("findings_detected").and_then(Value::as_array) {
                for class in classes.iter().filter_map(Value::as_str) {
                    detected_classes.insert(class.to_string());
                }
            }

            let compact = compact_escalation_result(result);
            if let Some(finding_id) = result.get("finding_id").and_then(Value::as_str) {
                by_finding.insert(finding_id.to_string(), compact.clone());
            }
            compact
        })
        .collect::<Vec<_>>();

    json!({
        "results_path": crashpack_path.join("escalations").join("results.json").display().to_string(),
        "total_runs": results.len(),
        "confirmed_runs": confirmed_runs,
        "tools": tools.into_iter().collect::<Vec<_>>(),
        "detected_classes": detected_classes.into_iter().collect::<Vec<_>>(),
        "by_finding_id": by_finding,
        "results": compact_results,
    })
}

fn compact_escalation_result(result: &Value) -> Value {
    json!({
        "id": result.get("id").cloned().unwrap_or(Value::Null),
        "finding_id": result.get("finding_id").cloned().unwrap_or(Value::Null),
        "tool": result.get("tool").cloned().unwrap_or(Value::Null),
        "success": result.get("success").cloned().unwrap_or(Value::Null),
        "confirmed": result.get("confirmed").cloned().unwrap_or(Value::Null),
        "findings_detected": result.get("findings_detected").cloned().unwrap_or_else(|| json!([])),
        "output_path": result.get("output_path").cloned().unwrap_or(Value::Null),
        "report_path": result.get("report_path").cloned().unwrap_or(Value::Null),
        "error": result.get("error").cloned().unwrap_or(Value::Null),
    })
}

fn load_findings(path: &PathBuf) -> Result<Vec<Finding>> {
    let content = fs::read_to_string(path)?;
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(serde_json::Value::Array(_)) => serde_json::from_str::<Vec<Finding>>(&content)
            .map_err(|error| anyhow::anyhow!("Failed to parse {}: {}", path.display(), error)),
        Ok(_) => Err(anyhow::anyhow!(
            "{} must contain a JSON array of findings",
            path.display()
        )),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to parse {}: {}",
            path.display(),
            error
        )),
    }
}

fn load_analysis_metadata(crashpack_dir: &PathBuf) -> Result<NativeRunMetadata> {
    let path = crashpack_dir.join("analysis.json");
    let content = fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("Failed to read {}: {}", path.display(), error))?;
    serde_json::from_str::<NativeRunMetadata>(&content)
        .map_err(|error| anyhow::anyhow!("Failed to parse {}: {}", path.display(), error))
}

/// Open and display crashpack summary
fn open_crashpack(path: &str) -> Result<()> {
    let crashpack_path = PathBuf::from(path);

    if !crashpack_path.exists() {
        return Err(anyhow::anyhow!("Crashpack not found: {}", path));
    }

    println!("Crashpack: {}", crashpack_path.display());

    // Check for manifest
    let manifest_path = crashpack_path.join("manifest.json");
    if manifest_path.exists() {
        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;
        println!("Manifest:");
        println!(
            "  Schema:   {}",
            manifest
                .get("schema_version")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        );
        println!(
            "  Findings: {}",
            manifest
                .get("total_findings")
                .and_then(|value| value.as_u64())
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "  Created:  {}",
            manifest
                .get("created_by")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        );
    }

    // Check for findings
    let findings_path = crashpack_path.join("findings.json");
    if findings_path.exists() {
        println!("\nFindings:");
        let findings = read_findings(&findings_path)?;
        print_findings_summary(&findings);
    }

    Ok(())
}

/// Validate crashpack structure and contents
fn validate_crashpack(path: &str) -> Result<()> {
    let crashpack_path = PathBuf::from(path);

    if !crashpack_path.exists() {
        return Err(anyhow::anyhow!("Crashpack not found: {}", path));
    }

    println!("Validating crashpack: {}", crashpack_path.display());

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check required files
    let required_files = ["manifest.json", "findings.json", "console.log"];
    for file in &required_files {
        let file_path = crashpack_path.join(file);
        if !file_path.exists() {
            errors.push(format!("Missing required file: {}", file));
        }
    }

    // Check manifest structure
    let manifest_path = crashpack_path.join("manifest.json");
    if manifest_path.exists() {
        match fs::read_to_string(&manifest_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(manifest) => {
                    if let Some(tool_version) = manifest
                        .get("recc_version")
                        .or_else(|| manifest.get("tool_version"))
                    {
                        println!("Tool version: {}", tool_version);
                    } else {
                        warnings.push("Manifest missing tool_version or legacy recc_version");
                    }

                    if let Some(schema_version) = manifest.get("schema_version") {
                        println!("Schema version: {}", schema_version);
                    } else {
                        warnings.push("Manifest missing schema_version");
                    }
                }
                Err(e) => {
                    errors.push(format!("Invalid manifest.json: {}", e));
                }
            },
            Err(e) => {
                errors.push(format!("Cannot read manifest.json: {}", e));
            }
        }
    }

    // Check findings structure
    let findings_path = crashpack_path.join("findings.json");
    if findings_path.exists() {
        match fs::read_to_string(&findings_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(findings) => {
                    if findings.is_array() {
                        println!("Findings: {} entries", findings.as_array().unwrap().len());
                    } else {
                        errors.push("findings.json must be a JSON array".to_string());
                    }
                }
                Err(e) => {
                    errors.push(format!("Invalid findings.json: {}", e));
                }
            },
            Err(e) => {
                errors.push(format!("Cannot read findings.json: {}", e));
            }
        }
    }

    // Report results
    if errors.is_empty() && warnings.is_empty() {
        println!("✅ Crashpack validation passed");
    } else {
        if !errors.is_empty() {
            println!("❌ Validation errors:");
            for error in errors {
                println!("  {}", error);
            }
        }

        if !warnings.is_empty() {
            println!("⚠️  Validation warnings:");
            for warning in warnings {
                println!("  {}", warning);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn agent_summary_handles_finding_crashpack() {
        let pack = json!({
            "artifacts": {
                "findings": "/tmp/crash/findings.json"
            },
            "binary": {
                "original_path": "/tmp/project/build/app",
                "captured_path": "/tmp/crash/bins/app"
            },
            "summary": {
                "total_findings": 1,
                "class_counts": {
                    "heap_overflow": 1
                },
                "source_resolved": 1,
                "source_unresolved": 0
            },
            "findings": [{
                "id": "F-1",
                "class": "heap_overflow",
                "severity": "error",
                "confidence": "high",
                "source": {
                    "status": "resolved",
                    "path": "/tmp/project/src/app.c"
                },
                "operation": "memcpy",
                "memory": {
                    "size": 64,
                    "alloc_size": 16
                },
                "stacks": {
                    "call": ["copy (/tmp/project/src/app.c:12)"]
                },
                "escalation_plan": {
                    "tool": "valgrind"
                }
            }]
        });

        let summary = build_agent_summary(&PathBuf::from("/tmp/crash"), &pack, &[]);

        assert_eq!(
            summary.pointer("/purpose").and_then(Value::as_str),
            Some("agent_summary")
        );
        assert_eq!(
            summary
                .pointer("/summary/class_counts/heap_overflow")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            summary
                .pointer("/findings/0/operation")
                .and_then(Value::as_str),
            Some("memcpy")
        );
        assert!(summary.pointer("/findings/0/raw_finding").is_none());
        assert_eq!(
            summary.pointer("/findings/0/escalation_result"),
            Some(&Value::Null)
        );
    }

    #[test]
    fn agent_summary_handles_no_finding_crashpack() {
        let pack = json!({
            "summary": {
                "total_findings": 0,
                "class_counts": {},
                "source_resolved": 0,
                "source_unresolved": 0
            },
            "findings": []
        });

        let summary = build_agent_summary(&PathBuf::from("/tmp/clean"), &pack, &[]);

        assert_eq!(
            summary
                .pointer("/summary/total_findings")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            summary
                .pointer("/findings")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn agent_summary_preserves_crash_evidence() {
        let pack = json!({
            "summary": {
                "total_findings": 1,
                "class_counts": {"unclassified_crash": 1},
                "source_resolved": 0,
                "source_unresolved": 1
            },
            "findings": [{
                "id": "F-crash-1",
                "origin": "runtime",
                "class": "unclassified_crash",
                "severity": "error",
                "confidence": "observed",
                "source": {"status": "unresolved", "path": null},
                "operation": "crash_observed",
                "crash": {
                    "signal": 11,
                    "signal_name": "SIGSEGV",
                    "stdout_path": "/tmp/crash/logs/target.stdout.log",
                    "stderr_path": "/tmp/crash/logs/target.stderr.log"
                },
                "stacks": {"crash": []}
            }]
        });

        let summary = build_agent_summary(&PathBuf::from("/tmp/crash"), &pack, &[]);

        assert_eq!(
            summary
                .pointer("/findings/0/crash/signal_name")
                .and_then(Value::as_str),
            Some("SIGSEGV")
        );
        assert_eq!(
            summary
                .pointer("/findings/0/operation")
                .and_then(Value::as_str),
            Some("crash_observed")
        );
    }

    #[test]
    fn agent_summary_includes_escalation_results() {
        let pack = json!({
            "summary": {
                "total_findings": 1,
                "class_counts": {
                    "use_after_free": 1
                },
                "source_resolved": 0,
                "source_unresolved": 1
            },
            "findings": []
        });
        let escalation_results = vec![json!({
            "id": "E-1",
            "finding_id": "F-1",
            "tool": "valgrind",
            "success": true,
            "confirmed": true,
            "findings_detected": ["use_after_free"],
            "output_path": "/tmp/crash/escalations/valgrind/report.json"
        })];

        let summary = build_agent_summary(&PathBuf::from("/tmp/crash"), &pack, &escalation_results);

        assert_eq!(
            summary
                .pointer("/summary/escalation_total_runs")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            summary
                .pointer("/summary/escalation_detected_classes/0")
                .and_then(Value::as_str),
            Some("use_after_free")
        );
        assert_eq!(
            summary
                .pointer("/escalation/results/0/tool")
                .and_then(Value::as_str),
            Some("valgrind")
        );
        assert_eq!(
            summary
                .pointer("/escalation/by_finding_id/F-1/confirmed")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn agent_summary_links_escalation_result_to_finding() {
        let pack = json!({
            "summary": {
                "total_findings": 1,
                "class_counts": {
                    "heap_overflow": 1
                },
                "source_resolved": 1,
                "source_unresolved": 0
            },
            "findings": [{
                "id": "F-heap-overflow-1",
                "class": "heap_overflow",
                "severity": "error",
                "confidence": "high",
                "source": {
                    "status": "resolved",
                    "path": "/tmp/project/src/app.c"
                },
                "operation": "memcpy"
            }]
        });
        let escalation_results = vec![json!({
            "id": "E-1",
            "finding_id": "F-heap-overflow-1",
            "tool": "valgrind",
            "success": true,
            "confirmed": true,
            "findings_detected": ["heap_overflow"],
            "output_path": "/tmp/crash/escalations/valgrind/report.json"
        })];

        let summary = build_agent_summary(&PathBuf::from("/tmp/crash"), &pack, &escalation_results);

        assert_eq!(
            summary
                .pointer("/findings/0/escalation_result/finding_id")
                .and_then(Value::as_str),
            Some("F-heap-overflow-1")
        );
        assert_eq!(
            summary
                .pointer("/findings/0/escalation_result/confirmed")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn tool_escalation_promotion_writes_first_class_finding_artifacts() {
        let base =
            std::env::temp_dir().join(format!("rerun-tool-finding-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("escalations").join("valgrind")).unwrap();

        let binary = base.join("app");
        fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = fs::metadata(&binary).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary, perms).unwrap();

        fs::write(base.join("findings.json"), "[]").unwrap();
        fs::write(
            base.join("analysis.json"),
            serde_json::to_vec_pretty(&json!({
                "binary_path": binary.display().to_string(),
                "args": []
            }))
            .unwrap(),
        )
        .unwrap();

        let report_path = base
            .join("escalations")
            .join("valgrind")
            .join("report.json");
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&json!({
                "tool": "valgrind",
                "detected": [{
                    "class": "use_after_free",
                    "summary": "Invalid read of size 1",
                    "line": 1
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let result = EscalationResult {
            id: "E-tool".to_string(),
            finding_id: "clean-run".to_string(),
            tool: "valgrind".to_string(),
            success: true,
            tool_available: true,
            duration_ms: 10,
            output_path: Some(report_path.display().to_string()),
            stdout_path: None,
            stderr_path: None,
            report_path: Some(report_path.display().to_string()),
            command: vec!["valgrind".to_string(), binary.display().to_string()],
            exit_code: Some(99),
            confirmed: true,
            error: None,
            findings_detected: vec!["use_after_free".to_string()],
            timestamp: 123,
        };

        let snapshot = promote_tool_findings_to_crashpack(&base, &[result])
            .unwrap()
            .expect("expected promoted finding");
        assert_eq!(snapshot.count, 1);
        assert_eq!(snapshot.class_counts.get("use_after_free"), Some(&1));
        assert_eq!(snapshot.issue_group_count, 1);

        let findings = read_json_file(&base.join("findings.json")).unwrap();
        assert_eq!(
            findings.pointer("/0/origin").and_then(Value::as_str),
            Some("valgrind")
        );
        assert_eq!(
            findings.pointer("/0/class").and_then(Value::as_str),
            Some("use_after_free")
        );
        assert_eq!(
            findings
                .pointer("/0/fingerprint")
                .and_then(Value::as_str)
                .is_some(),
            true
        );

        let evidence_pack = read_json_file(&base.join("evidence-pack.json")).unwrap();
        assert_eq!(
            evidence_pack
                .pointer("/summary/total_findings")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            evidence_pack
                .pointer("/findings/0/origin")
                .and_then(Value::as_str),
            Some("valgrind")
        );
        assert_eq!(
            evidence_pack
                .pointer("/summary/issue_group_count")
                .and_then(Value::as_u64),
            Some(1)
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn gdb_escalation_enriches_existing_crash_finding() {
        let base = std::env::temp_dir().join(format!(
            "rerun-gdb-crash-enrich-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("escalations").join("gdb")).unwrap();

        let binary = base.join("crash-app");
        fs::write(&binary, "#!/bin/sh\nexit 139\n").unwrap();
        let mut perms = fs::metadata(&binary).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary, perms).unwrap();

        fs::write(
            base.join("analysis.json"),
            serde_json::to_vec_pretty(&json!({
                "binary_path": binary.display().to_string(),
                "args": []
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            base.join("findings.json"),
            serde_json::to_vec_pretty(&json!([{
                "schema_version": "1.0",
                "id": "F-crash-1",
                "origin": "runtime",
                "class": "unclassified_crash",
                "severity": "error",
                "confidence": "observed",
                "timestamp": 1,
                "pid": 0,
                "evidence": {
                    "api": "crash_observed",
                    "crash": {"signal": 11, "signal_name": "SIGSEGV"},
                    "stacks": {"crash": []}
                },
                "provenance": {
                    "binary_path": binary.display().to_string(),
                    "source_status": "unresolved"
                },
                "next_commands": []
            }]))
            .unwrap(),
        )
        .unwrap();

        let report_path = base.join("escalations").join("gdb").join("report.json");
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&json!({
                "tool": "gdb",
                "confirmed": true,
                "signal_name": "SIGSEGV",
                "signal_line": "Program received signal SIGSEGV, Segmentation fault.",
                "crash_frames": [
                    "#0  crash_here () at crash_segv_case.c:5",
                    "#1  main () at crash_segv_case.c:11"
                ],
                "registers": ["rip 0x401142"],
                "detected": [{
                    "class": "unclassified_crash",
                    "summary": "Program received signal SIGSEGV, Segmentation fault.",
                    "line": 1
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let result = EscalationResult {
            id: "E-gdb".to_string(),
            finding_id: "F-crash-1".to_string(),
            tool: "gdb".to_string(),
            success: true,
            tool_available: true,
            duration_ms: 10,
            output_path: Some(report_path.display().to_string()),
            stdout_path: Some(
                base.join("escalations/gdb/stdout.log")
                    .display()
                    .to_string(),
            ),
            stderr_path: Some(
                base.join("escalations/gdb/stderr.log")
                    .display()
                    .to_string(),
            ),
            report_path: Some(report_path.display().to_string()),
            command: vec![
                "gdb".to_string(),
                "-batch".to_string(),
                "--args".to_string(),
                binary.display().to_string(),
            ],
            exit_code: Some(0),
            confirmed: true,
            error: None,
            findings_detected: vec!["unclassified_crash".to_string()],
            timestamp: 123,
        };

        let snapshot = promote_tool_findings_to_crashpack(&base, &[result])
            .unwrap()
            .expect("expected enriched crash finding");
        assert_eq!(snapshot.count, 1);
        assert_eq!(snapshot.class_counts.get("unclassified_crash"), Some(&1));

        let findings = read_json_file(&base.join("findings.json")).unwrap();
        assert_eq!(
            findings
                .pointer("/0/evidence/stacks/crash/0")
                .and_then(Value::as_str),
            Some("#0  crash_here () at crash_segv_case.c:5")
        );
        assert_eq!(
            findings
                .pointer("/0/evidence/tool/gdb/signal_name")
                .and_then(Value::as_str),
            Some("SIGSEGV")
        );

        let evidence_pack = read_json_file(&base.join("evidence-pack.json")).unwrap();
        assert_eq!(
            evidence_pack
                .pointer("/findings/0/stacks/crash/0")
                .and_then(Value::as_str),
            Some("#0  crash_here () at crash_segv_case.c:5")
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn replay_prefers_captured_binary_and_writes_result() {
        let base = std::env::temp_dir().join(format!("rerun-replay-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("bins")).unwrap();

        let original = base.join("missing-original");
        let captured = base.join("bins").join("missing-original");
        fs::write(&captured, "#!/bin/sh\necho replayed:$1\n").unwrap();
        let mut perms = fs::metadata(&captured).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&captured, perms).unwrap();

        fs::write(
            base.join("analysis.json"),
            serde_json::to_vec_pretty(&json!({
                "binary_path": original.display().to_string(),
                "args": ["arg1"]
            }))
            .unwrap(),
        )
        .unwrap();

        let result = replay_crashpack(&base).unwrap();

        assert!(result.ran);
        assert!(result.exit_success);
        assert_eq!(result.stdout.trim(), "replayed:arg1");
        assert_eq!(
            PathBuf::from(&result.binary_path),
            fs::canonicalize(&captured).unwrap()
        );
        assert!(base.join("replay").join("results.json").exists());

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn replay_uses_recorded_cwd() {
        let base =
            std::env::temp_dir().join(format!("rerun-replay-cwd-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("bins")).unwrap();
        fs::create_dir_all(base.join("work")).unwrap();
        fs::write(base.join("work").join("payload.txt"), "from-cwd\n").unwrap();

        let captured = base.join("bins").join("cwd-reader");
        fs::write(&captured, "#!/bin/sh\ncat payload.txt\n").unwrap();
        let mut perms = fs::metadata(&captured).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&captured, perms).unwrap();

        fs::write(
            base.join("analysis.json"),
            serde_json::to_vec_pretty(&json!({
                "binary_path": captured.display().to_string(),
                "cwd": base.join("work").display().to_string(),
                "args": []
            }))
            .unwrap(),
        )
        .unwrap();

        let result = replay_crashpack(&base).unwrap();

        assert!(result.ran);
        assert!(result.exit_success);
        assert_eq!(result.stdout.trim(), "from-cwd");

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn observation_target_names_are_filesystem_safe() {
        assert_eq!(
            observation_target_name(Path::new("build/my app/test.bin")),
            "test"
        );
        assert_eq!(
            observation_target_name(Path::new("build/weird target")),
            "weird_target"
        );
        assert_eq!(observation_target_name(Path::new("")), "target");
    }

    #[test]
    fn observation_error_target_preserves_failure_reason() {
        let output_root = PathBuf::from(".re");
        let target = observation_target_from_error(
            "app",
            Path::new("build/app"),
            &["--flag".to_string()],
            Some(Path::new("fixtures")),
            &output_root,
            Some(100),
            "native failure".to_string(),
            25,
        );

        assert_eq!(target.status, TargetStatus::Failed);
        assert_eq!(target.error.as_deref(), Some("native failure"));
        assert_eq!(target.args, vec!["--flag"]);
        assert_eq!(target.cwd, "fixtures");
        assert_eq!(target.timeout_ms, Some(100));
        assert_eq!(target.duration_ms, Some(25));
        assert_eq!(target.artifacts.crashpack, ".re/targets/app");
    }

    #[test]
    fn native_setup_errors_allow_tool_only_fallback() {
        assert!(native_error_allows_tool_only_fallback(
            "Native mode requires CAP_BPF and CAP_PERFMON capabilities."
        ));
        assert!(native_error_allows_tool_only_fallback(
            "Native mode is running in Docker without a shared host PID namespace."
        ));
        assert!(native_error_allows_tool_only_fallback(
            "Could not find heap_tracker.bpf.o. Build BPF objects with:"
        ));
        assert!(!native_error_allows_tool_only_fallback(
            "Binary not found: build/missing"
        ));
        assert!(!native_error_allows_tool_only_fallback(
            "Working directory not found: /tmp/missing"
        ));
    }

    #[test]
    fn fallback_status_prefers_findings_then_clean_then_unavailable() {
        let mut target = ObservationTargetSummary::new(
            "app",
            "build/app",
            Vec::new(),
            ".",
            TargetStatus::Failed,
            TargetExitSummary::not_run(),
            ObservationArtifacts::target_defaults(".re/targets/app"),
        );

        let mut result = EscalationResult {
            id: "E-1".to_string(),
            finding_id: "tool-only-fallback".to_string(),
            tool: "valgrind".to_string(),
            success: false,
            tool_available: false,
            duration_ms: 0,
            output_path: None,
            stdout_path: None,
            stderr_path: None,
            report_path: None,
            command: Vec::new(),
            exit_code: None,
            confirmed: false,
            error: Some("valgrind not found".to_string()),
            findings_detected: Vec::new(),
            timestamp: 1,
        };

        assert_eq!(
            fallback_target_status(&target, &[result.clone()]),
            TargetStatus::ToolUnavailable
        );

        result.success = true;
        result.tool_available = true;
        result.error = None;
        assert_eq!(
            fallback_target_status(&target, &[result.clone()]),
            TargetStatus::Clean
        );

        result.confirmed = true;
        result.findings_detected = vec!["use_after_free".to_string()];
        assert_eq!(
            fallback_target_status(&target, &[result]),
            TargetStatus::Findings
        );

        target.findings_count = 1;
        assert_eq!(fallback_target_status(&target, &[]), TargetStatus::Findings);
    }

    #[test]
    fn escalation_status_maps_tool_results_for_observe() {
        let mut result = EscalationResult {
            id: "E-1".to_string(),
            finding_id: "F-1".to_string(),
            tool: "valgrind".to_string(),
            success: true,
            tool_available: true,
            duration_ms: 1,
            output_path: Some(".re/targets/app/escalations/valgrind/report.json".to_string()),
            stdout_path: None,
            stderr_path: None,
            report_path: None,
            command: Vec::new(),
            exit_code: Some(99),
            confirmed: true,
            error: None,
            findings_detected: vec!["heap_overflow".to_string()],
            timestamp: 1,
        };
        assert_eq!(escalation_status(&result), TargetStatus::Findings);

        result.confirmed = false;
        result.findings_detected.clear();
        assert_eq!(escalation_status(&result), TargetStatus::Clean);

        result.success = false;
        result.tool_available = false;
        result.error = Some("valgrind not found in PATH".to_string());
        assert_eq!(escalation_status(&result), TargetStatus::ToolUnavailable);

        result.tool = "asan".to_string();
        result.tool_available = false;
        result.error = Some("ASan requires a binary built with -fsanitize=address".to_string());
        assert_eq!(escalation_status(&result), TargetStatus::NotApplicable);
    }
}
