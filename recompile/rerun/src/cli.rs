//! CLI command handlers

use anyhow::Result;
use clap::ArgMatches;
use re_crashpack::EscalationPlan as FindingEscalationPlan;
use re_escalate::{EscalationConfig, EscalationResult, EscalationRunner, Finding};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use crate::native::run_native;
use crate::summary::{print_findings_summary, read_findings};

#[derive(Deserialize)]
struct NativeRunMetadata {
    binary_path: String,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    args: Vec<String>,
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

    println!("RECC Sentinel v0.1.0");
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
    config.args = analysis.args.clone();

    if scan_binary {
        if tool == "all" {
            return Err(anyhow::anyhow!(
                "--scan-binary requires an explicit tool, such as --tool valgrind or --tool asan"
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
                "--scan-binary requires an explicit tool, such as --tool valgrind or --tool asan"
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

    write_escalation_results(crashpack_dir, &[result])?;
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
            "escalation_total_runs": escalation_summary.pointer("/total_runs").cloned().unwrap_or(Value::Null),
            "escalation_confirmed_runs": escalation_summary.pointer("/confirmed_runs").cloned().unwrap_or(Value::Null),
            "escalation_detected_classes": escalation_summary.pointer("/detected_classes").cloned().unwrap_or_else(|| json!([])),
        },
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
        "class": finding.get("class").cloned().unwrap_or(Value::Null),
        "severity": finding.get("severity").cloned().unwrap_or(Value::Null),
        "confidence": finding.get("confidence").cloned().unwrap_or(Value::Null),
        "source": finding.get("source").cloned().unwrap_or(Value::Null),
        "operation": finding.get("operation").cloned().unwrap_or(Value::Null),
        "memory": finding.get("memory").cloned().unwrap_or(Value::Null),
        "stacks": finding.get("stacks").cloned().unwrap_or(Value::Null),
        "alloc_site": finding.get("alloc_site").cloned().unwrap_or(Value::Null),
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

    // Check for harnesses
    let harnesses_dir = crashpack_path.join("harnesses");
    if harnesses_dir.exists() {
        let harness_files: Vec<_> = fs::read_dir(&harnesses_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();

        if !harness_files.is_empty() {
            println!("\nGenerated harnesses:");
            for harness in harness_files {
                println!("  {}", harness);
            }
        }
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
                        warnings.push("Manifest missing recc_version");
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

    // Check harnesses directory
    let harnesses_dir = crashpack_path.join("harnesses");
    if harnesses_dir.exists() {
        let harness_count = fs::read_dir(&harnesses_dir)?
            .filter(|entry| {
                if let Ok(entry) = entry {
                    entry.file_name().to_string_lossy().ends_with(".c")
                } else {
                    false
                }
            })
            .count();

        if harness_count > 0 {
            println!("Harnesses: {} generated", harness_count);
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
}
