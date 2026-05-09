use anyhow::{Context, Result};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSummary {
    pub class: String,
    pub severity: String,
    pub confidence: String,
    pub operation: Option<String>,
    pub location: Option<String>,
    pub fallback: Option<String>,
}

pub fn read_findings(path: &Path) -> Result<Vec<Value>> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).with_context(|| format!("Failed to parse {}", path.display()))
}

pub fn summarize_finding(finding: &Value) -> FindingSummary {
    FindingSummary {
        class: string_field(finding, &["class"]).unwrap_or_else(|| "unknown".to_string()),
        severity: string_field(finding, &["severity"]).unwrap_or_else(|| "unknown".to_string()),
        confidence: string_field(finding, &["confidence"]).unwrap_or_else(|| "unknown".to_string()),
        operation: string_field(finding, &["evidence", "memory", "operation"]),
        location: source_location(finding),
        fallback: binary_offset(finding),
    }
}

pub fn print_findings_summary(findings: &[Value]) {
    for (index, finding) in findings.iter().enumerate() {
        let summary = summarize_finding(finding);
        println!("\n--- Finding #{} ---", index + 1);
        println!("  Class:      {}", summary.class);
        println!("  Severity:   {}", summary.severity);
        println!("  Confidence: {}", summary.confidence);

        if let Some(operation) = summary.operation {
            println!("  Operation:  {}", operation);
        }

        match (summary.location, summary.fallback) {
            (Some(location), _) => println!("  Location:   {}", location),
            (None, Some(fallback)) => println!("  Location:   unresolved source ({})", fallback),
            (None, None) => println!("  Location:   unresolved source"),
        }
    }

    if findings.is_empty() {
        println!("No findings detected.");
        print_no_findings_help();
    } else {
        println!("\nTotal findings: {}", findings.len());
    }
}

pub fn print_no_findings_help() {
    println!("\nNo-finding checklist:");
    println!("  - If running in Docker, use --privileged --pid=host");
    println!("  - Build the target with debug info (-g) and frame pointers");
    println!("  - Avoid optimizer/builtin rewrites for allocator and libc memory calls");
    println!("  - Confirm the test run actually executes the bug path");
    println!("  - Check re-findings.jsonl for attach or symbolization diagnostics");
}

fn source_location(finding: &Value) -> Option<String> {
    string_field(finding, &["provenance", "source_path"])
        .or_else(|| string_field(finding, &["evidence", "alloc_site"]))
        .or_else(|| primary_location(finding))
        .filter(|value| !value.is_empty() && value != "unknown")
}

fn primary_location(finding: &Value) -> Option<String> {
    string_field(finding, &["primaryLocation", "uri"]).and_then(|uri| {
        uri.strip_prefix("file://")
            .map(str::to_string)
            .or(Some(uri))
    })
}

fn binary_offset(finding: &Value) -> Option<String> {
    ["call", "alloc"].iter().find_map(|stack_name| {
        finding
            .get("evidence")
            .and_then(|value| value.get("stacks"))
            .and_then(|value| value.get(stack_name))
            .and_then(|value| value.as_array())
            .and_then(|frames| {
                frames.iter().find_map(|frame| {
                    let text = frame.as_str()?.trim();
                    if text.contains("+0x") {
                        Some(text.to_string())
                    } else {
                        None
                    }
                })
            })
    })
}

fn string_field(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summary_prefers_provenance_source() {
        let finding = json!({
            "class": "heap_overflow",
            "severity": "error",
            "confidence": "high",
            "provenance": {"source_path": "src/user.c"},
            "evidence": {
                "alloc_site": "src/alloc.c",
                "memory": {"operation": "memcpy"}
            }
        });

        let summary = summarize_finding(&finding);
        assert_eq!(summary.location.as_deref(), Some("src/user.c"));
        assert_eq!(summary.operation.as_deref(), Some("memcpy"));
    }

    #[test]
    fn summary_uses_binary_offset_fallback() {
        let finding = json!({
            "class": "invalid_free",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "stacks": {
                    "call": ["/tmp/app+0x770"]
                }
            }
        });

        let summary = summarize_finding(&finding);
        assert_eq!(summary.location, None);
        assert_eq!(summary.fallback.as_deref(), Some("/tmp/app+0x770"));
    }
}
