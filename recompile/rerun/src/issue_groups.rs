//! Stable issue fingerprints and grouping for crashpack findings.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueGroupReport {
    pub schema_version: String,
    pub purpose: String,
    pub groups: Vec<IssueGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueGroup {
    pub id: String,
    pub fingerprint: String,
    pub class: String,
    pub operation: String,
    pub severity: String,
    pub confidence: String,
    pub finding_count: usize,
    pub finding_indices: Vec<usize>,
    pub finding_ids: Vec<String>,
    pub source: IssueSource,
    pub memory: IssueMemory,
    pub fingerprint_inputs: IssueFingerprintInputs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueSource {
    pub status: String,
    pub path: Option<String>,
    pub call_site: Option<String>,
    pub alloc_site: Option<String>,
    pub free_site: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueMemory {
    pub access_size: Option<u64>,
    pub alloc_size: Option<u64>,
    pub pointer_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueFingerprintInputs {
    pub class: String,
    pub operation: String,
    pub source_path: Option<String>,
    pub call_site: Option<String>,
    pub alloc_site: Option<String>,
    pub free_site: Option<String>,
    pub access_size: Option<u64>,
    pub alloc_size: Option<u64>,
    pub tool: Option<String>,
    pub tool_summary: Option<String>,
    pub binary_identity: Option<String>,
}

impl IssueGroupReport {
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

pub fn annotate_findings_with_issue_groups(findings: &mut [Value]) -> IssueGroupReport {
    let mut groups = BTreeMap::<String, IssueGroup>::new();

    for (index, finding) in findings.iter_mut().enumerate() {
        let inputs = fingerprint_inputs(finding);
        let fingerprint = issue_fingerprint(&inputs);
        let group_id = issue_group_id(&fingerprint);

        if let Some(object) = finding.as_object_mut() {
            object.insert(
                "fingerprint".to_string(),
                Value::String(fingerprint.clone()),
            );
            object.insert(
                "issue_group_id".to_string(),
                Value::String(group_id.clone()),
            );
        }

        let finding_id =
            finding_string(finding, &["id"]).unwrap_or_else(|| format!("finding-{}", index + 1));

        groups
            .entry(fingerprint.clone())
            .and_modify(|group| {
                group.finding_count += 1;
                group.finding_indices.push(index);
                group.finding_ids.push(finding_id.clone());
            })
            .or_insert_with(|| IssueGroup {
                id: group_id,
                fingerprint,
                class: inputs.class.clone(),
                operation: inputs.operation.clone(),
                severity: finding_string(finding, &["severity"])
                    .unwrap_or_else(|| "unknown".to_string()),
                confidence: finding_string(finding, &["confidence"])
                    .unwrap_or_else(|| "unknown".to_string()),
                finding_count: 1,
                finding_indices: vec![index],
                finding_ids: vec![finding_id],
                source: IssueSource {
                    status: finding_string(finding, &["provenance", "source_status"])
                        .unwrap_or_else(|| "unknown".to_string()),
                    path: inputs.source_path.clone(),
                    call_site: inputs.call_site.clone(),
                    alloc_site: inputs.alloc_site.clone(),
                    free_site: inputs.free_site.clone(),
                },
                memory: IssueMemory {
                    access_size: inputs.access_size,
                    alloc_size: inputs.alloc_size,
                    pointer_status: finding_string(finding, &["evidence", "pointer_status"])
                        .or_else(|| finding_string(finding, &["pointer_status"])),
                },
                fingerprint_inputs: inputs,
            });
    }

    IssueGroupReport {
        schema_version: "1.0".to_string(),
        purpose: "issue_groups".to_string(),
        groups: groups.into_values().collect(),
    }
}

fn fingerprint_inputs(finding: &Value) -> IssueFingerprintInputs {
    let tool = tool_name(finding);
    let source_path = finding_string(finding, &["provenance", "source_path"])
        .or_else(|| finding_file_uri(finding, &["primaryLocation", "uri"]));
    let call_site = tool_frame(finding, "call_frame").or_else(|| first_stack_site(finding, "call"));
    let alloc_site = finding_string(finding, &["evidence", "alloc_site"])
        .filter(|value| stable_non_unknown(value))
        .or_else(|| tool_frame(finding, "alloc_frame"))
        .or_else(|| first_stack_site(finding, "alloc"));
    let free_site = finding_string(finding, &["evidence", "free_site"])
        .filter(|value| stable_non_unknown(value))
        .or_else(|| tool_frame(finding, "free_frame"))
        .or_else(|| first_stack_site(finding, "free"));
    let binary_identity = if tool.is_some()
        && source_path.is_none()
        && call_site.is_none()
        && alloc_site.is_none()
        && free_site.is_none()
    {
        binary_identity(finding)
    } else {
        None
    };

    IssueFingerprintInputs {
        class: finding_string(finding, &["class"])
            .or_else(|| finding_string(finding, &["kind"]))
            .unwrap_or_else(|| "unknown".to_string()),
        operation: finding_string(finding, &["evidence", "memory", "operation"])
            .or_else(|| finding_string(finding, &["evidence", "api"]))
            .unwrap_or_else(|| "unknown".to_string()),
        source_path,
        call_site,
        alloc_site,
        free_site,
        access_size: finding_u64(finding, &["evidence", "memory", "size"]),
        alloc_size: finding_u64(finding, &["evidence", "memory", "alloc_size"]),
        tool,
        tool_summary: normalized_tool_summary(finding),
        binary_identity,
    }
}

fn issue_fingerprint(inputs: &IssueFingerprintInputs) -> String {
    let access_size = inputs
        .access_size
        .map(|value| value.to_string())
        .unwrap_or_default();
    let alloc_size = inputs
        .alloc_size
        .map(|value| value.to_string())
        .unwrap_or_default();
    let mut fields = vec![
        inputs.class.as_str(),
        inputs.operation.as_str(),
        inputs.source_path.as_deref().unwrap_or(""),
        inputs.call_site.as_deref().unwrap_or(""),
        inputs.alloc_site.as_deref().unwrap_or(""),
        inputs.free_site.as_deref().unwrap_or(""),
        access_size.as_str(),
        alloc_size.as_str(),
    ];
    if inputs.tool.is_some() {
        fields.push(inputs.tool.as_deref().unwrap_or(""));
        fields.push(inputs.tool_summary.as_deref().unwrap_or(""));
        fields.push(inputs.binary_identity.as_deref().unwrap_or(""));
    }
    format!("re-issue-v1-{:016x}", fnv1a64(&fields.join("\x1f")))
}

fn issue_group_id(fingerprint: &str) -> String {
    let suffix = fingerprint
        .rsplit_once('-')
        .map(|(_, value)| value)
        .unwrap_or(fingerprint);
    format!("IG-{}", &suffix[..suffix.len().min(12)])
}

fn fnv1a64(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn first_stack_site(finding: &Value, stack_name: &str) -> Option<String> {
    finding
        .get("evidence")
        .and_then(|value| value.get("stacks"))
        .and_then(|value| value.get(stack_name))
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|frames| frames.iter())
        .filter_map(Value::as_str)
        .filter_map(normalize_stack_site)
        .next()
}

fn normalize_stack_site(frame: &str) -> Option<String> {
    let frame = frame.trim();
    if !stable_non_unknown(frame) || frame.starts_with("0x") {
        return None;
    }

    if let (Some(start), Some(end)) = (frame.rfind('('), frame.rfind(')')) {
        if end > start {
            let location = normalize_source_location(&frame[start + 1..end]);
            if location.is_some() {
                return location;
            }
        }
    }

    if frame.contains("+0x") {
        return None;
    }

    normalize_source_location(frame).or_else(|| Some(normalize_volatile_tokens(frame)))
}

fn tool_frame(finding: &Value, field: &str) -> Option<String> {
    finding_string(finding, &["evidence", "tool", field])
        .and_then(|frame| normalize_stack_site(&frame))
}

fn tool_name(finding: &Value) -> Option<String> {
    finding_string(finding, &["evidence", "tool", "name"])
        .or_else(|| finding_string(finding, &["origin"]))
        .filter(|value| value != "ebpf" && stable_non_unknown(value))
}

fn normalized_tool_summary(finding: &Value) -> Option<String> {
    finding_string(finding, &["evidence", "tool", "summary"])
        .or_else(|| finding_string(finding, &["message"]))
        .map(|summary| normalize_volatile_tokens(&summary))
        .filter(|summary| stable_non_unknown(summary))
}

fn binary_identity(finding: &Value) -> Option<String> {
    finding_string(finding, &["provenance", "original_binary_path"])
        .or_else(|| finding_string(finding, &["provenance", "binary_path"]))
        .and_then(|path| {
            Path::new(&path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .filter(|value| stable_non_unknown(value))
}

fn normalize_volatile_tokens(value: &str) -> String {
    value
        .split_whitespace()
        .map(normalize_volatile_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_volatile_token(token: &str) -> String {
    let trimmed = token.trim_matches(|ch: char| ch == ',' || ch == ';' || ch == ':');
    if trimmed.starts_with("0x") && trimmed[2..].chars().all(|ch| ch.is_ascii_hexdigit()) {
        return token.replace(trimmed, "0xADDR");
    }
    if let Some(normalized_pid) = normalize_pid_prefix(trimmed) {
        return token.replace(trimmed, &normalized_pid);
    }
    if trimmed.starts_with("==")
        && trimmed.ends_with("==")
        && trimmed[2..trimmed.len().saturating_sub(2)]
            .chars()
            .all(|ch| ch.is_ascii_digit())
    {
        return token.replace(trimmed, "==PID==");
    }
    token.to_string()
}

fn normalize_pid_prefix(token: &str) -> Option<String> {
    let rest = token.strip_prefix("==")?;
    let end = rest.find("==")?;
    if end == 0 || !rest[..end].chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(format!("==PID=={}", &rest[end + 2..]))
}

fn normalize_source_location(location: &str) -> Option<String> {
    let location = location.trim();
    if !stable_non_unknown(location) {
        return None;
    }
    let (before_last, last) = numeric_suffix(location)?;
    let Some((file, line)) = numeric_suffix(before_last) else {
        return Some(format!("{before_last}:{last}"));
    };
    Some(format!("{file}:{line}"))
}

fn numeric_suffix(value: &str) -> Option<(&str, &str)> {
    let (head, tail) = value.rsplit_once(':')?;
    if !tail.is_empty() && tail.chars().all(|ch| ch.is_ascii_digit()) {
        Some((head, tail))
    } else {
        None
    }
}

fn stable_non_unknown(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "unknown" && value != "??" && !value.starts_with("??:")
}

fn finding_string(finding: &Value, path: &[&str]) -> Option<String> {
    let mut current = finding;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(str::to_string)
}

fn finding_file_uri(finding: &Value, path: &[&str]) -> Option<String> {
    finding_string(finding, path).and_then(|value| {
        value
            .strip_prefix("file://")
            .map(str::to_string)
            .filter(|value| stable_non_unknown(value))
    })
}

fn finding_u64(finding: &Value, path: &[&str]) -> Option<u64> {
    let mut current = finding;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_u64()
        .or_else(|| current.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| {
            current
                .as_str()
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprints_are_stable_for_same_finding() {
        let finding = json!({
            "id": "F-1",
            "class": "heap_overflow",
            "severity": "error",
            "confidence": "high",
            "evidence": {
                "memory": {"operation": "memcpy", "size": 64, "alloc_size": 16},
                "stacks": {"call": ["copy (/tmp/project/src/app.c:12:3)"]},
                "alloc_site": "/tmp/project/src/app.c"
            },
            "provenance": {
                "source_status": "resolved",
                "source_path": "/tmp/project/src/app.c"
            }
        });

        let first = issue_fingerprint(&fingerprint_inputs(&finding));
        let second = issue_fingerprint(&fingerprint_inputs(&finding));
        assert_eq!(first, second);
        assert!(first.starts_with("re-issue-v1-"));
    }

    #[test]
    fn groups_repeated_findings_but_preserves_independent_sites() {
        let mut findings = vec![
            json!({
                "id": "F-1",
                "class": "heap_overflow",
                "severity": "error",
                "confidence": "high",
                "evidence": {
                    "memory": {"operation": "memcpy", "size": 64, "alloc_size": 16},
                    "stacks": {"call": ["copy (/tmp/project/src/app.c:12:3)"]},
                    "alloc_site": "/tmp/project/src/app.c"
                },
                "provenance": {"source_status": "resolved", "source_path": "/tmp/project/src/app.c"}
            }),
            json!({
                "id": "F-2",
                "class": "heap_overflow",
                "severity": "error",
                "confidence": "high",
                "evidence": {
                    "memory": {"operation": "memcpy", "size": 64, "alloc_size": 16},
                    "stacks": {"call": ["copy (/tmp/project/src/app.c:12:9)"]},
                    "alloc_site": "/tmp/project/src/app.c"
                },
                "provenance": {"source_status": "resolved", "source_path": "/tmp/project/src/app.c"}
            }),
            json!({
                "id": "F-3",
                "class": "heap_overflow",
                "severity": "error",
                "confidence": "high",
                "evidence": {
                    "memory": {"operation": "memcpy", "size": 64, "alloc_size": 16},
                    "stacks": {"call": ["other (/tmp/project/src/app.c:30:1)"]},
                    "alloc_site": "/tmp/project/src/app.c"
                },
                "provenance": {"source_status": "resolved", "source_path": "/tmp/project/src/app.c"}
            }),
        ];

        let report = annotate_findings_with_issue_groups(&mut findings);

        assert_eq!(report.group_count(), 2);
        assert_eq!(report.groups[0].finding_count, 2);
        assert_eq!(report.groups[1].finding_count, 1);
        assert_eq!(
            findings[0].get("fingerprint"),
            findings[1].get("fingerprint")
        );
        assert_ne!(
            findings[0].get("fingerprint"),
            findings[2].get("fingerprint")
        );
        assert!(findings[0].get("issue_group_id").is_some());
    }

    #[test]
    fn normalizes_source_locations_without_losing_line_numbers() {
        assert_eq!(
            normalize_source_location("/tmp/project/src/app.c:12:3").as_deref(),
            Some("/tmp/project/src/app.c:12")
        );
        assert_eq!(
            normalize_source_location("/tmp/project/src/app.c:12").as_deref(),
            Some("/tmp/project/src/app.c:12")
        );
        assert_eq!(normalize_source_location("/tmp/project/src/app.c"), None);
    }

    #[test]
    fn normalizes_asan_pid_and_address_tokens() {
        assert_eq!(
            normalize_volatile_tokens(
                "==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x503000000040"
            ),
            "==PID==ERROR: AddressSanitizer: heap-use-after-free on address 0xADDR"
        );
    }

    #[test]
    fn tool_fingerprints_ignore_volatile_tool_fields() {
        let first = json!({
            "id": "F-valgrind-use_after_free-run-one",
            "origin": "valgrind",
            "class": "use_after_free",
            "severity": "critical",
            "confidence": "tool_confirmed",
            "timestamp": 1,
            "evidence": {
                "api": "valgrind",
                "tool": {
                    "name": "valgrind",
                    "result_id": "uuid-one",
                    "summary": "Invalid read of size 1 at 0x4a45040",
                    "line": 6,
                    "call_frame": "cache_line_score (/tmp/run-one/use_after_free_case.c:17)",
                    "report_path": "/tmp/run-one/valgrind_uuid-one.json",
                    "stderr_path": "/tmp/run-one/valgrind_uuid-one.stderr.log"
                },
                "stacks": {
                    "call": ["cache_line_score (/tmp/run-one/use_after_free_case.c:17)", "Invalid read of size 1 at 0x4a45040"]
                }
            },
            "provenance": {
                "source_status": "resolved",
                "source_path": "/tmp/run-one/use_after_free_case.c",
                "original_binary_path": "/tmp/run-one/use_after_free_case"
            }
        });

        let second = json!({
            "id": "F-valgrind-use_after_free-run-two",
            "origin": "valgrind",
            "class": "use_after_free",
            "severity": "critical",
            "confidence": "tool_confirmed",
            "timestamp": 999,
            "evidence": {
                "api": "valgrind",
                "tool": {
                    "name": "valgrind",
                    "result_id": "uuid-two",
                    "summary": "Invalid read of size 1 at 0x7fff1234",
                    "line": 18,
                    "call_frame": "cache_line_score (/tmp/run-one/use_after_free_case.c:17)",
                    "report_path": "/tmp/run-two/valgrind_uuid-two.json",
                    "stderr_path": "/tmp/run-two/valgrind_uuid-two.stderr.log"
                },
                "stacks": {
                    "call": ["cache_line_score (/tmp/run-one/use_after_free_case.c:17)", "Invalid read of size 1 at 0x7fff1234"]
                }
            },
            "provenance": {
                "source_status": "resolved",
                "source_path": "/tmp/run-one/use_after_free_case.c",
                "original_binary_path": "/tmp/run-two/use_after_free_case"
            }
        });

        assert_eq!(
            issue_fingerprint(&fingerprint_inputs(&first)),
            issue_fingerprint(&fingerprint_inputs(&second))
        );
    }

    #[test]
    fn tool_fingerprints_split_independent_source_frames() {
        let mut first = json!({
            "origin": "asan",
            "class": "use_after_free",
            "evidence": {
                "api": "asan",
                "tool": {
                    "name": "asan",
                    "summary": "ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040",
                    "call_frame": "/tmp/project/cache.c:17"
                }
            },
            "provenance": {"source_status": "resolved", "source_path": "/tmp/project/cache.c"}
        });
        let mut second = first.clone();
        second["evidence"]["tool"]["call_frame"] = Value::String("/tmp/project/cache.c:44".into());

        let first_fingerprint = issue_fingerprint(&fingerprint_inputs(&first));
        let second_fingerprint = issue_fingerprint(&fingerprint_inputs(&second));
        assert_ne!(first_fingerprint, second_fingerprint);

        first["evidence"]["tool"]["result_id"] = Value::String("run-one".into());
        second["evidence"]["tool"]["result_id"] = Value::String("run-two".into());
        assert_ne!(
            issue_fingerprint(&fingerprint_inputs(&first)),
            issue_fingerprint(&fingerprint_inputs(&second))
        );
    }

    #[test]
    fn tool_fingerprints_use_binary_fallback_when_sources_are_missing() {
        let first = json!({
            "origin": "valgrind",
            "class": "fd_leak",
            "evidence": {
                "api": "valgrind",
                "tool": {
                    "name": "valgrind",
                    "summary": "Open file descriptor 3: /tmp/data"
                }
            },
            "provenance": {
                "source_status": "unresolved",
                "original_binary_path": "/tmp/run-one/server"
            }
        });
        let second = json!({
            "origin": "valgrind",
            "class": "fd_leak",
            "evidence": {
                "api": "valgrind",
                "tool": {
                    "name": "valgrind",
                    "summary": "Open file descriptor 3: /tmp/data"
                }
            },
            "provenance": {
                "source_status": "unresolved",
                "original_binary_path": "/tmp/run-two/server"
            }
        });

        let inputs = fingerprint_inputs(&first);
        assert_eq!(inputs.binary_identity.as_deref(), Some("server"));
        assert_eq!(
            issue_fingerprint(&inputs),
            issue_fingerprint(&fingerprint_inputs(&second))
        );
    }
}
