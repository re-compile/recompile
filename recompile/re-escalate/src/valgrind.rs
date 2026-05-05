//! Valgrind escalation support.

use crate::EscalationDetection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValgrindReport {
    pub tool: String,
    pub error_summary: Option<String>,
    pub detected: Vec<EscalationDetection>,
}

impl ValgrindReport {
    pub fn confirmed(&self) -> bool {
        !self.detected.is_empty()
    }

    pub fn detected_classes(&self) -> Vec<String> {
        let mut classes = Vec::new();
        for detection in &self.detected {
            if !classes.contains(&detection.class) {
                classes.push(detection.class.clone());
            }
        }
        classes
    }
}

pub fn parse_valgrind_output(stdout: &str, stderr: &str) -> ValgrindReport {
    let combined = if stdout.trim().is_empty() {
        stderr.to_string()
    } else if stderr.trim().is_empty() {
        stdout.to_string()
    } else {
        format!("{}\n{}", stdout, stderr)
    };

    let lines: Vec<&str> = combined.lines().collect();
    let mut detected = Vec::new();
    let mut error_summary = None;

    for (index, line) in lines.iter().enumerate() {
        let normalized = strip_valgrind_prefix(line).trim();
        if normalized.starts_with("ERROR SUMMARY:") {
            error_summary = Some(normalized.to_string());
        }

        if normalized.starts_with("Invalid write of size")
            || normalized.starts_with("Invalid read of size")
        {
            let context = context_after(&lines, index, 8);
            let class = if context.contains("free'd") || context.contains("freed") {
                "use_after_free"
            } else {
                "heap_overflow"
            };
            push_detection(&mut detected, class, normalized, index + 1);
            continue;
        }

        if normalized.starts_with("Invalid free()") {
            let context = context_after(&lines, index, 10);
            let class = if context.contains("free'd") || context.contains("freed") {
                "double_free"
            } else {
                "invalid_free"
            };
            push_detection(&mut detected, class, normalized, index + 1);
            continue;
        }

        if (normalized.contains("definitely lost:") || normalized.contains("are definitely lost"))
            && !normalized.contains("0 bytes")
        {
            push_detection(&mut detected, "memory_leak", normalized, index + 1);
        }
    }

    ValgrindReport {
        tool: "valgrind".to_string(),
        error_summary,
        detected,
    }
}

fn push_detection(
    detected: &mut Vec<EscalationDetection>,
    class: &str,
    summary: &str,
    line: usize,
) {
    if detected.iter().any(|existing| existing.class == class) {
        return;
    }

    detected.push(EscalationDetection {
        class: class.to_string(),
        summary: summary.to_string(),
        line: Some(line),
    });
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

fn context_after(lines: &[&str], start: usize, count: usize) -> String {
    lines
        .iter()
        .skip(start)
        .take(count)
        .map(|line| strip_valgrind_prefix(line).trim())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_heap_overflow() {
        let stderr = r#"==1== Invalid write of size 1
==1==    at 0x109177: main (copy_overrun_case.c:9)
==1==  Address 0x4a45050 is 0 bytes after a block of size 16 alloc'd
==1== ERROR SUMMARY: 1 errors from 1 contexts
"#;

        let report = parse_valgrind_output("", stderr);
        assert!(report.confirmed());
        assert_eq!(report.detected_classes(), vec!["heap_overflow"]);
        assert_eq!(
            report.error_summary.as_deref(),
            Some("ERROR SUMMARY: 1 errors from 1 contexts")
        );
    }

    #[test]
    fn parses_double_free() {
        let stderr = r#"==1== Invalid free() / delete / delete[] / realloc()
==1==    at 0x484417B: free (vg_replace_malloc.c:872)
==1==  Address 0x4a45040 is 0 bytes inside a block of size 32 free'd
==1==    at 0x484417B: free (vg_replace_malloc.c:872)
"#;

        let report = parse_valgrind_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["double_free"]);
    }

    #[test]
    fn parses_invalid_free() {
        let stderr = r#"==1== Invalid free() / delete / delete[] / realloc()
==1==    at 0x484417B: free (vg_replace_malloc.c:872)
==1==  Address 0x1ffefffb2c is on thread 1's stack
"#;

        let report = parse_valgrind_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["invalid_free"]);
    }

    #[test]
    fn parses_use_after_free() {
        let stderr = r#"==1== Invalid read of size 1
==1==    at 0x1091C0: cache_line_score (use_after_free_case.c:17)
==1==  Address 0x4a45040 is 0 bytes inside a block of size 32 free'd
==1==    at 0x484417B: free (vg_replace_malloc.c:872)
==1== ERROR SUMMARY: 1 errors from 1 contexts
"#;

        let report = parse_valgrind_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["use_after_free"]);
    }

    #[test]
    fn clean_output_is_not_confirmed() {
        let stderr = "==1== ERROR SUMMARY: 0 errors from 0 contexts";
        let report = parse_valgrind_output("", stderr);
        assert!(!report.confirmed());
        assert!(report.detected.is_empty());
    }

    #[test]
    fn parses_definitely_lost_memory_leak() {
        let stderr = r#"==1== 48 bytes in 1 blocks are definitely lost in loss record 1 of 1
==1==    at 0x48417B4: malloc (vg_replace_malloc.c:381)
==1==    by 0x109177: session_open (memory_leak_case.c:8)
==1== ERROR SUMMARY: 1 errors from 1 contexts
"#;

        let report = parse_valgrind_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["memory_leak"]);
    }

    #[test]
    fn ignores_zero_and_reachable_leak_summaries() {
        let stderr = r#"==1== definitely lost: 0 bytes in 0 blocks
==1== still reachable: 64 bytes in 1 blocks
==1== ERROR SUMMARY: 0 errors from 0 contexts
"#;

        let report = parse_valgrind_output("", stderr);
        assert!(!report.confirmed());
        assert!(report.detected.is_empty());
    }
}
