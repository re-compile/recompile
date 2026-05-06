//! AddressSanitizer escalation support.

use crate::EscalationDetection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AsanReport {
    pub tool: String,
    pub summary: Option<String>,
    pub detected: Vec<EscalationDetection>,
}

impl AsanReport {
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

pub fn parse_asan_output(stdout: &str, stderr: &str) -> AsanReport {
    let combined = if stdout.trim().is_empty() {
        stderr.to_string()
    } else if stderr.trim().is_empty() {
        stdout.to_string()
    } else {
        format!("{}\n{}", stdout, stderr)
    };

    let lines: Vec<&str> = combined.lines().collect();
    let mut detected = Vec::new();
    let mut summary = None;

    for (index, line) in lines.iter().enumerate() {
        let normalized = line.trim();
        if normalized.contains("SUMMARY: AddressSanitizer:")
            || normalized.contains("SUMMARY: LeakSanitizer:")
        {
            summary = Some(normalized.to_string());
        }

        let Some(error_class) = asan_error_class(normalized) else {
            continue;
        };

        push_detection(&mut detected, error_class, normalized, index + 1);
    }

    AsanReport {
        tool: "asan".to_string(),
        summary,
        detected,
    }
}

fn asan_error_class(line: &str) -> Option<&'static str> {
    if line.contains("ERROR: AddressSanitizer: heap-buffer-overflow") {
        return Some("heap_overflow");
    }
    if line.contains("ERROR: AddressSanitizer: heap-use-after-free") {
        return Some("use_after_free");
    }
    if line.contains("ERROR: AddressSanitizer: attempting double-free") {
        return Some("double_free");
    }
    if line
        .contains("ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed")
    {
        return Some("invalid_free");
    }
    if line.contains("ERROR: LeakSanitizer: detected memory leaks")
        || line.contains("ERROR: AddressSanitizer: detected memory leaks")
    {
        return Some("memory_leak");
    }

    None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_heap_overflow() {
        let stderr = r#"=================================================================
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000020
WRITE of size 1 at 0x602000000020 thread T0
SUMMARY: AddressSanitizer: heap-buffer-overflow copy_overrun_case.c:10 in main
"#;

        let report = parse_asan_output("", stderr);
        assert!(report.confirmed());
        assert_eq!(report.detected_classes(), vec!["heap_overflow"]);
        assert_eq!(
            report.summary.as_deref(),
            Some("SUMMARY: AddressSanitizer: heap-buffer-overflow copy_overrun_case.c:10 in main")
        );
    }

    #[test]
    fn parses_use_after_free() {
        let stderr = r#"==42==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040
READ of size 1 at 0x603000000040 thread T0
SUMMARY: AddressSanitizer: heap-use-after-free use_after_free_case.c:17 in cache_line_score
"#;

        let report = parse_asan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["use_after_free"]);
    }

    #[test]
    fn parses_double_free() {
        let stderr = r#"==42==ERROR: AddressSanitizer: attempting double-free on 0x603000000040 in thread T0:
SUMMARY: AddressSanitizer: double-free sanitizer_malloc.cpp:50 in free
"#;

        let report = parse_asan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["double_free"]);
    }

    #[test]
    fn parses_invalid_free() {
        let stderr = r#"==42==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x7fff0000
SUMMARY: AddressSanitizer: bad-free sanitizer_malloc.cpp:50 in free
"#;

        let report = parse_asan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["invalid_free"]);
    }

    #[test]
    fn parses_memory_leak() {
        let stderr = r#"==42==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 48 byte(s) in 1 object(s) allocated from:
SUMMARY: AddressSanitizer: 48 byte(s) leaked in 1 allocation(s).
"#;

        let report = parse_asan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["memory_leak"]);
    }

    #[test]
    fn clean_output_is_not_confirmed() {
        let report = parse_asan_output("ok\n", "");
        assert!(!report.confirmed());
        assert!(report.detected.is_empty());
    }
}
