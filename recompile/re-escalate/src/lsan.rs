//! LeakSanitizer escalation support.

use crate::EscalationDetection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LsanReport {
    pub tool: String,
    pub summary: Option<String>,
    pub detected: Vec<EscalationDetection>,
}

impl LsanReport {
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

pub fn parse_lsan_output(stdout: &str, stderr: &str) -> LsanReport {
    let combined = if stdout.trim().is_empty() {
        stderr.to_string()
    } else if stderr.trim().is_empty() {
        stdout.to_string()
    } else {
        format!("{}\n{}", stdout, stderr)
    };

    let mut detected = Vec::new();
    let mut summary = None;

    for (index, line) in combined.lines().enumerate() {
        let normalized = line.trim();
        if normalized.contains("SUMMARY: LeakSanitizer:") {
            summary = Some(normalized.to_string());
        }
        if normalized.contains("ERROR: LeakSanitizer: detected memory leaks") {
            push_detection(&mut detected, "memory_leak", normalized, index + 1);
        }
    }

    LsanReport {
        tool: "lsan".to_string(),
        summary,
        detected,
    }
}

fn push_detection(
    detected: &mut Vec<EscalationDetection>,
    class: &str,
    summary: &str,
    line: usize,
) {
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
    fn parses_direct_memory_leak() {
        let stderr = r#"=================================================================
==42==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 48 byte(s) in 1 object(s) allocated from:
    #0 0xaaa in malloc lsan_interceptors.cpp:75
    #1 0xbbb in open_session memory_leak_case.c:8

SUMMARY: LeakSanitizer: 48 byte(s) leaked in 1 allocation(s).
"#;

        let report = parse_lsan_output("", stderr);
        assert!(report.confirmed());
        assert_eq!(report.detected_classes(), vec!["memory_leak"]);
        assert_eq!(
            report.summary.as_deref(),
            Some("SUMMARY: LeakSanitizer: 48 byte(s) leaked in 1 allocation(s).")
        );
    }

    #[test]
    fn parses_indirect_memory_leak() {
        let stderr = r#"==42==ERROR: LeakSanitizer: detected memory leaks
Indirect leak of 32 byte(s) in 1 object(s) allocated from:
SUMMARY: LeakSanitizer: 32 byte(s) leaked in 1 allocation(s).
"#;

        let report = parse_lsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["memory_leak"]);
    }

    #[test]
    fn preserves_independent_same_class_detections() {
        let stderr = r#"==42==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 48 byte(s) in 1 object(s) allocated from:
    #0 0xaaa in malloc lsan_interceptors.cpp:75
    #1 0xbbb in open_session session.c:8
SUMMARY: LeakSanitizer: 48 byte(s) leaked in 1 allocation(s).
==42==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 96 byte(s) in 1 object(s) allocated from:
    #0 0xccc in malloc lsan_interceptors.cpp:75
    #1 0xddd in open_buffer buffer.c:12
SUMMARY: LeakSanitizer: 96 byte(s) leaked in 1 allocation(s).
"#;

        let report = parse_lsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["memory_leak"]);
        assert_eq!(report.detected.len(), 2);
        assert_eq!(report.detected[0].line, Some(1));
        assert_eq!(report.detected[1].line, Some(6));
    }

    #[test]
    fn clean_output_is_not_confirmed() {
        let report = parse_lsan_output("ok\n", "");
        assert!(!report.confirmed());
        assert!(report.detected.is_empty());
    }
}
