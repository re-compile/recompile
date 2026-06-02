//! UndefinedBehaviorSanitizer escalation support.

use crate::EscalationDetection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UbsanReport {
    pub tool: String,
    pub detected: Vec<EscalationDetection>,
}

impl UbsanReport {
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

pub fn parse_ubsan_output(stdout: &str, stderr: &str) -> UbsanReport {
    let combined = if stdout.trim().is_empty() {
        stderr.to_string()
    } else if stderr.trim().is_empty() {
        stdout.to_string()
    } else {
        format!("{}\n{}", stdout, stderr)
    };

    let mut detected = Vec::new();
    for (index, line) in combined.lines().enumerate() {
        let normalized = line.trim();
        if !normalized.contains("runtime error:") {
            continue;
        }
        if let Some(class) = ubsan_error_class(normalized) {
            push_detection(&mut detected, class, normalized, index + 1);
        }
    }

    UbsanReport {
        tool: "ubsan".to_string(),
        detected,
    }
}

fn ubsan_error_class(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("signed integer overflow") {
        return Some("signed_integer_overflow");
    }
    if lower.contains("shift exponent")
        || lower.contains("shift base")
        || lower.contains("left shift of")
    {
        return Some("shift_out_of_bounds");
    }
    if lower.contains("null pointer")
        || lower.contains("null value")
        || lower.contains("member access within null")
    {
        return Some("null_pointer_use");
    }
    if lower.contains("misaligned address")
        || lower.contains("requires ")
            && lower.contains(" byte alignment")
            && lower.contains("address ")
    {
        return Some("misaligned_pointer");
    }
    if lower.contains("index ") && lower.contains("out of bounds") {
        return Some("bounds");
    }
    Some("undefined_behavior")
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
    fn parses_signed_integer_overflow() {
        let stderr = "overflow.c:8:14: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n";
        let report = parse_ubsan_output("", stderr);
        assert!(report.confirmed());
        assert_eq!(report.detected_classes(), vec!["signed_integer_overflow"]);
    }

    #[test]
    fn parses_shift_out_of_bounds() {
        let stderr =
            "shift.c:6:14: runtime error: shift exponent 32 is too large for 32-bit type 'int'\n";
        let report = parse_ubsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["shift_out_of_bounds"]);
    }

    #[test]
    fn parses_null_pointer_use() {
        let stderr = "null.c:6:9: runtime error: store to null pointer of type 'int'\n";
        let report = parse_ubsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["null_pointer_use"]);
    }

    #[test]
    fn parses_misaligned_pointer() {
        let stderr = "align.c:7:12: runtime error: load of misaligned address 0x123 for type 'int', which requires 4 byte alignment\n";
        let report = parse_ubsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["misaligned_pointer"]);
    }

    #[test]
    fn parses_bounds() {
        let stderr = "bounds.c:6:15: runtime error: index 4 out of bounds for type 'int [4]'\n";
        let report = parse_ubsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["bounds"]);
    }

    #[test]
    fn preserves_independent_same_class_detections() {
        let stderr = r#"overflow.c:8:14: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
counter.c:12:18: runtime error: signed integer overflow: 2000000000 + 2000000000 cannot be represented in type 'int'
"#;

        let report = parse_ubsan_output("", stderr);
        assert_eq!(report.detected_classes(), vec!["signed_integer_overflow"]);
        assert_eq!(report.detected.len(), 2);
        assert_eq!(report.detected[0].line, Some(1));
        assert_eq!(report.detected[1].line, Some(2));
        assert!(report.detected[0].summary.contains("overflow.c:8:14"));
        assert!(report.detected[1].summary.contains("counter.c:12:18"));
    }

    #[test]
    fn clean_output_is_not_confirmed() {
        let report = parse_ubsan_output("ok\n", "");
        assert!(!report.confirmed());
        assert!(report.detected.is_empty());
    }
}
