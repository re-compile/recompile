//! GDB crash-stack escalation support.

use crate::EscalationDetection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GdbReport {
    pub tool: String,
    pub confirmed: bool,
    pub signal_name: Option<String>,
    pub signal_line: Option<String>,
    pub crash_frames: Vec<String>,
    pub registers: Vec<String>,
    pub detected: Vec<EscalationDetection>,
}

impl GdbReport {
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

pub fn parse_gdb_output(stdout: &str, stderr: &str) -> GdbReport {
    let combined = [stdout, stderr]
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    let signal_line = combined
        .lines()
        .find(|line| line.contains("Program received signal"))
        .map(|line| line.trim().to_string());
    let signal_name = signal_line
        .as_deref()
        .and_then(extract_signal_name)
        .map(str::to_string);
    let crash_frames = combined
        .lines()
        .filter_map(stable_gdb_frame)
        .collect::<Vec<_>>();
    let registers = collect_register_lines(&combined);
    let confirmed = signal_line.is_some() || !crash_frames.is_empty();

    let detected = if confirmed {
        vec![EscalationDetection {
            class: "unclassified_crash".to_string(),
            summary: signal_line
                .clone()
                .unwrap_or_else(|| "gdb captured crash stack".to_string()),
            line: signal_line
                .as_ref()
                .and_then(|needle| line_number_for(&combined, needle)),
        }]
    } else {
        Vec::new()
    };

    GdbReport {
        tool: "gdb".to_string(),
        confirmed,
        signal_name,
        signal_line,
        crash_frames,
        registers,
        detected,
    }
}

fn extract_signal_name(line: &str) -> Option<&str> {
    let tail = line.split_once("Program received signal")?.1.trim();
    let signal = tail.split_once(',').map(|(value, _)| value).unwrap_or(tail);
    let signal = signal.trim().trim_end_matches('.');
    if signal.is_empty() {
        None
    } else {
        Some(signal)
    }
}

fn stable_gdb_frame(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with('#') {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let frame_number = parts.next()?;
    if !frame_number
        .strip_prefix('#')
        .is_some_and(|value| value.chars().all(|ch| ch.is_ascii_digit()))
    {
        return None;
    }

    Some(trimmed.to_string())
}

fn collect_register_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (name, _) = trimmed.split_once(char::is_whitespace)?;
            if is_likely_register_name(name) {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .take(64)
        .collect()
}

fn is_likely_register_name(name: &str) -> bool {
    matches!(
        name,
        "rip" | "rsp" | "rbp" | "pc" | "sp" | "fp" | "lr" | "x0" | "x1" | "x2" | "x3"
    ) || name.starts_with('r') && name[1..].chars().all(|ch| ch.is_ascii_digit())
        || name.starts_with('x') && name[1..].chars().all(|ch| ch.is_ascii_digit())
}

fn line_number_for(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .lines()
        .position(|line| line.trim() == needle.trim())
        .map(|index| index + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_signal_frames_and_registers() {
        let stdout = r#"Program received signal SIGSEGV, Segmentation fault.
0x0000000000401142 in crash_here () at crash_segv_case.c:5
#0  0x0000000000401142 in crash_here () at crash_segv_case.c:5
#1  0x0000000000401160 in main (argc=1, argv=0x7fffffffe018) at crash_segv_case.c:11
rax            0x0                 0
rip            0x401142            0x401142 <crash_here+10>
"#;

        let report = parse_gdb_output(stdout, "");

        assert!(report.confirmed);
        assert_eq!(report.signal_name.as_deref(), Some("SIGSEGV"));
        assert_eq!(report.crash_frames.len(), 2);
        assert_eq!(report.detected_classes(), vec!["unclassified_crash"]);
        assert!(report.registers.iter().any(|line| line.starts_with("rip ")));
    }

    #[test]
    fn clean_output_is_not_confirmed() {
        let report = parse_gdb_output("[Inferior 1 exited normally]\n", "");
        assert!(!report.confirmed);
        assert!(report.detected.is_empty());
    }
}
