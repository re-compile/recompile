//! Phase 4 observation-run contract.
//!
//! This module defines the stable JSON shape that `rerun observe` will write.
//! It intentionally contains the data contract only; execution wiring lives in
//! the CLI/native orchestration modules.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const OBSERVATION_RUN_SCHEMA_VERSION: &str = "1.0";
pub const OBSERVATION_RUN_PURPOSE: &str = "local_runtime_observation";
pub const REPEAT_SUMMARY_SCHEMA_VERSION: &str = "1.0";
pub const REPEAT_SUMMARY_PURPOSE: &str = "repeat_observation_summary";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Clean,
    Findings,
    Failed,
    Timeout,
    Skipped,
    ToolUnavailable,
    NotApplicable,
}

impl TargetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetStatus::Clean => "clean",
            TargetStatus::Findings => "findings",
            TargetStatus::Failed => "failed",
            TargetStatus::Timeout => "timeout",
            TargetStatus::Skipped => "skipped",
            TargetStatus::ToolUnavailable => "tool_unavailable",
            TargetStatus::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRunSummary {
    pub schema_version: String,
    pub purpose: String,
    pub output_root: String,
    pub target_count: usize,
    pub status_totals: BTreeMap<String, u64>,
    pub finding_totals_by_class: BTreeMap<String, u64>,
    pub escalation_totals_by_tool: BTreeMap<String, BTreeMap<String, u64>>,
    pub targets: Vec<ObservationTargetSummary>,
    pub next_commands: Vec<String>,
}

impl ObservationRunSummary {
    pub fn new(
        output_root: impl Into<String>,
        targets: Vec<ObservationTargetSummary>,
        next_commands: Vec<String>,
    ) -> Self {
        Self {
            schema_version: OBSERVATION_RUN_SCHEMA_VERSION.to_string(),
            purpose: OBSERVATION_RUN_PURPOSE.to_string(),
            output_root: output_root.into(),
            target_count: targets.len(),
            status_totals: status_totals(&targets),
            finding_totals_by_class: finding_totals_by_class(&targets),
            escalation_totals_by_tool: escalation_totals_by_tool(&targets),
            targets,
            next_commands,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationTargetSummary {
    pub name: String,
    pub binary_path: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub status: TargetStatus,
    pub error: Option<String>,
    pub exit: TargetExitSummary,
    pub duration_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub findings_count: u64,
    pub findings_by_class: BTreeMap<String, u64>,
    pub issue_group_count: u64,
    pub escalation: Vec<ObservationEscalationSummary>,
    pub diagnostics: Vec<ObservationDiagnostic>,
    pub artifacts: ObservationArtifacts,
    pub replay_command: Option<String>,
    pub summarize_command: Option<String>,
    pub next_commands: Vec<String>,
}

impl ObservationTargetSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        binary_path: impl Into<String>,
        args: Vec<String>,
        cwd: impl Into<String>,
        status: TargetStatus,
        exit: TargetExitSummary,
        artifacts: ObservationArtifacts,
    ) -> Self {
        Self {
            name: name.into(),
            binary_path: binary_path.into(),
            args,
            cwd: cwd.into(),
            env: BTreeMap::new(),
            status,
            error: None,
            exit,
            duration_ms: None,
            timeout_ms: None,
            findings_count: 0,
            findings_by_class: BTreeMap::new(),
            issue_group_count: 0,
            escalation: Vec::new(),
            diagnostics: Vec::new(),
            artifacts,
            replay_command: None,
            summarize_command: None,
            next_commands: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetExitSummary {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub crashed: bool,
}

impl TargetExitSummary {
    #[cfg(test)]
    pub fn clean_exit() -> Self {
        Self {
            code: Some(0),
            signal: None,
            crashed: false,
        }
    }

    pub fn not_run() -> Self {
        Self {
            code: None,
            signal: None,
            crashed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationEscalationSummary {
    pub tool: String,
    pub status: TargetStatus,
    pub confirmed: bool,
    pub findings_detected: Vec<String>,
    pub artifact_path: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationDiagnostic {
    pub component: String,
    pub status: String,
    pub detail: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationArtifacts {
    pub crashpack: String,
    pub evidence_pack: String,
    pub findings: String,
    pub analysis: String,
    pub manifest: String,
    pub logs: String,
    pub dependencies: Option<String>,
    pub issue_groups: Option<String>,
}

impl ObservationArtifacts {
    pub fn target_defaults(target_dir: impl AsRef<str>) -> Self {
        let target_dir = target_dir.as_ref();
        Self {
            crashpack: target_dir.to_string(),
            evidence_pack: format!("{target_dir}/evidence-pack.json"),
            findings: format!("{target_dir}/findings.json"),
            analysis: format!("{target_dir}/analysis.json"),
            manifest: format!("{target_dir}/manifest.json"),
            logs: format!("{target_dir}/logs"),
            dependencies: Some(format!("{target_dir}/dependencies.json")),
            issue_groups: Some(format!("{target_dir}/issue-groups.json")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepeatAttemptOutcome {
    Pass,
    Finding,
    Failure,
    Timeout,
    Inconclusive,
}

impl RepeatAttemptOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            RepeatAttemptOutcome::Pass => "pass",
            RepeatAttemptOutcome::Finding => "finding",
            RepeatAttemptOutcome::Failure => "failure",
            RepeatAttemptOutcome::Timeout => "timeout",
            RepeatAttemptOutcome::Inconclusive => "inconclusive",
        }
    }

    pub fn from_status(status: TargetStatus) -> Self {
        match status {
            TargetStatus::Clean => RepeatAttemptOutcome::Pass,
            TargetStatus::Findings => RepeatAttemptOutcome::Finding,
            TargetStatus::Failed | TargetStatus::Skipped => RepeatAttemptOutcome::Failure,
            TargetStatus::Timeout => RepeatAttemptOutcome::Timeout,
            TargetStatus::ToolUnavailable | TargetStatus::NotApplicable => {
                RepeatAttemptOutcome::Inconclusive
            }
        }
    }

    fn is_failure_like(self) -> bool {
        matches!(
            self,
            RepeatAttemptOutcome::Finding
                | RepeatAttemptOutcome::Failure
                | RepeatAttemptOutcome::Timeout
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatRunSummary {
    pub schema_version: String,
    pub purpose: String,
    pub output_root: String,
    pub requested_attempts: u32,
    pub completed_attempts: usize,
    pub status_totals: BTreeMap<String, u64>,
    pub outcome_totals: BTreeMap<String, u64>,
    pub finding_totals_by_class: BTreeMap<String, u64>,
    pub first_failure: Option<RepeatAttemptSelection>,
    pub best_evidence_attempt: Option<RepeatAttemptSelection>,
    pub escalation_policy: RepeatEscalationSummary,
    pub issue_groups: Vec<RepeatIssueGroup>,
    pub attempts: Vec<RepeatAttemptSummary>,
    pub next_commands: Vec<String>,
}

impl RepeatRunSummary {
    #[cfg(test)]
    pub fn new(
        output_root: impl Into<String>,
        requested_attempts: u32,
        attempts: Vec<RepeatAttemptSummary>,
        next_commands: Vec<String>,
    ) -> Self {
        Self::new_with_issue_groups(
            output_root,
            requested_attempts,
            attempts,
            Vec::new(),
            next_commands,
        )
    }

    #[cfg(test)]
    pub fn new_with_issue_groups(
        output_root: impl Into<String>,
        requested_attempts: u32,
        attempts: Vec<RepeatAttemptSummary>,
        issue_group_inputs: Vec<RepeatIssueGroupInput>,
        next_commands: Vec<String>,
    ) -> Self {
        Self::new_with_issue_groups_and_escalation(
            output_root,
            requested_attempts,
            attempts,
            issue_group_inputs,
            RepeatEscalationSummary::disabled(),
            next_commands,
        )
    }

    pub fn new_with_issue_groups_and_escalation(
        output_root: impl Into<String>,
        requested_attempts: u32,
        attempts: Vec<RepeatAttemptSummary>,
        issue_group_inputs: Vec<RepeatIssueGroupInput>,
        escalation_policy: RepeatEscalationSummary,
        next_commands: Vec<String>,
    ) -> Self {
        let first_failure = attempts
            .iter()
            .find(|attempt| attempt.outcome.is_failure_like())
            .map(|attempt| RepeatAttemptSelection::from_attempt(attempt, "first_non_pass"));
        let best_evidence_attempt = attempts
            .iter()
            .find(|attempt| attempt.findings_count > 0)
            .or_else(|| {
                attempts
                    .iter()
                    .find(|attempt| matches!(attempt.outcome, RepeatAttemptOutcome::Timeout))
            })
            .or_else(|| {
                attempts
                    .iter()
                    .find(|attempt| matches!(attempt.outcome, RepeatAttemptOutcome::Failure))
            })
            .map(|attempt| {
                RepeatAttemptSelection::from_attempt(attempt, "best_available_evidence")
            });

        Self {
            schema_version: REPEAT_SUMMARY_SCHEMA_VERSION.to_string(),
            purpose: REPEAT_SUMMARY_PURPOSE.to_string(),
            output_root: output_root.into(),
            requested_attempts,
            completed_attempts: repeat_completed_attempts(&attempts),
            status_totals: repeat_status_totals(&attempts),
            outcome_totals: repeat_outcome_totals(&attempts),
            finding_totals_by_class: repeat_finding_totals_by_class(&attempts),
            first_failure,
            best_evidence_attempt,
            escalation_policy,
            issue_groups: aggregate_repeat_issue_groups(issue_group_inputs),
            attempts,
            next_commands,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatAttemptSummary {
    pub attempt: u32,
    pub target_name: String,
    pub status: TargetStatus,
    pub outcome: RepeatAttemptOutcome,
    pub output_root: String,
    pub run_summary: String,
    pub crashpack: String,
    pub findings: String,
    pub evidence_pack: String,
    pub issue_groups: Option<String>,
    pub findings_count: u64,
    pub findings_by_class: BTreeMap<String, u64>,
    pub issue_group_count: u64,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
    pub next_commands: Vec<String>,
}

impl RepeatAttemptSummary {
    pub fn from_target(
        attempt: u32,
        target_name: impl Into<String>,
        output_root: impl Into<String>,
        run_summary: impl Into<String>,
        target: &ObservationTargetSummary,
    ) -> Self {
        Self {
            attempt,
            target_name: target_name.into(),
            status: target.status,
            outcome: RepeatAttemptOutcome::from_status(target.status),
            output_root: output_root.into(),
            run_summary: run_summary.into(),
            crashpack: target.artifacts.crashpack.clone(),
            findings: target.artifacts.findings.clone(),
            evidence_pack: target.artifacts.evidence_pack.clone(),
            issue_groups: target.artifacts.issue_groups.clone(),
            findings_count: target.findings_count,
            findings_by_class: target.findings_by_class.clone(),
            issue_group_count: target.issue_group_count,
            error: target.error.clone(),
            duration_ms: target.duration_ms,
            next_commands: target.next_commands.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatAttemptSelection {
    pub attempt: u32,
    pub target_name: String,
    pub status: TargetStatus,
    pub outcome: RepeatAttemptOutcome,
    pub reason: String,
    pub run_summary: String,
    pub crashpack: String,
    pub findings_count: u64,
    pub findings_by_class: BTreeMap<String, u64>,
}

impl RepeatAttemptSelection {
    fn from_attempt(attempt: &RepeatAttemptSummary, reason: impl Into<String>) -> Self {
        Self {
            attempt: attempt.attempt,
            target_name: attempt.target_name.clone(),
            status: attempt.status,
            outcome: attempt.outcome,
            reason: reason.into(),
            run_summary: attempt.run_summary.clone(),
            crashpack: attempt.crashpack.clone(),
            findings_count: attempt.findings_count,
            findings_by_class: attempt.findings_by_class.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatEscalationSummary {
    pub policy: String,
    pub deep: bool,
    pub selected_attempt_count: usize,
    pub selected_attempts: Vec<RepeatEscalationAttempt>,
}

impl RepeatEscalationSummary {
    pub fn new(
        policy: impl Into<String>,
        deep: bool,
        selected_attempts: Vec<RepeatEscalationAttempt>,
    ) -> Self {
        Self {
            policy: policy.into(),
            deep,
            selected_attempt_count: selected_attempts.len(),
            selected_attempts,
        }
    }

    #[cfg(test)]
    pub fn disabled() -> Self {
        Self::new("never", false, Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatEscalationAttempt {
    pub attempt: u32,
    pub target_name: String,
    pub status: TargetStatus,
    pub outcome: RepeatAttemptOutcome,
    pub reason: String,
    pub run_summary: String,
    pub crashpack: String,
    pub findings_count: u64,
    pub findings_by_class: BTreeMap<String, u64>,
}

impl RepeatEscalationAttempt {
    pub fn from_attempt(attempt: &RepeatAttemptSummary, reason: impl Into<String>) -> Self {
        Self {
            attempt: attempt.attempt,
            target_name: attempt.target_name.clone(),
            status: attempt.status,
            outcome: attempt.outcome,
            reason: reason.into(),
            run_summary: attempt.run_summary.clone(),
            crashpack: attempt.crashpack.clone(),
            findings_count: attempt.findings_count,
            findings_by_class: attempt.findings_by_class.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatIssueGroupInput {
    pub fingerprint: String,
    pub class: String,
    pub operation: String,
    pub severity: String,
    pub confidence: String,
    pub occurrence: RepeatIssueGroupOccurrence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatIssueGroup {
    pub id: String,
    pub fingerprint: String,
    pub class: String,
    pub operation: String,
    pub severity: String,
    pub confidence: String,
    pub attempt_count: u64,
    pub occurrence_count: u64,
    pub first_attempt: u32,
    pub last_attempt: u32,
    pub representative_attempt: RepeatIssueGroupOccurrence,
    pub attempts: Vec<RepeatIssueGroupOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatIssueGroupOccurrence {
    pub attempt: u32,
    pub target_name: String,
    pub issue_group_id: String,
    pub finding_count: u64,
    pub issue_groups: String,
    pub crashpack: String,
}

fn status_totals(targets: &[ObservationTargetSummary]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for target in targets {
        *totals
            .entry(target.status.as_str().to_string())
            .or_insert(0) += 1;
    }
    totals
}

fn repeat_status_totals(attempts: &[RepeatAttemptSummary]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for attempt in attempts {
        *totals
            .entry(attempt.status.as_str().to_string())
            .or_insert(0) += 1;
    }
    totals
}

fn repeat_outcome_totals(attempts: &[RepeatAttemptSummary]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for attempt in attempts {
        *totals
            .entry(attempt.outcome.as_str().to_string())
            .or_insert(0) += 1;
    }
    totals
}

fn repeat_completed_attempts(attempts: &[RepeatAttemptSummary]) -> usize {
    attempts
        .iter()
        .map(|attempt| attempt.attempt)
        .collect::<BTreeSet<_>>()
        .len()
}

fn repeat_finding_totals_by_class(attempts: &[RepeatAttemptSummary]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for attempt in attempts {
        for (class, count) in &attempt.findings_by_class {
            *totals.entry(class.clone()).or_insert(0) += count;
        }
    }
    totals
}

fn aggregate_repeat_issue_groups(inputs: Vec<RepeatIssueGroupInput>) -> Vec<RepeatIssueGroup> {
    #[derive(Debug)]
    struct RepeatIssueGroupBuilder {
        id: String,
        fingerprint: String,
        class: String,
        operation: String,
        severity: String,
        confidence: String,
        occurrence_count: u64,
        attempt_numbers: BTreeSet<u32>,
        attempts: Vec<RepeatIssueGroupOccurrence>,
    }

    let mut builders = BTreeMap::<String, RepeatIssueGroupBuilder>::new();
    for input in inputs {
        builders
            .entry(input.fingerprint.clone())
            .and_modify(|builder| {
                builder.occurrence_count += input.occurrence.finding_count;
                builder.attempt_numbers.insert(input.occurrence.attempt);
                builder.attempts.push(input.occurrence.clone());
            })
            .or_insert_with(|| {
                let mut attempt_numbers = BTreeSet::new();
                attempt_numbers.insert(input.occurrence.attempt);
                RepeatIssueGroupBuilder {
                    id: repeat_issue_group_id(&input.fingerprint),
                    fingerprint: input.fingerprint,
                    class: input.class,
                    operation: input.operation,
                    severity: input.severity,
                    confidence: input.confidence,
                    occurrence_count: input.occurrence.finding_count,
                    attempt_numbers,
                    attempts: vec![input.occurrence],
                }
            });
    }

    builders
        .into_values()
        .map(|mut builder| {
            builder.attempts.sort_by(|left, right| {
                left.attempt
                    .cmp(&right.attempt)
                    .then_with(|| left.target_name.cmp(&right.target_name))
                    .then_with(|| left.issue_group_id.cmp(&right.issue_group_id))
            });
            let representative_attempt = builder
                .attempts
                .first()
                .cloned()
                .expect("repeat issue group builders always contain an occurrence");
            let first_attempt = builder
                .attempt_numbers
                .first()
                .copied()
                .expect("repeat issue group builders always contain an attempt");
            let last_attempt = builder
                .attempt_numbers
                .last()
                .copied()
                .expect("repeat issue group builders always contain an attempt");

            RepeatIssueGroup {
                id: builder.id,
                fingerprint: builder.fingerprint,
                class: builder.class,
                operation: builder.operation,
                severity: builder.severity,
                confidence: builder.confidence,
                attempt_count: builder.attempt_numbers.len() as u64,
                occurrence_count: builder.occurrence_count,
                first_attempt,
                last_attempt,
                representative_attempt,
                attempts: builder.attempts,
            }
        })
        .collect()
}

fn repeat_issue_group_id(fingerprint: &str) -> String {
    let suffix = fingerprint
        .rsplit_once('-')
        .map(|(_, value)| value)
        .unwrap_or(fingerprint);
    format!("RIG-{}", &suffix[..suffix.len().min(12)])
}

fn finding_totals_by_class(targets: &[ObservationTargetSummary]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for target in targets {
        for (class, count) in &target.findings_by_class {
            *totals.entry(class.clone()).or_insert(0) += count;
        }
    }
    totals
}

fn escalation_totals_by_tool(
    targets: &[ObservationTargetSummary],
) -> BTreeMap<String, BTreeMap<String, u64>> {
    let mut totals: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for target in targets {
        for escalation in &target.escalation {
            let status_totals = totals.entry(escalation.tool.clone()).or_default();
            *status_totals
                .entry(escalation.status.as_str().to_string())
                .or_insert(0) += 1;
        }
    }
    totals
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn sample_target(name: &str, status: TargetStatus) -> ObservationTargetSummary {
        ObservationTargetSummary::new(
            name,
            format!("build/{name}"),
            vec!["--smoke".to_string()],
            ".",
            status,
            TargetExitSummary::clean_exit(),
            ObservationArtifacts::target_defaults(format!(".re/targets/{name}")),
        )
    }

    fn sample_repeat_attempt(
        attempt: u32,
        status: TargetStatus,
        findings_by_class: &[(&str, u64)],
    ) -> RepeatAttemptSummary {
        let mut target = sample_target("app", status);
        for (class, count) in findings_by_class {
            target.findings_count += count;
            target
                .findings_by_class
                .insert((*class).to_string(), *count);
        }
        RepeatAttemptSummary::from_target(
            attempt,
            format!("attempt-{attempt:04}-app"),
            format!(".re/attempts/{attempt:04}"),
            format!(".re/attempts/{attempt:04}/run-summary.json"),
            &target,
        )
    }

    fn sample_repeat_issue_group_input(
        attempt: &RepeatAttemptSummary,
        fingerprint: &str,
        class: &str,
        operation: &str,
        finding_count: u64,
    ) -> RepeatIssueGroupInput {
        RepeatIssueGroupInput {
            fingerprint: fingerprint.to_string(),
            class: class.to_string(),
            operation: operation.to_string(),
            severity: "high".to_string(),
            confidence: "confirmed".to_string(),
            occurrence: RepeatIssueGroupOccurrence {
                attempt: attempt.attempt,
                target_name: attempt.target_name.clone(),
                issue_group_id: format!("IG-{}", &fingerprint[fingerprint.len() - 4..]),
                finding_count,
                issue_groups: attempt.issue_groups.clone().unwrap(),
                crashpack: attempt.crashpack.clone(),
            },
        }
    }

    #[test]
    fn status_values_are_stable_snake_case() {
        let statuses = [
            (TargetStatus::Clean, "clean"),
            (TargetStatus::Findings, "findings"),
            (TargetStatus::Failed, "failed"),
            (TargetStatus::Timeout, "timeout"),
            (TargetStatus::Skipped, "skipped"),
            (TargetStatus::ToolUnavailable, "tool_unavailable"),
            (TargetStatus::NotApplicable, "not_applicable"),
        ];

        for (status, expected) in statuses {
            assert_eq!(status.as_str(), expected);
            assert_eq!(serde_json::to_value(status).unwrap(), json!(expected));
        }
    }

    #[test]
    fn run_summary_computes_totals_from_targets() {
        let clean = sample_target("clean_app", TargetStatus::Clean);
        let mut finding = sample_target("buggy_app", TargetStatus::Findings);
        finding.findings_count = 2;
        finding
            .findings_by_class
            .insert("heap_overflow".to_string(), 2);
        finding.escalation.push(ObservationEscalationSummary {
            tool: "valgrind".to_string(),
            status: TargetStatus::Findings,
            confirmed: true,
            findings_detected: vec!["heap_overflow".to_string()],
            artifact_path: Some(".re/targets/buggy_app/escalations/results.json".to_string()),
            error: None,
        });

        let summary = ObservationRunSummary::new(
            ".re",
            vec![clean, finding],
            vec!["jq . .re/run-summary.json".to_string()],
        );

        assert_eq!(summary.schema_version, OBSERVATION_RUN_SCHEMA_VERSION);
        assert_eq!(summary.purpose, OBSERVATION_RUN_PURPOSE);
        assert_eq!(summary.target_count, 2);
        assert_eq!(summary.status_totals.get("clean"), Some(&1));
        assert_eq!(summary.status_totals.get("findings"), Some(&1));
        assert_eq!(
            summary.finding_totals_by_class.get("heap_overflow"),
            Some(&2)
        );
        assert_eq!(
            summary
                .escalation_totals_by_tool
                .get("valgrind")
                .and_then(|totals| totals.get("findings")),
            Some(&1)
        );
    }

    #[test]
    fn repeat_outcome_values_are_stable_snake_case() {
        let outcomes = [
            (RepeatAttemptOutcome::Pass, "pass"),
            (RepeatAttemptOutcome::Finding, "finding"),
            (RepeatAttemptOutcome::Failure, "failure"),
            (RepeatAttemptOutcome::Timeout, "timeout"),
            (RepeatAttemptOutcome::Inconclusive, "inconclusive"),
        ];

        for (outcome, expected) in outcomes {
            assert_eq!(outcome.as_str(), expected);
            assert_eq!(serde_json::to_value(outcome).unwrap(), json!(expected));
        }
    }

    #[test]
    fn repeat_summary_computes_attempt_totals_and_evidence_selection() {
        let clean = sample_repeat_attempt(1, TargetStatus::Clean, &[]);
        let finding = sample_repeat_attempt(2, TargetStatus::Findings, &[("heap_overflow", 1)]);
        let timeout = sample_repeat_attempt(3, TargetStatus::Timeout, &[]);

        let summary = RepeatRunSummary::new(
            ".re",
            3,
            vec![clean, finding, timeout],
            vec!["jq . .re/repeat-summary.json".to_string()],
        );

        assert_eq!(summary.schema_version, REPEAT_SUMMARY_SCHEMA_VERSION);
        assert_eq!(summary.purpose, REPEAT_SUMMARY_PURPOSE);
        assert_eq!(summary.requested_attempts, 3);
        assert_eq!(summary.completed_attempts, 3);
        assert_eq!(summary.status_totals.get("clean"), Some(&1));
        assert_eq!(summary.status_totals.get("findings"), Some(&1));
        assert_eq!(summary.status_totals.get("timeout"), Some(&1));
        assert_eq!(summary.outcome_totals.get("pass"), Some(&1));
        assert_eq!(summary.outcome_totals.get("finding"), Some(&1));
        assert_eq!(summary.outcome_totals.get("timeout"), Some(&1));
        assert_eq!(
            summary.finding_totals_by_class.get("heap_overflow"),
            Some(&1)
        );
        assert_eq!(summary.escalation_policy.policy, "never");
        assert_eq!(summary.escalation_policy.selected_attempt_count, 0);

        let first_failure = summary.first_failure.as_ref().unwrap();
        assert_eq!(first_failure.attempt, 2);
        assert_eq!(first_failure.status, TargetStatus::Findings);
        assert_eq!(first_failure.reason, "first_non_pass");

        let best_evidence = summary.best_evidence_attempt.as_ref().unwrap();
        assert_eq!(best_evidence.attempt, 2);
        assert_eq!(best_evidence.findings_count, 1);
    }

    #[test]
    fn repeat_summary_keeps_all_clean_selection_empty() {
        let summary = RepeatRunSummary::new(
            ".re",
            2,
            vec![
                sample_repeat_attempt(1, TargetStatus::Clean, &[]),
                sample_repeat_attempt(2, TargetStatus::Clean, &[]),
            ],
            vec!["jq . .re/repeat-summary.json".to_string()],
        );

        assert_eq!(summary.outcome_totals.get("pass"), Some(&2));
        assert!(summary.first_failure.is_none());
        assert!(summary.best_evidence_attempt.is_none());
    }

    #[test]
    fn repeat_summary_counts_completed_attempts_once_per_attempt() {
        let mut app = sample_repeat_attempt(1, TargetStatus::Clean, &[]);
        app.target_name = "attempt-0001-app".to_string();
        let mut worker = sample_repeat_attempt(1, TargetStatus::Clean, &[]);
        worker.target_name = "attempt-0001-worker".to_string();

        let summary = RepeatRunSummary::new(
            ".re",
            1,
            vec![app, worker],
            vec!["jq . .re/repeat-summary.json".to_string()],
        );

        assert_eq!(summary.completed_attempts, 1);
        assert_eq!(summary.status_totals.get("clean"), Some(&2));
        assert_eq!(summary.outcome_totals.get("pass"), Some(&2));
    }

    #[test]
    fn repeat_summary_aggregates_issue_groups_by_fingerprint() {
        let first = sample_repeat_attempt(1, TargetStatus::Findings, &[("heap_overflow", 1)]);
        let second = sample_repeat_attempt(2, TargetStatus::Findings, &[("heap_overflow", 2)]);
        let third = sample_repeat_attempt(3, TargetStatus::Findings, &[("invalid_free", 1)]);
        let repeated_fingerprint = "re-issue-v1-1111111111111111";
        let independent_fingerprint = "re-issue-v1-2222222222222222";

        let summary = RepeatRunSummary::new_with_issue_groups(
            ".re",
            3,
            vec![first.clone(), second.clone(), third.clone()],
            vec![
                sample_repeat_issue_group_input(
                    &second,
                    repeated_fingerprint,
                    "heap_overflow",
                    "memcpy",
                    2,
                ),
                sample_repeat_issue_group_input(
                    &first,
                    repeated_fingerprint,
                    "heap_overflow",
                    "memcpy",
                    1,
                ),
                sample_repeat_issue_group_input(
                    &third,
                    independent_fingerprint,
                    "invalid_free",
                    "free",
                    1,
                ),
            ],
            vec!["jq . .re/repeat-summary.json".to_string()],
        );

        assert_eq!(summary.issue_groups.len(), 2);

        let repeated = &summary.issue_groups[0];
        assert_eq!(repeated.id, "RIG-111111111111");
        assert_eq!(repeated.fingerprint, repeated_fingerprint);
        assert_eq!(repeated.class, "heap_overflow");
        assert_eq!(repeated.operation, "memcpy");
        assert_eq!(repeated.attempt_count, 2);
        assert_eq!(repeated.occurrence_count, 3);
        assert_eq!(repeated.first_attempt, 1);
        assert_eq!(repeated.last_attempt, 2);
        assert_eq!(repeated.representative_attempt.attempt, 1);
        assert_eq!(
            repeated
                .attempts
                .iter()
                .map(|occurrence| occurrence.attempt)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        let independent = &summary.issue_groups[1];
        assert_eq!(independent.fingerprint, independent_fingerprint);
        assert_eq!(independent.class, "invalid_free");
        assert_eq!(independent.attempt_count, 1);
        assert_eq!(independent.occurrence_count, 1);
        assert_eq!(independent.first_attempt, 3);
    }

    #[test]
    fn repeat_summary_uses_timeout_as_best_evidence_without_findings() {
        let summary = RepeatRunSummary::new(
            ".re",
            2,
            vec![
                sample_repeat_attempt(1, TargetStatus::Clean, &[]),
                sample_repeat_attempt(2, TargetStatus::Timeout, &[]),
            ],
            vec!["jq . .re/repeat-summary.json".to_string()],
        );

        assert_eq!(
            summary
                .best_evidence_attempt
                .as_ref()
                .map(|attempt| attempt.attempt),
            Some(2)
        );
        assert_eq!(
            summary
                .best_evidence_attempt
                .as_ref()
                .map(|attempt| attempt.outcome),
            Some(RepeatAttemptOutcome::Timeout)
        );
    }

    #[test]
    fn serialized_summary_matches_schema_contract_shape() {
        let summary = ObservationRunSummary::new(
            ".re",
            vec![sample_target("app", TargetStatus::Clean)],
            vec!["rerun summarize .re/targets/app --format json".to_string()],
        );
        let value = serde_json::to_value(summary).unwrap();
        let not_run = TargetExitSummary::not_run();
        assert_eq!(not_run.code, None);
        assert_eq!(not_run.signal, None);
        assert!(!not_run.crashed);

        assert_eq!(value["schema_version"], json!("1.0"));
        assert_eq!(value["purpose"], json!("local_runtime_observation"));
        assert_eq!(value["output_root"], json!(".re"));
        assert_eq!(value["target_count"], json!(1));
        assert!(value["status_totals"].is_object());
        assert!(value["finding_totals_by_class"].is_object());
        assert!(value["escalation_totals_by_tool"].is_object());
        assert!(value["targets"].is_array());
        assert!(value["next_commands"].is_array());

        let target: &Value = &value["targets"][0];
        for key in [
            "name",
            "binary_path",
            "args",
            "cwd",
            "env",
            "status",
            "exit",
            "error",
            "duration_ms",
            "timeout_ms",
            "findings_count",
            "findings_by_class",
            "issue_group_count",
            "escalation",
            "diagnostics",
            "artifacts",
            "replay_command",
            "summarize_command",
            "next_commands",
        ] {
            assert!(target.get(key).is_some(), "missing target field {key}");
        }
    }

    #[test]
    fn serialized_repeat_summary_matches_contract_shape() {
        let summary = RepeatRunSummary::new(
            ".re",
            1,
            vec![sample_repeat_attempt(
                1,
                TargetStatus::Findings,
                &[("heap_overflow", 1)],
            )],
            vec![
                "jq . .re/repeat-summary.json".to_string(),
                "jq . .re/run-summary.json".to_string(),
            ],
        );
        let value = serde_json::to_value(summary).unwrap();

        for key in [
            "schema_version",
            "purpose",
            "output_root",
            "requested_attempts",
            "completed_attempts",
            "status_totals",
            "outcome_totals",
            "finding_totals_by_class",
            "first_failure",
            "best_evidence_attempt",
            "escalation_policy",
            "issue_groups",
            "attempts",
            "next_commands",
        ] {
            assert!(value.get(key).is_some(), "missing repeat field {key}");
        }
        assert_eq!(value["escalation_policy"]["policy"], json!("never"));
        assert_eq!(
            value["escalation_policy"]["selected_attempt_count"],
            json!(0)
        );
        assert!(value["issue_groups"].is_array());

        let attempt: &Value = &value["attempts"][0];
        for key in [
            "attempt",
            "target_name",
            "status",
            "outcome",
            "output_root",
            "run_summary",
            "crashpack",
            "findings",
            "evidence_pack",
            "issue_groups",
            "findings_count",
            "findings_by_class",
            "issue_group_count",
            "error",
            "duration_ms",
            "next_commands",
        ] {
            assert!(attempt.get(key).is_some(), "missing attempt field {key}");
        }
    }

    #[test]
    fn schema_file_matches_rust_contract_statuses() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("schemas/observation-run.schema.json");
        let schema: Value = serde_json::from_slice(&std::fs::read(schema_path).unwrap()).unwrap();

        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            json!("1.0")
        );
        assert_eq!(
            schema["properties"]["purpose"]["const"],
            json!("local_runtime_observation")
        );

        let schema_statuses = schema["$defs"]["status"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let rust_statuses = [
            TargetStatus::Clean,
            TargetStatus::Findings,
            TargetStatus::Failed,
            TargetStatus::Timeout,
            TargetStatus::Skipped,
            TargetStatus::ToolUnavailable,
            TargetStatus::NotApplicable,
        ]
        .into_iter()
        .map(|status| status.as_str().to_string())
        .collect::<Vec<_>>();

        assert_eq!(schema_statuses, rust_statuses);
    }

    #[test]
    fn repeat_schema_file_matches_rust_contract() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("schemas/repeat-summary.schema.json");
        let schema: Value = serde_json::from_slice(&std::fs::read(schema_path).unwrap()).unwrap();

        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            json!(REPEAT_SUMMARY_SCHEMA_VERSION)
        );
        assert_eq!(
            schema["properties"]["purpose"]["const"],
            json!(REPEAT_SUMMARY_PURPOSE)
        );

        let schema_statuses = schema["$defs"]["status"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let rust_statuses = [
            TargetStatus::Clean,
            TargetStatus::Findings,
            TargetStatus::Failed,
            TargetStatus::Timeout,
            TargetStatus::Skipped,
            TargetStatus::ToolUnavailable,
            TargetStatus::NotApplicable,
        ]
        .into_iter()
        .map(|status| status.as_str().to_string())
        .collect::<Vec<_>>();
        assert_eq!(schema_statuses, rust_statuses);

        let schema_outcomes = schema["$defs"]["outcome"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let rust_outcomes = [
            RepeatAttemptOutcome::Pass,
            RepeatAttemptOutcome::Finding,
            RepeatAttemptOutcome::Failure,
            RepeatAttemptOutcome::Timeout,
            RepeatAttemptOutcome::Inconclusive,
        ]
        .into_iter()
        .map(|outcome| outcome.as_str().to_string())
        .collect::<Vec<_>>();
        assert_eq!(schema_outcomes, rust_outcomes);
    }
}
