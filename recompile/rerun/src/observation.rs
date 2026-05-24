//! Phase 4 observation-run contract.
//!
//! This module defines the stable JSON shape that `rerun observe` will write.
//! It intentionally contains no runner behavior; execution wiring lands in a
//! later Phase 4 slice.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OBSERVATION_RUN_SCHEMA_VERSION: &str = "1.0";
pub const OBSERVATION_RUN_PURPOSE: &str = "local_runtime_observation";

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

fn status_totals(targets: &[ObservationTargetSummary]) -> BTreeMap<String, u64> {
    let mut totals = BTreeMap::new();
    for target in targets {
        *totals
            .entry(target.status.as_str().to_string())
            .or_insert(0) += 1;
    }
    totals
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
}
