#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"
cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-observe-hit-rate.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
    cat >&2 <<'MSG'
valgrind is required for observe hit-rate evaluation.
Use the supported Docker image or install valgrind on the Linux host.
MSG
    exit 1
fi

printf '[observe-hit-rate] building project fixtures\n'
./scripts/build-project-fixtures.sh

printf '[observe-hit-rate] building rerun release binary\n'
cargo build -q -p rerun --release
runner_path="./target/release/rerun"

report_dir="build/observe-hit-rate"
cases_dir="${report_dir}/cases"
cases_jsonl="${report_dir}/cases.jsonl"
summary_json="${report_dir}/summary.json"
rm -rf "$report_dir"
mkdir -p "$cases_dir"
: >"$cases_jsonl"

run_observe_case() {
    local name="$1"
    local expected_status="$2"
    local expected_class="$3"
    local expected_count="$4"
    local expected_escalation_tool="$5"
    local expected_escalation_status="$6"
    local expected_escalation_class="$7"
    shift 7

    local case_dir="${cases_dir}/${name}"
    local run_log="${case_dir}.log"
    mkdir -p "$(dirname "$case_dir")"

    printf '[observe-hit-rate] running %s\n' "$name"
    if [[ "$expected_status" == "timeout" ]]; then
        if "$runner_path" observe --output "$case_dir" "$@" >"$run_log" 2>&1; then
            printf '[observe-hit-rate] expected timeout case %s to return nonzero\n' "$name" >&2
            exit 1
        fi
    else
        if ! "$runner_path" observe --output "$case_dir" "$@" >"$run_log" 2>&1; then
            printf '\n[observe-hit-rate] observe failed for %s\n' "$name" >&2
            printf '\n--- observe log ---\n' >&2
            tail -n 120 "$run_log" >&2 || true
            exit 1
        fi
    fi

    python3 - "$name" "$case_dir" "$expected_status" "$expected_class" "$expected_count" \
        "$expected_escalation_tool" "$expected_escalation_status" "$expected_escalation_class" "$runner_path" >>"$cases_jsonl" <<'PY'
import json
import pathlib
import subprocess
import sys

name = sys.argv[1]
case_dir = pathlib.Path(sys.argv[2])
expected_status = sys.argv[3]
expected_class = sys.argv[4]
expected_count = int(sys.argv[5])
expected_escalation_tool = sys.argv[6]
expected_escalation_status = sys.argv[7]
expected_escalation_class = sys.argv[8]
runner_path = pathlib.Path(sys.argv[9])
summary_path = case_dir / "run-summary.json"
summary = json.loads(summary_path.read_text())

target = summary["targets"][0]
artifacts = target.get("artifacts") or {}
crashpack = pathlib.Path(artifacts["crashpack"])
findings = json.loads(pathlib.Path(artifacts["findings"]).read_text())
native_findings = [
    finding
    for finding in findings
    if isinstance(finding, dict) and (finding.get("origin") in (None, "ebpf"))
]
tool_findings = [
    finding
    for finding in findings
    if isinstance(finding, dict) and finding.get("origin") not in (None, "ebpf")
]
issue_groups = json.loads(pathlib.Path(artifacts["issue_groups"]).read_text()).get("groups") or []
evidence_pack = json.loads(pathlib.Path(artifacts["evidence_pack"]).read_text())
agent_summary_path = case_dir / "agent-summary.json"
agent_summary = subprocess.check_output(
    [str(runner_path), "summarize", str(crashpack), "--format", "json"],
    text=True,
)
agent_summary_path.write_text(agent_summary)
agent_summary_json = json.loads(agent_summary)

actual_status = target.get("status")
classes = target.get("findings_by_class") or {}
native_classes = {}
for finding in native_findings:
    cls = finding.get("class")
    if cls:
        native_classes[cls] = native_classes.get(cls, 0) + 1
escalations = target.get("escalation") or []

status_outcome = "match" if actual_status == expected_status else "mismatch"
if expected_class == "__none__":
    native_outcome = "tn" if not native_classes and not native_findings else "fp"
else:
    native_outcome = (
        "tp"
        if native_classes.get(expected_class) == expected_count and len(native_findings) == expected_count
        else "fn"
    )

if expected_escalation_tool == "__none__":
    escalation_outcome = "tn" if not escalations else "fp"
    escalation_match = None
else:
    escalation_match = next(
        (
            result
            for result in escalations
            if result.get("tool") == expected_escalation_tool
            and result.get("status") == expected_escalation_status
        ),
        None,
    )
    escalation_detected = (escalation_match or {}).get("findings_detected") or []
    escalation_outcome = (
        "tp"
        if escalation_match
        and (
            expected_escalation_class == "__none__"
            or expected_escalation_class in escalation_detected
        )
        else "fn"
    )

if target.get("issue_group_count") != len(issue_groups):
    raise SystemExit(f"{name}: issue_group_count does not match issue-groups.json")
if (evidence_pack.get("summary") or {}).get("issue_group_count") != len(issue_groups):
    raise SystemExit(f"{name}: evidence-pack issue_group_count does not match issue-groups.json")
if (agent_summary_json.get("summary") or {}).get("issue_group_count") != len(issue_groups):
    raise SystemExit(f"{name}: agent summary issue_group_count does not match issue groups")
if agent_summary_json.get("purpose") != "agent_summary":
    raise SystemExit(f"{name}: summarize output must be agent_summary")
if not target.get("next_commands"):
    raise SystemExit(f"{name}: target missing next_commands")

print(json.dumps({
    "name": name,
    "status": {
        "expected": expected_status,
        "actual": actual_status,
        "outcome": status_outcome,
    },
    "native": {
        "expected_class": None if expected_class == "__none__" else expected_class,
        "expected_count": expected_count,
        "actual_classes": classes,
        "native_classes": native_classes,
        "finding_count": len(native_findings),
        "total_finding_count": len(findings),
        "tool_backed_finding_count": len(tool_findings),
        "outcome": native_outcome,
    },
    "issue_groups": {
        "count": len(issue_groups),
        "fingerprints": [group.get("fingerprint") for group in issue_groups],
    },
    "escalation": {
        "expected_tool": None if expected_escalation_tool == "__none__" else expected_escalation_tool,
        "expected_status": None if expected_escalation_status == "__none__" else expected_escalation_status,
        "expected_class": None if expected_escalation_class == "__none__" else expected_escalation_class,
        "outcome": escalation_outcome,
        "results": escalations,
    },
    "artifacts": {
        "run_summary": str(summary_path),
        "crashpack": str(crashpack),
        "evidence_pack": artifacts.get("evidence_pack"),
        "issue_groups": artifacts.get("issue_groups"),
        "agent_summary": str(agent_summary_path),
    },
    "next_commands": target.get("next_commands"),
}, sort_keys=True))
PY
}

run_observe_case multifile-heap findings heap_overflow 1 valgrind findings heap_overflow \
    build/project-fixtures/multifile-heap/app
run_observe_case clean-multifile clean __none__ 0 __none__ __none__ __none__ \
    build/project-fixtures/clean-multifile/app
run_observe_case args-cwd findings heap_overflow 1 valgrind findings heap_overflow \
    --cwd build/project-fixtures/args-cwd/run build/project-fixtures/args-cwd/app -- trigger payload.bin
run_observe_case multi-binary-healthcheck clean __none__ 0 __none__ __none__ __none__ \
    build/project-fixtures/multi-binary/healthcheck
run_observe_case multi-binary-worker findings heap_overflow 1 valgrind findings heap_overflow \
    build/project-fixtures/multi-binary/worker
run_observe_case shared-lib findings heap_overflow 1 valgrind findings heap_overflow \
    build/project-fixtures/shared-lib/app
run_observe_case valgrind-first findings __none__ 0 valgrind findings use_after_free \
    --deep build/project-fixtures/valgrind-first/app
run_observe_case timeout timeout __none__ 0 __none__ __none__ __none__ \
    --timeout-ms 100 build/project-fixtures/timeout/app

python3 - "$cases_jsonl" "$summary_json" <<'PY'
import json
import pathlib
import sys

cases_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
cases = [json.loads(line) for line in cases_path.read_text().splitlines() if line.strip()]
support_matrix_path = pathlib.Path("docs/support-matrix.json")
support_matrix = json.loads(support_matrix_path.read_text())
support_by_class = {
    entry["class"]: entry
    for entry in support_matrix.get("classes", [])
}

def outcome_totals(key):
    totals = {}
    for case in cases:
        outcome = case[key]["outcome"]
        totals[outcome] = totals.get(outcome, 0) + 1
    return dict(sorted(totals.items()))

status_totals = {}
for case in cases:
    actual_status = case["status"]["actual"]
    status_totals[actual_status] = status_totals.get(actual_status, 0) + 1

def coverage_by_class():
    coverage = {}
    for case in cases:
        native_expected = case["native"].get("expected_class")
        if native_expected:
            entry = coverage.setdefault(native_expected, {
                "class": native_expected,
                "category": (support_by_class.get(native_expected) or {}).get("category"),
                "support": {
                    "native": ((support_by_class.get(native_expected) or {}).get("native") or {}).get("status"),
                    "tools": (support_by_class.get(native_expected) or {}).get("tools") or {},
                },
                "native_cases": [],
                "escalation_cases": [],
            })
            entry["native_cases"].append({
                "name": case["name"],
                "outcome": case["native"]["outcome"],
                "actual_classes": case["native"].get("native_classes") or {},
            })
        escalation_expected = case["escalation"].get("expected_class")
        if escalation_expected:
            entry = coverage.setdefault(escalation_expected, {
                "class": escalation_expected,
                "category": (support_by_class.get(escalation_expected) or {}).get("category"),
                "support": {
                    "native": ((support_by_class.get(escalation_expected) or {}).get("native") or {}).get("status"),
                    "tools": (support_by_class.get(escalation_expected) or {}).get("tools") or {},
                },
                "native_cases": [],
                "escalation_cases": [],
            })
            entry["escalation_cases"].append({
                "name": case["name"],
                "outcome": case["escalation"]["outcome"],
                "expected_tool": case["escalation"].get("expected_tool"),
            })
    return [
        {
            **value,
            "native_case_count": len(value["native_cases"]),
            "escalation_case_count": len(value["escalation_cases"]),
        }
        for _, value in sorted(coverage.items())
    ]

summary = {
    "schema_version": "1.0",
    "purpose": "observe_hit_rate",
    "total_cases": len(cases),
    "support_matrix": str(support_matrix_path),
    "status_totals": dict(sorted(status_totals.items())),
    "status_outcomes": outcome_totals("status"),
    "native_outcomes": outcome_totals("native"),
    "escalation_outcomes": outcome_totals("escalation"),
    "coverage_by_class": coverage_by_class(),
    "total_issue_groups": sum(case["issue_groups"]["count"] for case in cases),
    "cases_jsonl": str(cases_path),
    "cases": cases,
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))

failed = any(case["status"]["outcome"] != "match" for case in cases)
failed = failed or any(case["native"]["outcome"] in {"fp", "fn"} for case in cases)
failed = failed or any(case["escalation"]["outcome"] in {"fp", "fn"} for case in cases)
if failed:
    raise SystemExit(1)
PY

printf '\n[observe-hit-rate] summary written to %s\n' "$summary_json"
printf '[observe-hit-rate] evaluation passed\n'
