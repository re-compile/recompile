#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"
cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-repeat-fixtures.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[repeat-fixtures] building project fixtures\n'
./scripts/build-project-fixtures.sh

printf '[repeat-fixtures] building rerun release binary\n'
cargo build -q -p rerun --release
runner_path="./target/release/rerun"
output_root="build/repeat-fixture-smoke"
rm -rf "$output_root"
mkdir -p "$output_root"

run_repeat_case() {
    local name="$1"
    local repeat="$2"
    local expect_error="$3"
    shift 3
    local case_dir="$output_root/$name"
    local run_log="$case_dir.log"

    printf '[repeat-fixtures] running %s\n' "$name"
    if "$runner_path" observe --native-only --repeat "$repeat" --output "$case_dir" "$@" >"$run_log" 2>&1; then
        if [[ "$expect_error" == "yes" ]]; then
            printf '\n[repeat-fixtures] expected observe to report error statuses for %s\n' "$name" >&2
            printf '\n--- observe log ---\n' >&2
            tail -n 160 "$run_log" >&2 || true
            exit 1
        fi
    elif [[ "$expect_error" != "yes" ]]; then
        printf '\n[repeat-fixtures] observe failed for %s\n' "$name" >&2
        printf '\n--- observe log ---\n' >&2
        tail -n 160 "$run_log" >&2 || true
        exit 1
    fi
}

run_repeat_case repeat-clean 3 no build/project-fixtures/repeat-clean/repeat_clean
run_repeat_case repeat-failing 3 no build/project-fixtures/repeat-failing/repeat_failing

printf '0\n' > build/project-fixtures/repeat-flaky/run/attempt-state.txt
run_repeat_case repeat-flaky 3 no \
    --cwd build/project-fixtures/repeat-flaky/run \
    build/project-fixtures/repeat-flaky/repeat_flaky

run_repeat_case repeat-timeout 2 yes \
    --timeout-ms 100 \
    build/project-fixtures/repeat-timeout/repeat_timeout

python3 - "$output_root" "build/project-fixtures/repeat-flaky/run/attempt-state.txt" <<'PY'
import json
import pathlib
import sys

output_root = pathlib.Path(sys.argv[1])
flaky_state_path = pathlib.Path(sys.argv[2])

cases = [
    {
        "name": "repeat-clean",
        "binary": "repeat_clean",
        "requested_attempts": 3,
        "statuses": ["clean", "clean", "clean"],
        "outcomes": ["pass", "pass", "pass"],
        "classes": [{}, {}, {}],
        "first_failure": None,
        "best_evidence": None,
    },
    {
        "name": "repeat-failing",
        "binary": "repeat_failing",
        "requested_attempts": 3,
        "statuses": ["findings", "findings", "findings"],
        "outcomes": ["finding", "finding", "finding"],
        "classes": [{"heap_overflow": 1}, {"heap_overflow": 1}, {"heap_overflow": 1}],
        "first_failure": 1,
        "best_evidence": 1,
    },
    {
        "name": "repeat-flaky",
        "binary": "repeat_flaky",
        "requested_attempts": 3,
        "statuses": ["clean", "findings", "clean"],
        "outcomes": ["pass", "finding", "pass"],
        "classes": [{}, {"heap_overflow": 1}, {}],
        "first_failure": 2,
        "best_evidence": 2,
    },
    {
        "name": "repeat-timeout",
        "binary": "repeat_timeout",
        "requested_attempts": 2,
        "statuses": ["timeout", "timeout"],
        "outcomes": ["timeout", "timeout"],
        "classes": [{}, {}],
        "first_failure": 1,
        "best_evidence": 1,
    },
]


def count_values(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def merge_class_counts(class_maps):
    counts = {}
    for class_map in class_maps:
        for name, count in class_map.items():
            counts[name] = counts.get(name, 0) + count
    return dict(sorted(counts.items()))


def assert_artifact(path_text, label):
    path = pathlib.Path(path_text or "")
    if not path.exists():
        raise SystemExit(f"{label}: missing artifact at {path}")
    return path


def assert_selection(summary, field, expected_attempt):
    selection = summary.get(field)
    if expected_attempt is None:
        if selection is not None:
            raise SystemExit(f"{summary['output_root']}: expected null {field}, got {selection}")
        return
    if not isinstance(selection, dict):
        raise SystemExit(f"{summary['output_root']}: expected {field} object, got {selection}")
    if selection.get("attempt") != expected_attempt:
        raise SystemExit(
            f"{summary['output_root']}: expected {field} attempt {expected_attempt}, got {selection}"
        )
    if not selection.get("crashpack") or not pathlib.Path(selection["crashpack"]).exists():
        raise SystemExit(f"{summary['output_root']}: {field} crashpack missing: {selection}")


results = []
for case in cases:
    case_dir = output_root / case["name"]
    repeat_summary_path = case_dir / "repeat-summary.json"
    run_summary_path = case_dir / "run-summary.json"
    repeat_summary = json.loads(repeat_summary_path.read_text())
    run_summary = json.loads(run_summary_path.read_text())

    if repeat_summary.get("purpose") != "repeat_observation_summary":
        raise SystemExit(f"{repeat_summary_path}: unexpected purpose")
    if repeat_summary.get("requested_attempts") != case["requested_attempts"]:
        raise SystemExit(f"{repeat_summary_path}: requested_attempts mismatch")
    if repeat_summary.get("completed_attempts") != case["requested_attempts"]:
        raise SystemExit(f"{repeat_summary_path}: completed_attempts mismatch")
    if run_summary.get("target_count") != case["requested_attempts"]:
        raise SystemExit(f"{run_summary_path}: target_count mismatch")

    expected_status_totals = count_values(case["statuses"])
    expected_outcome_totals = count_values(case["outcomes"])
    expected_class_totals = merge_class_counts(case["classes"])
    if repeat_summary.get("status_totals") != expected_status_totals:
        raise SystemExit(
            f"{repeat_summary_path}: expected status_totals {expected_status_totals}, "
            f"got {repeat_summary.get('status_totals')}"
        )
    if repeat_summary.get("outcome_totals") != expected_outcome_totals:
        raise SystemExit(
            f"{repeat_summary_path}: expected outcome_totals {expected_outcome_totals}, "
            f"got {repeat_summary.get('outcome_totals')}"
        )
    if repeat_summary.get("finding_totals_by_class") != expected_class_totals:
        raise SystemExit(
            f"{repeat_summary_path}: expected class totals {expected_class_totals}, "
            f"got {repeat_summary.get('finding_totals_by_class')}"
        )

    assert_selection(repeat_summary, "first_failure", case["first_failure"])
    assert_selection(repeat_summary, "best_evidence_attempt", case["best_evidence"])

    attempts = repeat_summary.get("attempts") or []
    if len(attempts) != case["requested_attempts"]:
        raise SystemExit(f"{repeat_summary_path}: attempt count mismatch")
    if len(run_summary.get("targets") or []) != case["requested_attempts"]:
        raise SystemExit(f"{run_summary_path}: aggregate target count mismatch")

    for index, attempt in enumerate(attempts, start=1):
        expected_name = f"attempt-{index:04}-{case['binary']}"
        if attempt.get("attempt") != index:
            raise SystemExit(f"{repeat_summary_path}: attempt index mismatch: {attempt}")
        if attempt.get("target_name") != expected_name:
            raise SystemExit(f"{repeat_summary_path}: expected {expected_name}, got {attempt}")
        if attempt.get("status") != case["statuses"][index - 1]:
            raise SystemExit(f"{repeat_summary_path}: status mismatch for attempt {index}: {attempt}")
        if attempt.get("outcome") != case["outcomes"][index - 1]:
            raise SystemExit(f"{repeat_summary_path}: outcome mismatch for attempt {index}: {attempt}")
        if attempt.get("findings_by_class") != case["classes"][index - 1]:
            raise SystemExit(f"{repeat_summary_path}: classes mismatch for attempt {index}: {attempt}")
        expected_finding_count = sum(case["classes"][index - 1].values())
        if attempt.get("findings_count") != expected_finding_count:
            raise SystemExit(f"{repeat_summary_path}: findings_count mismatch for attempt {index}")
        if attempt.get("status") == "timeout" and attempt.get("error") != "target timed out":
            raise SystemExit(f"{repeat_summary_path}: timeout attempt missing timeout error: {attempt}")
        if attempt.get("status") == "clean" and attempt.get("issue_group_count") != 0:
            raise SystemExit(f"{repeat_summary_path}: clean attempt should have no issue groups")
        if expected_finding_count > 0 and attempt.get("issue_group_count") < 1:
            raise SystemExit(f"{repeat_summary_path}: finding attempt missing issue group")

        attempt_summary_path = assert_artifact(attempt.get("run_summary"), f"{case['name']} run_summary")
        assert_artifact(attempt.get("crashpack"), f"{case['name']} crashpack")
        assert_artifact(attempt.get("findings"), f"{case['name']} findings")
        assert_artifact(attempt.get("evidence_pack"), f"{case['name']} evidence_pack")
        assert_artifact(attempt.get("issue_groups"), f"{case['name']} issue_groups")

        attempt_summary = json.loads(attempt_summary_path.read_text())
        target = attempt_summary["targets"][0]
        if target.get("status") != attempt.get("status"):
            raise SystemExit(f"{attempt_summary_path}: target status mismatch")
        if target.get("findings_by_class") != attempt.get("findings_by_class"):
            raise SystemExit(f"{attempt_summary_path}: target classes mismatch")

    if not any("repeat-summary.json" in command for command in repeat_summary.get("next_commands") or []):
        raise SystemExit(f"{repeat_summary_path}: next_commands should include repeat-summary.json")

    results.append({
        "name": case["name"],
        "status_totals": repeat_summary.get("status_totals"),
        "outcome_totals": repeat_summary.get("outcome_totals"),
        "finding_totals_by_class": repeat_summary.get("finding_totals_by_class"),
        "first_failure": None if case["first_failure"] is None else repeat_summary["first_failure"]["attempt"],
        "best_evidence": None if case["best_evidence"] is None else repeat_summary["best_evidence_attempt"]["attempt"],
    })

if flaky_state_path.read_text().strip() != "3":
    raise SystemExit(f"{flaky_state_path}: expected deterministic flaky state to finish at 3")

print(json.dumps({
    "schema_version": "1.0",
    "purpose": "repeat_fixture_smoke",
    "case_count": len(results),
    "cases": results,
}, indent=2))
PY

printf '\n[repeat-fixtures] repeat fixture smoke passed\n'
