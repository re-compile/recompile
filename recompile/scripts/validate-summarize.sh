#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-summarize.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[summarize] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[summarize] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

output_root="build/summarize-smoke"
rm -rf "$output_root"
mkdir -p "$output_root"

run_native_case() {
    local name="$1"
    local binary_path="${2:-build/user-samples/${name}}"
    local output_dir="${output_root}/${name}"
    local log_path="${output_dir}.log"
    if ! "$runner_path" run --native "$binary_path" --output "$output_dir" >"$log_path" 2>&1; then
        printf '\n[summarize] native run failed for %s\n' "$name" >&2
        tail -n 80 "$log_path" >&2 || true
        exit 1
    fi
}

assert_summary() {
    local output_dir="$1"
    local expected_total="$2"
    local expected_class="$3"
    local expected_escalation_class="$4"
    local expect_linked_finding="${5:-0}"
    local summary_path="${output_dir}/agent-summary.json"

    "$runner_path" summarize "$output_dir" --format json >"$summary_path"

    python3 - "$summary_path" "$expected_total" "$expected_class" "$expected_escalation_class" "$expect_linked_finding" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
expected_total = int(sys.argv[2])
expected_class = sys.argv[3]
expected_escalation_class = sys.argv[4]
expect_linked_finding = sys.argv[5] == "1"

summary = json.loads(summary_path.read_text())
if summary.get("purpose") != "agent_summary":
    raise SystemExit(f"{summary_path}: purpose must be agent_summary")

total = (summary.get("summary") or {}).get("total_findings")
if total != expected_total:
    raise SystemExit(f"{summary_path}: expected total_findings={expected_total}, got {total}")

if expected_class != "__none__":
    class_counts = (summary.get("summary") or {}).get("class_counts") or {}
    if class_counts.get(expected_class) != expected_total:
        raise SystemExit(f"{summary_path}: missing class count for {expected_class}")

issue_group_count = (summary.get("summary") or {}).get("issue_group_count")
issue_groups = summary.get("issue_groups") or []
if expected_total == 0:
    if issue_group_count not in (0, None):
        raise SystemExit(f"{summary_path}: expected zero issue groups, got {issue_group_count}")
else:
    if issue_group_count != len(issue_groups) or issue_group_count < 1:
        raise SystemExit(
            f"{summary_path}: issue_group_count={issue_group_count} does not match issue_groups={issue_groups}"
        )

if expected_escalation_class != "__none__":
    detected = (summary.get("summary") or {}).get("escalation_detected_classes") or []
    if expected_escalation_class not in detected:
        raise SystemExit(f"{summary_path}: missing escalation class {expected_escalation_class}")
    if (summary.get("summary") or {}).get("escalation_total_runs") != 1:
        raise SystemExit(f"{summary_path}: expected one escalation run")

if expect_linked_finding:
    findings = summary.get("findings") or []
    if not findings:
        raise SystemExit(f"{summary_path}: expected at least one finding")
    if not findings[0].get("fingerprint") or not findings[0].get("issue_group_id"):
        raise SystemExit(f"{summary_path}: expected finding fingerprint and issue_group_id")
    linked = findings[0].get("escalation_result")
    if not isinstance(linked, dict):
        raise SystemExit(f"{summary_path}: expected linked escalation_result")
    if linked.get("finding_id") != findings[0].get("id"):
        raise SystemExit(f"{summary_path}: linked finding_id does not match finding id")
    if linked.get("confirmed") is not True:
        raise SystemExit(f"{summary_path}: linked escalation_result must be confirmed")

print(json.dumps({
    "summary": str(summary_path),
    "total_findings": total,
    "expected_class": None if expected_class == "__none__" else expected_class,
    "expected_escalation_class": None if expected_escalation_class == "__none__" else expected_escalation_class,
}))
PY
}

printf '[summarize] finding crashpack with linked Valgrind confirmation\n'
run_native_case copy_overrun_case
"$runner_path" escalate "${output_root}/copy_overrun_case" --tool valgrind
assert_summary "${output_root}/copy_overrun_case" 1 heap_overflow heap_overflow 1

printf '[summarize] clean crashpack\n'
run_native_case clean_malloc_free
assert_summary "${output_root}/clean_malloc_free" 0 __none__ __none__

printf '[summarize] Valgrind binary-scan crashpack\n'
run_native_case use_after_free_case
"$runner_path" escalate "${output_root}/use_after_free_case" --tool valgrind --scan-binary
assert_summary "${output_root}/use_after_free_case" 0 __none__ use_after_free

printf '[summarize] ASan binary-scan crashpack\n'
run_native_case asan_use_after_free_case build/user-samples-asan/use_after_free_case
"$runner_path" escalate "${output_root}/asan_use_after_free_case" --tool asan --scan-binary
assert_summary "${output_root}/asan_use_after_free_case" 0 __none__ use_after_free

printf '\n[summarize] agent summary smoke passed\n'
