#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-observe.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[observe] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[observe] building rerun release binary\n'
cargo build -q -p rerun --release
runner_path="./target/release/rerun"
output_root="build/observe-smoke"
rm -rf "$output_root"

assert_observation() {
    local summary_path="$1"
    local expected_status="$2"
    local expected_class="$3"
    local expected_count="$4"
    local expected_escalation_tool="${5:-__none__}"
    local expected_escalation_status="${6:-__none__}"
    local expected_escalation_class="${7:-__none__}"
    python3 - "$summary_path" "$expected_status" "$expected_class" "$expected_count" \
        "$expected_escalation_tool" "$expected_escalation_status" "$expected_escalation_class" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
expected_status = sys.argv[2]
expected_class = sys.argv[3]
expected_count = int(sys.argv[4])
expected_escalation_tool = sys.argv[5]
expected_escalation_status = sys.argv[6]
expected_escalation_class = sys.argv[7]
summary = json.loads(summary_path.read_text())

if summary.get("schema_version") != "1.0":
    raise SystemExit(f"{summary_path}: schema_version must be 1.0")
if summary.get("purpose") != "local_runtime_observation":
    raise SystemExit(f"{summary_path}: unexpected purpose {summary.get('purpose')}")
if summary.get("target_count") != 1:
    raise SystemExit(f"{summary_path}: expected one target")

target = summary["targets"][0]
if target.get("status") != expected_status:
    raise SystemExit(f"{summary_path}: expected status {expected_status}, got {target.get('status')}")
if target.get("findings_count") != expected_count:
    raise SystemExit(f"{summary_path}: expected findings_count {expected_count}, got {target.get('findings_count')}")

classes = target.get("findings_by_class") or {}
if expected_class == "__none__":
    if classes:
        raise SystemExit(f"{summary_path}: expected no finding classes, got {classes}")
else:
    if classes.get(expected_class) != expected_count:
        raise SystemExit(f"{summary_path}: missing class {expected_class} count {expected_count}: {classes}")

artifacts = target.get("artifacts") or {}
for key in ["crashpack", "findings", "evidence_pack", "analysis", "manifest", "dependencies", "issue_groups"]:
    path = pathlib.Path(artifacts.get(key, ""))
    if not path.exists():
        raise SystemExit(f"{summary_path}: artifact {key} missing at {path}")

dependencies_path = pathlib.Path(artifacts["dependencies"])
dependencies = json.loads(dependencies_path.read_text())
if dependencies.get("schema_version") != "1.0":
    raise SystemExit(f"{dependencies_path}: schema_version must be 1.0")
if dependencies.get("purpose") != "binary_dependency_metadata":
    raise SystemExit(f"{dependencies_path}: unexpected purpose {dependencies.get('purpose')}")
for tool_name in ["readelf", "ldd"]:
    tool = dependencies.get(tool_name) or {}
    if tool.get("tool") != tool_name:
        raise SystemExit(f"{dependencies_path}: missing tool identity for {tool_name}: {tool}")
    if tool.get("status") not in ["available", "unavailable", "failed", "not_applicable"]:
        raise SystemExit(f"{dependencies_path}: invalid {tool_name} status: {tool}")
if not isinstance(dependencies.get("elf"), dict):
    raise SystemExit(f"{dependencies_path}: missing elf metadata")
if not isinstance(dependencies.get("dynamic_dependencies"), list):
    raise SystemExit(f"{dependencies_path}: missing dynamic dependency list")

findings_path = pathlib.Path(artifacts["findings"])
findings = json.loads(findings_path.read_text())
issue_groups_path = pathlib.Path(artifacts["issue_groups"])
issue_groups = json.loads(issue_groups_path.read_text())
if issue_groups.get("schema_version") != "1.0":
    raise SystemExit(f"{issue_groups_path}: schema_version must be 1.0")
if issue_groups.get("purpose") != "issue_groups":
    raise SystemExit(f"{issue_groups_path}: unexpected purpose {issue_groups.get('purpose')}")
groups = issue_groups.get("groups")
if not isinstance(groups, list):
    raise SystemExit(f"{issue_groups_path}: groups must be a list")
if target.get("issue_group_count") != len(groups):
    raise SystemExit(
        f"{summary_path}: issue_group_count={target.get('issue_group_count')} does not match {len(groups)} groups"
    )
if expected_count == 0:
    if groups:
        raise SystemExit(f"{issue_groups_path}: expected no issue groups, got {groups}")
else:
    if not groups:
        raise SystemExit(f"{issue_groups_path}: expected at least one issue group")
    group_ids = {group.get("id") for group in groups}
    fingerprints = {group.get("fingerprint") for group in groups}
    for finding in findings:
        if not finding.get("fingerprint") or finding.get("fingerprint") not in fingerprints:
            raise SystemExit(f"{findings_path}: finding has missing or unknown fingerprint: {finding}")
        if not finding.get("issue_group_id") or finding.get("issue_group_id") not in group_ids:
            raise SystemExit(f"{findings_path}: finding has missing or unknown issue_group_id: {finding}")

status_totals = summary.get("status_totals") or {}
if status_totals.get(expected_status) != 1:
    raise SystemExit(f"{summary_path}: status_totals missing {expected_status}: {status_totals}")

escalations = target.get("escalation") or []
if expected_escalation_tool == "__none__":
    if escalations:
        raise SystemExit(f"{summary_path}: expected no escalation results, got {escalations}")
else:
    match = None
    for result in escalations:
        if result.get("tool") == expected_escalation_tool and result.get("status") == expected_escalation_status:
            match = result
            break
    if match is None:
        raise SystemExit(
            f"{summary_path}: missing escalation {expected_escalation_tool}/{expected_escalation_status}: {escalations}"
        )
    if expected_escalation_class != "__none__":
        detected = match.get("findings_detected") or []
        if expected_escalation_class not in detected:
            raise SystemExit(f"{summary_path}: escalation missing class {expected_escalation_class}: {match}")
        artifact = match.get("artifact_path")
        if not artifact or not pathlib.Path(artifact).exists():
            raise SystemExit(f"{summary_path}: escalation artifact missing: {artifact}")
    totals = ((summary.get("escalation_totals_by_tool") or {}).get(expected_escalation_tool) or {})
    if totals.get(expected_escalation_status, 0) < 1:
        raise SystemExit(f"{summary_path}: escalation totals missing {expected_escalation_tool}/{expected_escalation_status}: {totals}")

print(json.dumps({
    "summary": str(summary_path),
    "status": target.get("status"),
    "findings_count": target.get("findings_count"),
    "classes": classes,
    "escalations": escalations,
}, sort_keys=True))
PY
}

printf '[observe] clean binary\n'
"$runner_path" observe build/user-samples/clean_malloc_free --output "$output_root/clean_malloc_free"
assert_observation "$output_root/clean_malloc_free/run-summary.json" clean __none__ 0

printf '[observe] finding binary with default confirmation\n'
"$runner_path" observe build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case"
assert_observation "$output_root/copy_overrun_case/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow

printf '[observe] repeated finding binary keeps stable fingerprint\n'
"$runner_path" observe build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case_repeat"
assert_observation "$output_root/copy_overrun_case_repeat/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow
python3 - "$output_root/copy_overrun_case/targets/copy_overrun_case/issue-groups.json" \
    "$output_root/copy_overrun_case_repeat/targets/copy_overrun_case/issue-groups.json" <<'PY'
import json
import pathlib
import sys

left = json.loads(pathlib.Path(sys.argv[1]).read_text())
right = json.loads(pathlib.Path(sys.argv[2]).read_text())
left_fingerprints = [group.get("fingerprint") for group in left.get("groups") or []]
right_fingerprints = [group.get("fingerprint") for group in right.get("groups") or []]
if left_fingerprints != right_fingerprints:
    raise SystemExit(f"fingerprints are not stable: {left_fingerprints} != {right_fingerprints}")
print(json.dumps({"stable_fingerprints": left_fingerprints}, sort_keys=True))
PY

printf '[observe] deep Valgrind-first binary\n'
"$runner_path" observe --deep build/user-samples/use_after_free_case --output "$output_root/use_after_free_case"
assert_observation "$output_root/use_after_free_case/run-summary.json" findings __none__ 0 valgrind findings use_after_free

printf '[observe] deep non-ASan binary records ASan not-applicable\n'
python3 - "$output_root/use_after_free_case/run-summary.json" <<'PY'
import json
import pathlib
import sys
summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
escalations = summary["targets"][0].get("escalation") or []
if not any(result.get("tool") == "asan" and result.get("status") == "not_applicable" for result in escalations):
    raise SystemExit(f"missing ASan not_applicable escalation: {escalations}")
print(json.dumps({"asan_not_applicable": True}, sort_keys=True))
PY

printf '\n[observe] observe smoke passed\n'
