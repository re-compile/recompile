#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"
cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-project-fixtures.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[project] building project fixtures\n'
./scripts/build-project-fixtures.sh

printf '[project] building rerun release binary\n'
cargo build -q -p rerun --release
runner_path="./target/release/rerun"
output_root="build/project-smoke"
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
        raise SystemExit(f"{summary_path}: expected no native finding classes, got {classes}")
else:
    if classes.get(expected_class) != expected_count:
        raise SystemExit(f"{summary_path}: missing class {expected_class} count {expected_count}: {classes}")

artifacts = target.get("artifacts") or {}
required = ["crashpack", "findings", "evidence_pack", "analysis", "manifest", "dependencies", "issue_groups"]
for key in required:
    path = pathlib.Path(artifacts.get(key, ""))
    if not path.exists():
        raise SystemExit(f"{summary_path}: artifact {key} missing at {path}")

findings = json.loads(pathlib.Path(artifacts["findings"]).read_text())
evidence_pack = json.loads(pathlib.Path(artifacts["evidence_pack"]).read_text())
dependencies = json.loads(pathlib.Path(artifacts["dependencies"]).read_text())
issue_groups = json.loads(pathlib.Path(artifacts["issue_groups"]).read_text())

groups = issue_groups.get("groups")
if not isinstance(groups, list):
    raise SystemExit(f"{summary_path}: issue groups must be a list")
if target.get("issue_group_count") != len(groups):
    raise SystemExit(f"{summary_path}: issue_group_count does not match issue-groups.json")
if (evidence_pack.get("summary") or {}).get("issue_group_count") != len(groups):
    raise SystemExit(f"{summary_path}: evidence-pack issue_group_count does not match issue-groups.json")
if expected_count == 0 and groups:
    raise SystemExit(f"{summary_path}: expected no native issue groups, got {groups}")
if expected_count > 0:
    group_ids = {group.get("id") for group in groups}
    fingerprints = {group.get("fingerprint") for group in groups}
    for finding in findings:
        if finding.get("fingerprint") not in fingerprints:
            raise SystemExit(f"{summary_path}: finding fingerprint missing from groups: {finding}")
        if finding.get("issue_group_id") not in group_ids:
            raise SystemExit(f"{summary_path}: finding issue_group_id missing from groups: {finding}")

if dependencies.get("purpose") != "binary_dependency_metadata":
    raise SystemExit(f"{summary_path}: missing dependency metadata")
if not isinstance(dependencies.get("dynamic_dependencies"), list):
    raise SystemExit(f"{summary_path}: dynamic_dependencies must be a list")

escalations = target.get("escalation") or []
if expected_escalation_tool == "__none__":
    if escalations:
        raise SystemExit(f"{summary_path}: expected no escalation, got {escalations}")
else:
    match = next((result for result in escalations if result.get("tool") == expected_escalation_tool and result.get("status") == expected_escalation_status), None)
    if match is None:
        raise SystemExit(f"{summary_path}: missing escalation {expected_escalation_tool}/{expected_escalation_status}: {escalations}")
    if expected_escalation_class != "__none__" and expected_escalation_class not in (match.get("findings_detected") or []):
        raise SystemExit(f"{summary_path}: escalation missing class {expected_escalation_class}: {match}")

if not target.get("next_commands"):
    raise SystemExit(f"{summary_path}: missing next_commands")

print(json.dumps({
    "summary": str(summary_path),
    "status": target.get("status"),
    "findings_count": target.get("findings_count"),
    "issue_group_count": target.get("issue_group_count"),
    "classes": classes,
    "escalations": escalations,
}, sort_keys=True))
PY
}

printf '[project] multi-file heap bug\n'
"$runner_path" observe build/project-fixtures/multifile-heap/app --output "$output_root/multifile-heap"
assert_observation "$output_root/multifile-heap/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow

printf '[project] clean multi-file app\n'
"$runner_path" observe build/project-fixtures/clean-multifile/app --output "$output_root/clean-multifile"
assert_observation "$output_root/clean-multifile/run-summary.json" clean __none__ 0

printf '[project] args and cwd-sensitive app\n'
"$runner_path" observe build/project-fixtures/args-cwd/app \
    --cwd build/project-fixtures/args-cwd/run \
    --output "$output_root/args-cwd" \
    -- trigger payload.bin
assert_observation "$output_root/args-cwd/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow

printf '[project] multi-binary clean target\n'
"$runner_path" observe build/project-fixtures/multi-binary/healthcheck --output "$output_root/multi-binary-healthcheck"
assert_observation "$output_root/multi-binary-healthcheck/run-summary.json" clean __none__ 0

printf '[project] multi-binary finding target\n'
"$runner_path" observe build/project-fixtures/multi-binary/worker --output "$output_root/multi-binary-worker"
assert_observation "$output_root/multi-binary-worker/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow

printf '[project] shared-library target\n'
"$runner_path" observe build/project-fixtures/shared-lib/app --output "$output_root/shared-lib"
assert_observation "$output_root/shared-lib/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow
python3 - "$output_root/shared-lib/targets/app/dependencies.json" <<'PY'
import json
import pathlib
import sys

dependencies = json.loads(pathlib.Path(sys.argv[1]).read_text())
names = {dep.get("name") for dep in dependencies.get("dynamic_dependencies") or []}
if "libprojectbug.so" not in names:
    raise SystemExit(f"shared library dependency missing from dynamic_dependencies: {names}")
print(json.dumps({"shared_dependency": "libprojectbug.so"}, sort_keys=True))
PY
test -f "$output_root/shared-lib/targets/app/bins/lib/libprojectbug.so"

printf '[project] Valgrind-first target\n'
"$runner_path" observe --deep build/project-fixtures/valgrind-first/app --output "$output_root/valgrind-first"
assert_observation "$output_root/valgrind-first/run-summary.json" findings __none__ 0 valgrind findings use_after_free

printf '[project] timeout target\n'
if "$runner_path" observe build/project-fixtures/timeout/app --timeout-ms 100 --output "$output_root/timeout"; then
    printf '[project] expected timeout observe command to return nonzero\n' >&2
    exit 1
fi
assert_observation "$output_root/timeout/run-summary.json" timeout __none__ 0

printf '\n[project] project fixture smoke passed\n'
