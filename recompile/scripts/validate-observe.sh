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

printf '[observe] opt-in repeated clean binary\n'
"$runner_path" observe --native-only --repeat 2 build/user-samples/clean_malloc_free --output "$output_root/clean_malloc_free_repeat"
python3 - "$output_root/clean_malloc_free_repeat/run-summary.json" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
summary = json.loads(summary_path.read_text())
repeat_summary_path = summary_path.parent / "repeat-summary.json"
if not repeat_summary_path.exists():
    raise SystemExit(f"{summary_path}: missing repeat summary {repeat_summary_path}")
repeat_summary = json.loads(repeat_summary_path.read_text())
if summary.get("target_count") != 2:
    raise SystemExit(f"{summary_path}: expected two repeated targets, got {summary.get('target_count')}")
if (summary.get("status_totals") or {}).get("clean") != 2:
    raise SystemExit(f"{summary_path}: expected two clean attempts, got {summary.get('status_totals')}")
if repeat_summary.get("schema_version") != "1.0":
    raise SystemExit(f"{repeat_summary_path}: schema_version must be 1.0")
if repeat_summary.get("purpose") != "repeat_observation_summary":
    raise SystemExit(f"{repeat_summary_path}: unexpected purpose {repeat_summary.get('purpose')}")
if repeat_summary.get("requested_attempts") != 2 or repeat_summary.get("completed_attempts") != 2:
    raise SystemExit(f"{repeat_summary_path}: unexpected attempt counts {repeat_summary}")
if (repeat_summary.get("status_totals") or {}).get("clean") != 2:
    raise SystemExit(f"{repeat_summary_path}: expected two clean statuses, got {repeat_summary.get('status_totals')}")
if (repeat_summary.get("outcome_totals") or {}).get("pass") != 2:
    raise SystemExit(f"{repeat_summary_path}: expected two pass outcomes, got {repeat_summary.get('outcome_totals')}")
if repeat_summary.get("first_failure") is not None:
    raise SystemExit(f"{repeat_summary_path}: expected null first_failure for clean repeat")
if repeat_summary.get("best_evidence_attempt") is not None:
    raise SystemExit(f"{repeat_summary_path}: expected null best_evidence_attempt for clean repeat")
expected_names = ["attempt-0001-clean_malloc_free", "attempt-0002-clean_malloc_free"]
actual_names = [target.get("name") for target in summary.get("targets") or []]
if actual_names != expected_names:
    raise SystemExit(f"{summary_path}: unexpected repeated target names {actual_names}")
attempts = repeat_summary.get("attempts") or []
if [attempt.get("target_name") for attempt in attempts] != expected_names:
    raise SystemExit(f"{repeat_summary_path}: unexpected attempt names {attempts}")
for index, target in enumerate(summary.get("targets") or [], start=1):
    attempt_summary = summary_path.parent / "attempts" / f"{index:04}" / "run-summary.json"
    if not attempt_summary.exists():
        raise SystemExit(f"{summary_path}: missing attempt summary {attempt_summary}")
    crashpack = pathlib.Path((target.get("artifacts") or {}).get("crashpack", ""))
    if f"attempts/{index:04}/targets/clean_malloc_free" not in crashpack.as_posix():
        raise SystemExit(f"{summary_path}: target crashpack is not attempt-scoped: {crashpack}")
    repeat_attempt = attempts[index - 1]
    if pathlib.Path(repeat_attempt.get("run_summary", "")) != attempt_summary:
        raise SystemExit(f"{repeat_summary_path}: attempt run_summary mismatch {repeat_attempt}")
    for key in ["crashpack", "findings", "evidence_pack", "issue_groups"]:
        path = pathlib.Path(repeat_attempt.get(key, ""))
        if not path.exists():
            raise SystemExit(f"{repeat_summary_path}: attempt {key} missing at {path}")
if not any("repeat-summary.json" in command for command in repeat_summary.get("next_commands") or []):
    raise SystemExit(f"{repeat_summary_path}: next_commands should include repeat-summary.json")
print(json.dumps({
    "summary": str(summary_path),
    "repeat_summary": str(repeat_summary_path),
    "target_count": summary.get("target_count"),
    "status_totals": summary.get("status_totals"),
    "outcome_totals": repeat_summary.get("outcome_totals"),
    "targets": actual_names,
}, sort_keys=True))
PY

printf '[observe] repeat deep defaults to first-failure policy\n'
"$runner_path" observe --deep --repeat 2 build/user-samples/clean_malloc_free --output "$output_root/repeat_deep_clean"
python3 - "$output_root/repeat_deep_clean/repeat-summary.json" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
summary = json.loads(summary_path.read_text())
policy = summary.get("escalation_policy") or {}
if policy.get("policy") != "first-failure" or policy.get("deep") is not True:
    raise SystemExit(f"{summary_path}: repeat deep should default to first-failure: {policy}")
if policy.get("selected_attempt_count") != 0 or policy.get("selected_attempts") != []:
    raise SystemExit(f"{summary_path}: clean first-failure repeat should not run escalations: {policy}")
for attempt in summary.get("attempts") or []:
    run_summary = json.loads(pathlib.Path(attempt["run_summary"]).read_text())
    target = run_summary["targets"][0]
    if target.get("escalation"):
        raise SystemExit(f"{summary_path}: clean first-failure attempt unexpectedly escalated: {target}")
print(json.dumps({
    "repeat_summary": str(summary_path),
    "policy": policy.get("policy"),
    "selected_attempt_count": policy.get("selected_attempt_count"),
}, sort_keys=True))
PY

printf '[observe] signal-only crash evidence\n'
"$runner_path" observe build/user-samples/crash_segv_case --output "$output_root/crash_segv_case"
assert_observation "$output_root/crash_segv_case/run-summary.json" findings unclassified_crash 1 gdb findings unclassified_crash
python3 - "$output_root/crash_segv_case/run-summary.json" "$runner_path" <<'PY'
import json
import pathlib
import subprocess
import sys

summary_path = pathlib.Path(sys.argv[1])
runner_path = pathlib.Path(sys.argv[2])
summary = json.loads(summary_path.read_text())
target = summary["targets"][0]
if target["exit"].get("signal") != 11 or not target["exit"].get("crashed"):
    raise SystemExit(f"{summary_path}: expected SIGSEGV crashed exit, got {target['exit']}")
crashpack = pathlib.Path(target["artifacts"]["crashpack"])
findings = json.loads(pathlib.Path(target["artifacts"]["findings"]).read_text())
finding = findings[0]
crash = ((finding.get("evidence") or {}).get("crash") or {})
if crash.get("signal_name") != "SIGSEGV":
    raise SystemExit(f"{summary_path}: missing SIGSEGV crash evidence: {crash}")
crash_stack = (((finding.get("evidence") or {}).get("stacks") or {}).get("crash") or [])
if not crash_stack:
    raise SystemExit(f"{summary_path}: missing GDB crash stack: {finding}")
gdb_tool = (((finding.get("evidence") or {}).get("tool") or {}).get("gdb") or {})
if gdb_tool.get("signal_name") != "SIGSEGV":
    raise SystemExit(f"{summary_path}: missing GDB signal evidence: {gdb_tool}")
for key in ["stdout_path", "stderr_path", "console_log_path"]:
    path = pathlib.Path(crash.get(key, ""))
    if not path.exists():
        raise SystemExit(f"{summary_path}: crash evidence {key} missing at {path}")
if "about to segfault" not in pathlib.Path(crash["stdout_path"]).read_text():
    raise SystemExit(f"{summary_path}: target stdout was not captured")
agent_summary = json.loads(subprocess.check_output(
    [str(runner_path), "summarize", str(crashpack), "--format", "json"],
    text=True,
))
agent_finding = (agent_summary.get("findings") or [])[0]
if agent_finding.get("operation") != "crash_observed":
    raise SystemExit(f"{summary_path}: summarize missing crash_observed operation: {agent_finding}")
if (agent_finding.get("crash") or {}).get("signal_name") != "SIGSEGV":
    raise SystemExit(f"{summary_path}: summarize missing crash evidence: {agent_finding}")
if not (((agent_finding.get("stacks") or {}).get("crash") or [])):
    raise SystemExit(f"{summary_path}: summarize missing GDB crash stack: {agent_finding}")
print(json.dumps({
    "crash_class": finding.get("class"),
    "signal": crash.get("signal_name"),
    "gdb_frame": crash_stack[0],
    "stdout": crash.get("stdout_path"),
}, sort_keys=True))
PY

printf '[observe] finding binary with default confirmation\n'
"$runner_path" observe build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case"
assert_observation "$output_root/copy_overrun_case/run-summary.json" findings heap_overflow 1 valgrind findings heap_overflow

printf '[observe] tool timeout budget preserves native finding\n'
"$runner_path" observe --valgrind-timeout-ms 1 build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case_tool_timeout"
python3 - "$output_root/copy_overrun_case_tool_timeout/run-summary.json" \
    "$output_root/copy_overrun_case_tool_timeout/targets/copy_overrun_case/escalations/results.json" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = json.loads(pathlib.Path(sys.argv[2]).read_text())
target = summary["targets"][0]
if target.get("status") != "findings" or target.get("findings_by_class", {}).get("heap_overflow") != 1:
    raise SystemExit(f"native finding was not preserved under tool timeout: {target}")
match = next((item for item in target.get("escalation") or [] if item.get("tool") == "valgrind"), None)
if not match or match.get("status") != "timeout" or match.get("timeout_ms") != 1:
    raise SystemExit(f"missing timeout escalation summary: {target.get('escalation')}")
raw = next((item for item in results if item.get("tool") == "valgrind"), None)
if not raw or raw.get("status") != "timeout" or raw.get("timeout_ms") != 1:
    raise SystemExit(f"missing raw timeout result: {results}")
stderr_path = raw.get("stderr_path")
if not stderr_path or not pathlib.Path(stderr_path).exists():
    raise SystemExit(f"timeout stderr artifact missing: {raw}")
print(json.dumps({
    "status": target.get("status"),
    "tool": match.get("tool"),
    "tool_status": match.get("status"),
    "timeout_ms": match.get("timeout_ms"),
}, sort_keys=True))
PY

printf '[observe] opt-in repeated finding binary writes repeat summary\n'
"$runner_path" observe --native-only --repeat 2 build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case_native_repeat"
python3 - "$output_root/copy_overrun_case_native_repeat/repeat-summary.json" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
summary = json.loads(summary_path.read_text())
if summary.get("purpose") != "repeat_observation_summary":
    raise SystemExit(f"{summary_path}: unexpected purpose {summary.get('purpose')}")
if summary.get("requested_attempts") != 2 or summary.get("completed_attempts") != 2:
    raise SystemExit(f"{summary_path}: unexpected attempt counts {summary}")
if (summary.get("status_totals") or {}).get("findings") != 2:
    raise SystemExit(f"{summary_path}: expected two finding statuses, got {summary.get('status_totals')}")
if (summary.get("outcome_totals") or {}).get("finding") != 2:
    raise SystemExit(f"{summary_path}: expected two finding outcomes, got {summary.get('outcome_totals')}")
if (summary.get("finding_totals_by_class") or {}).get("heap_overflow") != 2:
    raise SystemExit(f"{summary_path}: expected two heap_overflow findings, got {summary.get('finding_totals_by_class')}")
first_failure = summary.get("first_failure") or {}
best_evidence = summary.get("best_evidence_attempt") or {}
if first_failure.get("attempt") != 1 or first_failure.get("status") != "findings":
    raise SystemExit(f"{summary_path}: unexpected first_failure {first_failure}")
if best_evidence.get("attempt") != 1 or best_evidence.get("findings_count") != 1:
    raise SystemExit(f"{summary_path}: unexpected best_evidence_attempt {best_evidence}")
policy = summary.get("escalation_policy") or {}
if policy.get("policy") != "never" or policy.get("selected_attempt_count") != 0:
    raise SystemExit(f"{summary_path}: native-only repeat should record policy never: {policy}")
attempts = summary.get("attempts") or []
if len(attempts) != 2:
    raise SystemExit(f"{summary_path}: expected two attempts, got {attempts}")
for index, attempt in enumerate(attempts, start=1):
    if attempt.get("target_name") != f"attempt-{index:04}-copy_overrun_case":
        raise SystemExit(f"{summary_path}: bad target_name for attempt {index}: {attempt}")
    if attempt.get("findings_by_class", {}).get("heap_overflow") != 1:
        raise SystemExit(f"{summary_path}: missing heap_overflow for attempt {index}: {attempt}")
    for key in ["run_summary", "crashpack", "findings", "evidence_pack", "issue_groups"]:
        path = pathlib.Path(attempt.get(key, ""))
        if not path.exists():
            raise SystemExit(f"{summary_path}: attempt {index} {key} missing at {path}")
print(json.dumps({
    "repeat_summary": str(summary_path),
    "status_totals": summary.get("status_totals"),
    "outcome_totals": summary.get("outcome_totals"),
    "first_failure": first_failure.get("attempt"),
    "best_evidence_attempt": best_evidence.get("attempt"),
}, sort_keys=True))
PY

printf '[observe] repeat deep escalates only first failing attempt by default\n'
"$runner_path" observe --deep --repeat 2 build/user-samples/copy_overrun_case --output "$output_root/copy_overrun_case_deep_repeat"
python3 - "$output_root/copy_overrun_case_deep_repeat/repeat-summary.json" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
summary = json.loads(summary_path.read_text())
policy = summary.get("escalation_policy") or {}
selected = policy.get("selected_attempts") or []
if policy.get("policy") != "first-failure" or policy.get("deep") is not True:
    raise SystemExit(f"{summary_path}: unexpected repeat escalation policy {policy}")
if policy.get("selected_attempt_count") != 1 or len(selected) != 1:
    raise SystemExit(f"{summary_path}: expected one selected escalation attempt, got {policy}")
if selected[0].get("attempt") != 1 or selected[0].get("reason") != "first_escalatable_failure":
    raise SystemExit(f"{summary_path}: expected attempt 1 first failure selection, got {selected}")

attempts = summary.get("attempts") or []
if len(attempts) != 2:
    raise SystemExit(f"{summary_path}: expected two attempts, got {attempts}")
first_summary = json.loads(pathlib.Path(attempts[0]["run_summary"]).read_text())
second_summary = json.loads(pathlib.Path(attempts[1]["run_summary"]).read_text())
first_escalations = first_summary["targets"][0].get("escalation") or []
second_escalations = second_summary["targets"][0].get("escalation") or []
if not any(result.get("tool") == "valgrind" for result in first_escalations):
    raise SystemExit(f"{summary_path}: first attempt missing Valgrind escalation: {first_escalations}")
if second_escalations:
    raise SystemExit(f"{summary_path}: second attempt should not be escalated by first-failure: {second_escalations}")
print(json.dumps({
    "repeat_summary": str(summary_path),
    "policy": policy.get("policy"),
    "selected_attempts": [attempt.get("attempt") for attempt in selected],
}, sort_keys=True))
PY

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
assert_observation "$output_root/use_after_free_case/run-summary.json" findings use_after_free 1 valgrind findings use_after_free

printf '[observe] repeated deep Valgrind-first binary keeps stable tool fingerprint\n'
"$runner_path" observe --deep build/user-samples/use_after_free_case --output "$output_root/use_after_free_case_repeat"
assert_observation "$output_root/use_after_free_case_repeat/run-summary.json" findings use_after_free 1 valgrind findings use_after_free
python3 - "$output_root/use_after_free_case/targets/use_after_free_case/issue-groups.json" \
    "$output_root/use_after_free_case_repeat/targets/use_after_free_case/issue-groups.json" <<'PY'
import json
import pathlib
import sys

left = json.loads(pathlib.Path(sys.argv[1]).read_text())
right = json.loads(pathlib.Path(sys.argv[2]).read_text())
left_fingerprints = [group.get("fingerprint") for group in left.get("groups") or []]
right_fingerprints = [group.get("fingerprint") for group in right.get("groups") or []]
if left_fingerprints != right_fingerprints:
    raise SystemExit(f"tool fingerprints are not stable: {left_fingerprints} != {right_fingerprints}")
print(json.dumps({"stable_tool_fingerprints": left_fingerprints}, sort_keys=True))
PY

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
