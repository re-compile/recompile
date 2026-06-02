#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-ubsan.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[ubsan] building user-style samples\n'
./scripts/build-user-samples.sh

if [[ ! -x build/user-samples-ubsan/signed_overflow ]]; then
    cat >&2 <<'MSG'
missing UBSan sample: build/user-samples-ubsan/signed_overflow
The UBSan smoke requires binaries compiled with -fsanitize=undefined.
MSG
    exit 1
fi

printf '[ubsan] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

assert_ubsan_confirmed() {
    local output_dir="$1"
    local binary_name="$2"
    local expected_class="$3"

    python3 - "$output_dir" "$binary_name" "$expected_class" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]
expected_class = sys.argv[3]
results_path = output_dir / "escalations" / "results.json"
findings_path = output_dir / "findings.json"
evidence_pack_path = output_dir / "evidence-pack.json"

if not results_path.exists():
    raise SystemExit(f"{binary_name}: missing UBSan results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one UBSan result")

result = results[0]
if result.get("tool") != "ubsan":
    raise SystemExit(f"{binary_name}: expected ubsan result, got {result.get('tool')}")
if not result.get("tool_available"):
    raise SystemExit(f"{binary_name}: UBSan reported unavailable: {result.get('error')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: UBSan escalation failed: {result.get('error')}")
if not result.get("confirmed"):
    raise SystemExit(f"{binary_name}: UBSan did not confirm {expected_class}")
if expected_class not in (result.get("findings_detected") or []):
    raise SystemExit(f"{binary_name}: expected {expected_class}, got {result.get('findings_detected')}")

for key in ("stdout_path", "stderr_path", "report_path"):
    path = result.get(key)
    if not path or not pathlib.Path(path).exists():
        raise SystemExit(f"{binary_name}: missing {key}: {path}")

findings = json.loads(findings_path.read_text())
if len(findings) != 1:
    raise SystemExit(f"{binary_name}: expected one promoted finding, got {len(findings)}")
finding = findings[0]
if finding.get("origin") != "ubsan":
    raise SystemExit(f"{binary_name}: promoted finding origin is not ubsan: {finding}")
if finding.get("class") != expected_class:
    raise SystemExit(f"{binary_name}: promoted finding class mismatch: {finding.get('class')}")
if not finding.get("fingerprint") or not finding.get("issue_group_id"):
    raise SystemExit(f"{binary_name}: promoted finding lacks grouping metadata: {finding}")

tool = ((finding.get("evidence") or {}).get("tool") or {})
if tool.get("name") != "ubsan":
    raise SystemExit(f"{binary_name}: promoted finding lacks UBSan tool evidence: {tool}")
if not tool.get("summary"):
    raise SystemExit(f"{binary_name}: promoted finding lacks UBSan summary: {tool}")

pack = json.loads(evidence_pack_path.read_text())
summary = pack.get("summary") or {}
if summary.get("total_findings") != 1:
    raise SystemExit(f"{binary_name}: evidence-pack total_findings mismatch: {summary}")
if summary.get("issue_group_count") != 1:
    raise SystemExit(f"{binary_name}: evidence-pack issue_group_count mismatch: {summary}")

print(json.dumps({
    "binary": binary_name,
    "tool": result.get("tool"),
    "confirmed": result.get("confirmed"),
    "class": expected_class,
    "fingerprint": finding.get("fingerprint"),
    "report": result.get("report_path"),
}))
PY
}

assert_ubsan_clean() {
    local results_path="$1"
    local binary_name="$2"

    python3 - "$results_path" "$binary_name" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one UBSan result")
result = results[0]
if result.get("tool") != "ubsan":
    raise SystemExit(f"{binary_name}: expected ubsan result, got {result.get('tool')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: clean UBSan scan failed: {result.get('error')}")
if result.get("confirmed"):
    raise SystemExit(f"{binary_name}: clean UBSan sample unexpectedly confirmed")
if result.get("findings_detected"):
    raise SystemExit(f"{binary_name}: clean UBSan sample unexpectedly detected {result.get('findings_detected')}")
print(json.dumps({"binary": binary_name, "tool": result.get("tool"), "confirmed": False}))
PY
}

assert_ubsan_rejected() {
    local results_path="$1"
    local binary_name="$2"

    python3 - "$results_path" "$binary_name" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]
results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one UBSan result")
result = results[0]
error = result.get("error") or ""
if result.get("tool") != "ubsan":
    raise SystemExit(f"{binary_name}: expected ubsan result, got {result.get('tool')}")
if result.get("success"):
    raise SystemExit(f"{binary_name}: non-UBSan binary should not produce successful UBSan result")
if result.get("confirmed"):
    raise SystemExit(f"{binary_name}: non-UBSan binary unexpectedly confirmed")
if "-fsanitize=undefined" not in error:
    raise SystemExit(f"{binary_name}: rejection did not explain UBSan build requirement: {error}")
print(json.dumps({"binary": binary_name, "tool": result.get("tool"), "success": False, "error": error}))
PY
}

run_positive() {
    local binary="$1"
    local expected_class="$2"
    local output_dir="build/ubsan-smoke/${binary}"

    ./scripts/validate-binary.sh \
        --binary "build/user-samples-ubsan/${binary}" \
        --expect-none \
        --runner "$runner_path" \
        --output "$output_dir"

    printf '[ubsan] running UBSan binary scan for %s\n' "$binary"
    "$runner_path" escalate "$output_dir" --tool ubsan --scan-binary
    assert_ubsan_confirmed "$output_dir" "$binary" "$expected_class"
}

run_positive signed_overflow signed_integer_overflow
run_positive shift_out_of_bounds shift_out_of_bounds
run_positive null_pointer null_pointer_use
run_positive misaligned_pointer misaligned_pointer
run_positive bounds bounds

printf '[ubsan] summarizing UBSan-promoted crashpack\n'
"$runner_path" summarize build/ubsan-smoke/signed_overflow --format json > build/ubsan-smoke/signed_overflow/agent-summary.json
python3 - build/ubsan-smoke/signed_overflow/agent-summary.json <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
if (summary.get("summary") or {}).get("total_findings") != 1:
    raise SystemExit(f"summary did not expose one UBSan finding: {summary}")
finding = (summary.get("findings") or [{}])[0]
if finding.get("origin") != "ubsan" or finding.get("class") != "signed_integer_overflow":
    raise SystemExit(f"summary did not expose UBSan finding evidence: {finding}")
print(json.dumps({
    "summary": str(sys.argv[1]),
    "origin": finding.get("origin"),
    "class": finding.get("class"),
}))
PY

printf '[ubsan] observing UBSan binary through deep path\n'
"$runner_path" observe --deep build/user-samples-ubsan/signed_overflow --output build/ubsan-smoke/observe_signed_overflow
python3 - build/ubsan-smoke/observe_signed_overflow/run-summary.json <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = summary["targets"][0]
classes = target.get("findings_by_class") or {}
if target.get("status") != "findings":
    raise SystemExit(f"observe did not report findings: {target}")
if classes.get("signed_integer_overflow") != 1:
    raise SystemExit(f"observe did not promote UBSan class: {classes}")
if not any(
    result.get("tool") == "ubsan"
    and result.get("status") == "findings"
    and "signed_integer_overflow" in (result.get("findings_detected") or [])
    for result in target.get("escalation") or []
):
    raise SystemExit(f"observe did not surface UBSan escalation: {target.get('escalation')}")
if not any(
    result.get("tool") == "valgrind"
    and result.get("status") == "skipped"
    and "sanitizer runtime detected" in (result.get("error") or "")
    for result in target.get("escalation") or []
):
    raise SystemExit(f"observe did not record Valgrind sanitizer skip: {target.get('escalation')}")
print(json.dumps({
    "summary": str(sys.argv[1]),
    "classes": classes,
    "escalations": target.get("escalation"),
}, sort_keys=True))
PY

clean_output="build/ubsan-smoke/clean_malloc_free"
./scripts/validate-binary.sh \
    --binary build/user-samples-ubsan/clean_malloc_free \
    --expect-none \
    --runner "$runner_path" \
    --output "$clean_output"

printf '[ubsan] running clean UBSan binary scan for clean_malloc_free\n'
"$runner_path" escalate "$clean_output" --tool ubsan --scan-binary
assert_ubsan_clean "$clean_output/escalations/results.json" "clean_malloc_free"

rejected_output="build/ubsan-smoke/non_ubsan_clean_malloc_free"
./scripts/validate-binary.sh \
    --binary build/user-samples/clean_malloc_free \
    --expect-none \
    --runner "$runner_path" \
    --output "$rejected_output"

printf '[ubsan] checking clear rejection for non-UBSan binary\n'
"$runner_path" escalate "$rejected_output" --tool ubsan --scan-binary
assert_ubsan_rejected "$rejected_output/escalations/results.json" "clean_malloc_free"

printf '\n[ubsan] UBSan binary smoke passed\n'
