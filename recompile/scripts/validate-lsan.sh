#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-lsan.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[lsan] building user-style samples\n'
./scripts/build-user-samples.sh

if [[ ! -x build/user-samples-lsan/direct_leak ]]; then
    cat >&2 <<'MSG'
missing LSan sample: build/user-samples-lsan/direct_leak
The LSan smoke requires binaries compiled with -fsanitize=leak.
MSG
    exit 1
fi

printf '[lsan] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

assert_lsan_confirmed() {
    local output_dir="$1"
    local binary_name="$2"

    python3 - "$output_dir" "$binary_name" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]
results_path = output_dir / "escalations" / "results.json"
findings_path = output_dir / "findings.json"
evidence_pack_path = output_dir / "evidence-pack.json"

if not results_path.exists():
    raise SystemExit(f"{binary_name}: missing LSan results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one LSan result")

result = results[0]
if result.get("tool") != "lsan":
    raise SystemExit(f"{binary_name}: expected lsan result, got {result.get('tool')}")
if not result.get("tool_available"):
    raise SystemExit(f"{binary_name}: LSan reported unavailable: {result.get('error')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: LSan escalation failed: {result.get('error')}")
if not result.get("confirmed"):
    raise SystemExit(f"{binary_name}: LSan did not confirm memory_leak")
if "memory_leak" not in (result.get("findings_detected") or []):
    raise SystemExit(f"{binary_name}: expected memory_leak, got {result.get('findings_detected')}")

for key in ("stdout_path", "stderr_path", "report_path"):
    path = result.get(key)
    if not path or not pathlib.Path(path).exists():
        raise SystemExit(f"{binary_name}: missing {key}: {path}")

findings = json.loads(findings_path.read_text())
if len(findings) != 1:
    raise SystemExit(f"{binary_name}: expected one promoted finding, got {len(findings)}")
finding = findings[0]
if finding.get("origin") != "lsan":
    raise SystemExit(f"{binary_name}: promoted finding origin is not lsan: {finding}")
if finding.get("class") != "memory_leak":
    raise SystemExit(f"{binary_name}: promoted finding class mismatch: {finding.get('class')}")
if not finding.get("fingerprint") or not finding.get("issue_group_id"):
    raise SystemExit(f"{binary_name}: promoted finding lacks grouping metadata: {finding}")

tool = ((finding.get("evidence") or {}).get("tool") or {})
if tool.get("name") != "lsan":
    raise SystemExit(f"{binary_name}: promoted finding lacks LSan tool evidence: {tool}")
if not tool.get("summary"):
    raise SystemExit(f"{binary_name}: promoted finding lacks LSan summary: {tool}")
if not (((finding.get("evidence") or {}).get("stacks") or {}).get("alloc")):
    raise SystemExit(f"{binary_name}: promoted finding lacks allocation stack evidence: {finding}")

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
    "class": "memory_leak",
    "fingerprint": finding.get("fingerprint"),
    "report": result.get("report_path"),
}))
PY
}

assert_lsan_clean() {
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
    raise SystemExit(f"{binary_name}: expected exactly one LSan result")
result = results[0]
if result.get("tool") != "lsan":
    raise SystemExit(f"{binary_name}: expected lsan result, got {result.get('tool')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: clean LSan scan failed: {result.get('error')}")
if result.get("confirmed"):
    raise SystemExit(f"{binary_name}: clean LSan sample unexpectedly confirmed")
if result.get("findings_detected"):
    raise SystemExit(f"{binary_name}: clean LSan sample unexpectedly detected {result.get('findings_detected')}")
print(json.dumps({"binary": binary_name, "tool": result.get("tool"), "confirmed": False}))
PY
}

assert_lsan_rejected() {
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
    raise SystemExit(f"{binary_name}: expected exactly one LSan result")
result = results[0]
error = result.get("error") or ""
if result.get("tool") != "lsan":
    raise SystemExit(f"{binary_name}: expected lsan result, got {result.get('tool')}")
if result.get("success"):
    raise SystemExit(f"{binary_name}: non-LSan binary should not produce successful LSan result")
if result.get("confirmed"):
    raise SystemExit(f"{binary_name}: non-LSan binary unexpectedly confirmed")
if "-fsanitize=leak" not in error:
    raise SystemExit(f"{binary_name}: rejection did not explain LSan build requirement: {error}")
print(json.dumps({"binary": binary_name, "tool": result.get("tool"), "success": False, "error": error}))
PY
}

run_positive() {
    local binary="$1"
    local output_dir="build/lsan-smoke/${binary}"

    ./scripts/validate-binary.sh \
        --binary "build/user-samples-lsan/${binary}" \
        --expect-none \
        --runner "$runner_path" \
        --output "$output_dir"

    printf '[lsan] running LSan binary scan for %s\n' "$binary"
    "$runner_path" escalate "$output_dir" --tool lsan --scan-binary
    assert_lsan_confirmed "$output_dir" "$binary"
}

run_positive direct_leak
run_positive indirect_leak

printf '[lsan] summarizing LSan-promoted crashpack\n'
"$runner_path" summarize build/lsan-smoke/direct_leak --format json > build/lsan-smoke/direct_leak/agent-summary.json
python3 - build/lsan-smoke/direct_leak/agent-summary.json <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
if (summary.get("summary") or {}).get("total_findings") != 1:
    raise SystemExit(f"summary did not expose one LSan finding: {summary}")
finding = (summary.get("findings") or [{}])[0]
if finding.get("origin") != "lsan" or finding.get("class") != "memory_leak":
    raise SystemExit(f"summary did not expose LSan finding evidence: {finding}")
print(json.dumps({
    "summary": str(sys.argv[1]),
    "origin": finding.get("origin"),
    "class": finding.get("class"),
}))
PY

printf '[lsan] observing LSan binary through deep path\n'
"$runner_path" observe --deep build/user-samples-lsan/direct_leak --output build/lsan-smoke/observe_direct_leak
python3 - build/lsan-smoke/observe_direct_leak/run-summary.json <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = summary["targets"][0]
classes = target.get("findings_by_class") or {}
if target.get("status") != "findings":
    raise SystemExit(f"observe did not report findings: {target}")
if classes.get("memory_leak") != 1:
    raise SystemExit(f"observe did not promote LSan class: {classes}")
if not any(
    result.get("tool") == "lsan"
    and result.get("status") == "findings"
    and "memory_leak" in (result.get("findings_detected") or [])
    for result in target.get("escalation") or []
):
    raise SystemExit(f"observe did not surface LSan escalation: {target.get('escalation')}")
print(json.dumps({
    "summary": str(sys.argv[1]),
    "classes": classes,
    "escalations": target.get("escalation"),
}, sort_keys=True))
PY

clean_output="build/lsan-smoke/clean_malloc_free"
./scripts/validate-binary.sh \
    --binary build/user-samples-lsan/clean_malloc_free \
    --expect-none \
    --runner "$runner_path" \
    --output "$clean_output"

printf '[lsan] running clean LSan binary scan for clean_malloc_free\n'
"$runner_path" escalate "$clean_output" --tool lsan --scan-binary
assert_lsan_clean "$clean_output/escalations/results.json" "clean_malloc_free"

rejected_output="build/lsan-smoke/non_lsan_clean_malloc_free"
./scripts/validate-binary.sh \
    --binary build/user-samples/clean_malloc_free \
    --expect-none \
    --runner "$runner_path" \
    --output "$rejected_output"

printf '[lsan] checking clear rejection for non-LSan binary\n'
"$runner_path" escalate "$rejected_output" --tool lsan --scan-binary
assert_lsan_rejected "$rejected_output/escalations/results.json" "clean_malloc_free"

printf '\n[lsan] LSan binary smoke passed\n'
