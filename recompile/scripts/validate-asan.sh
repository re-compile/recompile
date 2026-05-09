#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-asan.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[asan] building user-style samples\n'
./scripts/build-user-samples.sh

if [[ ! -x build/user-samples-asan/use_after_free_case ]]; then
    cat >&2 <<'MSG'
missing ASan sample: build/user-samples-asan/use_after_free_case
The ASan smoke requires binaries compiled with -fsanitize=address.
MSG
    exit 1
fi

printf '[asan] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

assert_asan_confirmed() {
    local results_path="$1"
    local binary_name="$2"
    local expected_class="$3"

    python3 - "$results_path" "$binary_name" "$expected_class" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]
expected_class = sys.argv[3]

if not results_path.exists():
    raise SystemExit(f"{binary_name}: missing ASan results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one ASan result")

result = results[0]
if result.get("tool") != "asan":
    raise SystemExit(f"{binary_name}: expected asan result, got {result.get('tool')}")
if not result.get("tool_available"):
    raise SystemExit(f"{binary_name}: ASan reported unavailable: {result.get('error')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: ASan escalation failed: {result.get('error')}")
if not result.get("confirmed"):
    raise SystemExit(f"{binary_name}: ASan did not confirm {expected_class}")

detected = result.get("findings_detected", [])
if expected_class not in detected:
    raise SystemExit(f"{binary_name}: expected {expected_class}, got {detected}")

for key in ("stdout_path", "stderr_path", "report_path"):
    path = result.get(key)
    if not path or not pathlib.Path(path).exists():
        raise SystemExit(f"{binary_name}: missing {key}: {path}")

print(json.dumps({
    "binary": binary_name,
    "tool": result.get("tool"),
    "confirmed": result.get("confirmed"),
    "findings_detected": detected,
    "report": result.get("report_path"),
}))
PY
}

assert_asan_clean() {
    local results_path="$1"
    local binary_name="$2"

    python3 - "$results_path" "$binary_name" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]

if not results_path.exists():
    raise SystemExit(f"{binary_name}: missing ASan results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one ASan result")

result = results[0]
if result.get("tool") != "asan":
    raise SystemExit(f"{binary_name}: expected asan result, got {result.get('tool')}")
if not result.get("tool_available"):
    raise SystemExit(f"{binary_name}: ASan reported unavailable: {result.get('error')}")
if not result.get("success"):
    raise SystemExit(f"{binary_name}: ASan clean scan failed: {result.get('error')}")
if result.get("confirmed"):
    raise SystemExit(f"{binary_name}: clean ASan sample unexpectedly confirmed")
if result.get("findings_detected"):
    raise SystemExit(f"{binary_name}: clean ASan sample unexpectedly detected {result.get('findings_detected')}")

print(json.dumps({
    "binary": binary_name,
    "tool": result.get("tool"),
    "confirmed": result.get("confirmed"),
    "report": result.get("report_path"),
}))
PY
}

assert_asan_rejected() {
    local results_path="$1"
    local binary_name="$2"

    python3 - "$results_path" "$binary_name" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
binary_name = sys.argv[2]

if not results_path.exists():
    raise SystemExit(f"{binary_name}: missing ASan results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or len(results) != 1:
    raise SystemExit(f"{binary_name}: expected exactly one ASan result")

result = results[0]
error = result.get("error") or ""
if result.get("tool") != "asan":
    raise SystemExit(f"{binary_name}: expected asan result, got {result.get('tool')}")
if result.get("success"):
    raise SystemExit(f"{binary_name}: non-ASan binary should not produce successful ASan result")
if result.get("confirmed"):
    raise SystemExit(f"{binary_name}: non-ASan binary unexpectedly confirmed")
if "-fsanitize=address" not in error:
    raise SystemExit(f"{binary_name}: rejection did not explain ASan build requirement: {error}")

print(json.dumps({
    "binary": binary_name,
    "tool": result.get("tool"),
    "success": result.get("success"),
    "error": error,
}))
PY
}

positive_output="build/asan-smoke/use_after_free_case"
./scripts/validate-binary.sh \
    --binary build/user-samples-asan/use_after_free_case \
    --expect-none \
    --runner "$runner_path" \
    --output "$positive_output"

printf '[asan] running ASan binary scan for use_after_free_case\n'
"$runner_path" escalate "$positive_output" --tool asan --scan-binary
assert_asan_confirmed \
    "$positive_output/escalations/results.json" \
    "use_after_free_case" \
    "use_after_free"

positive_repeat_output="build/asan-smoke/use_after_free_case_repeat"
./scripts/validate-binary.sh \
    --binary build/user-samples-asan/use_after_free_case \
    --expect-none \
    --runner "$runner_path" \
    --output "$positive_repeat_output"

printf '[asan] repeated ASan binary scan keeps stable tool fingerprint\n'
"$runner_path" escalate "$positive_repeat_output" --tool asan --scan-binary
assert_asan_confirmed \
    "$positive_repeat_output/escalations/results.json" \
    "use_after_free_case_repeat" \
    "use_after_free"
python3 - "$positive_output/findings.json" "$positive_repeat_output/findings.json" <<'PY'
import json
import pathlib
import sys

left = json.loads(pathlib.Path(sys.argv[1]).read_text())
right = json.loads(pathlib.Path(sys.argv[2]).read_text())
left_fingerprints = [finding.get("fingerprint") for finding in left]
right_fingerprints = [finding.get("fingerprint") for finding in right]
if left_fingerprints != right_fingerprints:
    raise SystemExit(f"ASan tool fingerprints are not stable: {left_fingerprints} != {right_fingerprints}")
print(json.dumps({"stable_asan_fingerprints": left_fingerprints}, sort_keys=True))
PY

clean_output="build/asan-smoke/clean_malloc_free"
./scripts/validate-binary.sh \
    --binary build/user-samples-asan/clean_malloc_free \
    --expect-none \
    --runner "$runner_path" \
    --output "$clean_output"

printf '[asan] running clean ASan binary scan for clean_malloc_free\n'
"$runner_path" escalate "$clean_output" --tool asan --scan-binary
assert_asan_clean "$clean_output/escalations/results.json" "clean_malloc_free"

rejected_output="build/asan-smoke/non_asan_clean_malloc_free"
./scripts/validate-binary.sh \
    --binary build/user-samples/clean_malloc_free \
    --expect-none \
    --runner "$runner_path" \
    --output "$rejected_output"

printf '[asan] checking clear rejection for non-ASan binary\n'
"$runner_path" escalate "$rejected_output" --tool asan --scan-binary
assert_asan_rejected "$rejected_output/escalations/results.json" "clean_malloc_free"

printf '\n[asan] ASan binary smoke passed\n'
