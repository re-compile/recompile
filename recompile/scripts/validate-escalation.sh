#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-escalation.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
    cat >&2 <<'MSG'
valgrind is required for escalation smoke tests.
Use the supported Docker image or install valgrind on the Linux host.
MSG
    exit 1
fi

printf '[escalation] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[escalation] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

output_dir="build/escalation-smoke/copy_overrun_case"
rm -rf "$output_dir" "${output_dir}.log"

./scripts/validate-binary.sh \
    --binary build/user-samples/copy_overrun_case \
    --expect-class heap_overflow \
    --runner "$runner_path" \
    --output "$output_dir"

printf '[escalation] running valgrind escalation\n'
"$runner_path" escalate "$output_dir" --tool valgrind

python3 - "$output_dir/escalations/results.json" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
if not results_path.exists():
    raise SystemExit(f"missing escalation results: {results_path}")

results = json.loads(results_path.read_text())
if not isinstance(results, list) or not results:
    raise SystemExit("escalation results must be a non-empty JSON array")

result = results[0]
if result.get("tool") != "valgrind":
    raise SystemExit(f"expected valgrind result, got {result.get('tool')}")
if not result.get("tool_available"):
    raise SystemExit(f"valgrind not available: {result.get('error')}")
if not result.get("success"):
    raise SystemExit(f"valgrind escalation failed: {result.get('error')}")
if not result.get("confirmed"):
    raise SystemExit("valgrind did not confirm the finding")
if "heap_overflow" not in result.get("findings_detected", []):
    raise SystemExit(f"expected heap_overflow confirmation, got {result.get('findings_detected')}")

for key in ("stdout_path", "stderr_path", "report_path"):
    path = result.get(key)
    if not path or not pathlib.Path(path).exists():
        raise SystemExit(f"missing {key}: {path}")

print(json.dumps({
    "tool": result.get("tool"),
    "confirmed": result.get("confirmed"),
    "findings_detected": result.get("findings_detected"),
    "report": result.get("report_path"),
}))
PY

printf '\n[escalation] valgrind escalation smoke passed\n'
