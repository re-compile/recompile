#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-hit-rate.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
    cat >&2 <<'MSG'
valgrind is required for hit-rate evaluation.
Use the supported Docker image or install valgrind on the Linux host.
MSG
    exit 1
fi

printf '[hit-rate] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[hit-rate] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

report_dir="build/hit-rate"
cases_dir="${report_dir}/cases"
cases_jsonl="${report_dir}/cases.jsonl"
summary_json="${report_dir}/summary.json"

rm -rf "$report_dir"
mkdir -p "$cases_dir"
: >"$cases_jsonl"

samples=(
    "copy_overrun_case:heap_overflow:heap_overflow:1"
    "memmove_overrun_case:heap_overflow:heap_overflow:1"
    "memset_overrun_case:heap_overflow:heap_overflow:1"
    "strcpy_overrun_case:heap_overflow:heap_overflow:1"
    "strncpy_overrun_case:heap_overflow:heap_overflow:1"
    "multi_overrun_case:heap_overflow:heap_overflow:2"
    "cache_release_twice:double_free:double_free:1"
    "free_stack_slot:invalid_free:invalid_free:1"
    "use_after_free_case:__unsupported__:use_after_free:0"
    "memory_leak_case:__unsupported__:memory_leak:0"
    "fd_leak_case:__unsupported__:fd_leak:0"
    "clean_malloc_free:__none__:__none__:0"
    "clean_bounded_memcpy:__none__:__none__:0"
    "clean_bounded_memmove:__none__:__none__:0"
    "clean_bounded_memset:__none__:__none__:0"
    "clean_bounded_strcpy:__none__:__none__:0"
    "clean_bounded_strncpy:__none__:__none__:0"
    "clean_fd_close:__none__:__none__:0"
)

append_case_record() {
    local binary_name="$1"
    local native_expected_class="$2"
    local escalation_expected_class="$3"
    local output_dir="$4"
    local native_expected_count="$5"

    python3 - "$binary_name" "$native_expected_class" "$escalation_expected_class" "$output_dir" "$native_expected_count" >>"$cases_jsonl" <<'PY'
import json
import pathlib
import sys

binary_name = sys.argv[1]
native_expected_class = sys.argv[2]
escalation_expected_class = sys.argv[3]
output_dir = pathlib.Path(sys.argv[4])
native_expected_count = int(sys.argv[5])
findings_path = output_dir / "findings.json"
results_path = output_dir / "escalations" / "results.json"

findings = json.loads(findings_path.read_text())
if not isinstance(findings, list):
    raise SystemExit(f"{binary_name}: findings.json is not a JSON array")

native_findings = [
    finding
    for finding in findings
    if isinstance(finding, dict) and finding.get("origin") in (None, "ebpf")
]
tool_findings = [
    finding
    for finding in findings
    if isinstance(finding, dict) and finding.get("origin") not in (None, "ebpf")
]
actual_classes = [
    finding.get("class")
    for finding in native_findings
    if isinstance(finding, dict) and finding.get("class")
]
source_statuses = [
    (finding.get("provenance") or {}).get("source_status")
    for finding in native_findings
    if isinstance(finding, dict)
]

if native_expected_class == "__unsupported__":
    native_outcome = "unsupported"
elif native_expected_class == "__none__":
    native_outcome = "tn" if not actual_classes else "fp"
else:
    native_outcome = (
        "tp"
        if native_expected_class in actual_classes and len(native_findings) == native_expected_count
        else "fn"
    )

escalation_results = []
if results_path.exists():
    escalation_results = json.loads(results_path.read_text())
    if not isinstance(escalation_results, list):
        raise SystemExit(f"{binary_name}: escalation results are not a JSON array")

escalation = escalation_results[0] if escalation_results else {}
escalation_detected = escalation.get("findings_detected") or []
if escalation_expected_class == "__none__":
    escalation_outcome = (
        "tn"
        if escalation.get("success") and not escalation.get("confirmed") and not escalation_detected
        else "fp"
    )
else:
    escalation_outcome = (
        "tp"
        if escalation.get("confirmed") and escalation_expected_class in escalation_detected
        else "fn"
    )

print(json.dumps({
    "binary": binary_name,
    "native_expected_class": None if native_expected_class.startswith("__") else native_expected_class,
    "escalation_expected_class": None if escalation_expected_class == "__none__" else escalation_expected_class,
    "native": {
        "outcome": native_outcome,
        "actual_classes": actual_classes,
        "source_statuses": source_statuses,
        "finding_count": len(native_findings),
        "total_finding_count": len(findings),
        "tool_backed_finding_count": len(tool_findings),
        "expected_count": native_expected_count,
    },
    "escalation": {
        "tool": escalation.get("tool"),
        "outcome": escalation_outcome,
        "success": escalation.get("success", False),
        "confirmed": escalation.get("confirmed", False),
        "findings_detected": escalation_detected,
        "results_path": str(results_path) if results_path.exists() else None,
    },
    "output": str(output_dir),
}))
PY
}

for entry in "${samples[@]}"; do
    IFS=':' read -r binary_name native_expected_class escalation_expected_class native_expected_count <<<"$entry"
    binary_path="build/user-samples/${binary_name}"
    output_dir="${cases_dir}/${binary_name}"
    run_log="${output_dir}.log"

    printf '[hit-rate] running %s\n' "$binary_name"
    mkdir -p "$(dirname "$output_dir")"
    if ! "$runner_path" run --native "$binary_path" --output "$output_dir" >"$run_log" 2>&1; then
        printf '\n[hit-rate] native run failed for %s\n' "$binary_name" >&2
        printf '\n--- run log ---\n' >&2
        tail -n 80 "$run_log" >&2 || true
        exit 1
    fi

    if [[ "$escalation_expected_class" == "__none__" ]]; then
        printf '[hit-rate] clean Valgrind check for %s\n' "$binary_name"
        "$runner_path" escalate "$output_dir" --tool valgrind --check-clean
    elif [[ "$native_expected_class" == "__unsupported__" ]]; then
        printf '[hit-rate] Valgrind binary scan for %s\n' "$binary_name"
        "$runner_path" escalate "$output_dir" --tool valgrind --scan-binary
    elif (( native_expected_count > 1 )); then
        printf '[hit-rate] Valgrind binary scan for multi-finding case %s\n' "$binary_name"
        "$runner_path" escalate "$output_dir" --tool valgrind --scan-binary
    else
        printf '[hit-rate] Valgrind confirmation for %s\n' "$binary_name"
        "$runner_path" escalate "$output_dir" --tool valgrind
    fi

    append_case_record "$binary_name" "$native_expected_class" "$escalation_expected_class" "$output_dir" "$native_expected_count"
done

python3 - "$cases_jsonl" "$summary_json" <<'PY'
import json
import pathlib
import sys

cases_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
cases = [
    json.loads(line)
    for line in cases_path.read_text().splitlines()
    if line.strip()
]

def totals_for(key):
    totals = {
        "true_positives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "unsupported": 0,
    }
    for case in cases:
        outcome = case[key]["outcome"]
        if outcome == "tp":
            totals["true_positives"] += 1
        elif outcome == "tn":
            totals["true_negatives"] += 1
        elif outcome == "fp":
            totals["false_positives"] += 1
        elif outcome == "fn":
            totals["false_negatives"] += 1
        elif outcome == "unsupported":
            totals["unsupported"] += 1
        else:
            raise SystemExit(f"unknown {key} outcome: {outcome}")
    return totals

summary = {
    "schema_version": "1.0",
    "total_cases": len(cases),
    "native": totals_for("native"),
    "escalation": totals_for("escalation"),
    "cases": cases,
}

summary_path.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))

failed = (
    summary["native"]["false_positives"]
    or summary["native"]["false_negatives"]
    or summary["escalation"]["false_positives"]
    or summary["escalation"]["false_negatives"]
)
if failed:
    raise SystemExit(1)
PY

printf '\n[hit-rate] summary written to %s\n' "$summary_json"
printf '[hit-rate] evaluation passed\n'
