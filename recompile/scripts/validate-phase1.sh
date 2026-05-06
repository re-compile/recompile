#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/validate-phase1.sh [--output-root PATH] [--runner PATH]

Runs the Phase 1 Linux-native regression baseline:
  - builds the rerun release binary
  - builds the three golden examples
  - runs native analysis for each golden
  - asserts the expected finding class

Options:
  --output-root PATH   Directory for regression outputs
                       Default: build/phase1-regression
  --runner PATH        Use an existing rerun binary instead of building release
  -h, --help           Show this help
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

output_root="${project_dir}/build/phase1-regression"
runner_path=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)
            output_root="$2"
            shift 2
            ;;
        --runner)
            runner_path="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-phase1.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

cd "$project_dir"

if [[ -z "$runner_path" ]]; then
    printf '[phase1] building rerun release binary\n'
    cargo build --release -p rerun
    runner_path="${project_dir}/target/release/rerun"
fi

if [[ ! -x "$runner_path" ]]; then
    printf 'rerun binary is not executable: %s\n' "$runner_path" >&2
    exit 1
fi

printf '[phase1] building golden examples\n'
./scripts/build-examples.sh

mkdir -p "$output_root"

goldens=(
    "memcpy_overflow:heap_overflow"
    "double_free:double_free"
    "invalid_free:invalid_free"
)

for entry in "${goldens[@]}"; do
    name="${entry%%:*}"
    expected_class="${entry##*:}"
    binary_path="${project_dir}/build/examples/${name}"
    run_dir="${output_root}/${name}"
    log_path="${run_dir}.log"

    rm -rf "$run_dir" "$log_path"

    printf '[phase1] running %s -> %s\n' "$name" "$expected_class"
    if ! "$runner_path" run --native "$binary_path" --output "$run_dir" >"$log_path" 2>&1; then
        printf '\n[phase1] run failed for %s\n' "$name" >&2
        if grep -q "shared host PID namespace" "$log_path"; then
            cat >&2 <<'EOF'
Native Docker tracing is only supported with:
  docker run --rm -it --privileged --pid=host -v "$PWD":/workspace/recompile recompile-bootstrap:host bash
EOF
        fi
        printf '\n--- %s log ---\n' "$name" >&2
        tail -n 80 "$log_path" >&2 || true
        exit 1
    fi

    python3 - "$run_dir/findings.json" "$expected_class" "$name" <<'PY'
import json
import pathlib
import sys

findings_path = pathlib.Path(sys.argv[1])
expected_class = sys.argv[2]
name = sys.argv[3]

if not findings_path.exists():
    raise SystemExit(f"{name}: missing findings.json at {findings_path}")

findings = json.loads(findings_path.read_text())
if not isinstance(findings, list):
    raise SystemExit(f"{name}: findings.json is not a JSON array")
if len(findings) != 1:
    raise SystemExit(f"{name}: expected exactly 1 finding, got {len(findings)}")

evidence_pack_path = findings_path.parent / "evidence-pack.json"
if not evidence_pack_path.exists():
    raise SystemExit(f"{name}: missing evidence-pack.json at {evidence_pack_path}")
evidence_pack = json.loads(evidence_pack_path.read_text())
summary = evidence_pack.get("summary") or {}
if summary.get("total_findings") != 1:
    raise SystemExit(f"{name}: evidence-pack total_findings must be 1")

finding = findings[0]
actual_class = finding.get("class")
if actual_class != expected_class:
    raise SystemExit(f"{name}: expected class {expected_class}, got {actual_class}")
if (summary.get("class_counts") or {}).get(expected_class) != 1:
    raise SystemExit(f"{name}: evidence-pack missing class count for {expected_class}")

provenance = finding.get("provenance") or {}
evidence = finding.get("evidence") or {}

print(json.dumps({
    "golden": name,
    "class": actual_class,
    "severity": finding.get("severity"),
    "source_path": provenance.get("source_path"),
    "source_status": provenance.get("source_status"),
    "alloc_site": evidence.get("alloc_site"),
}))
PY
done

printf '\n[phase1] regression baseline passed\n'
printf '[phase1] outputs: %s\n' "$output_root"
