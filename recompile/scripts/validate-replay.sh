#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-replay.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[replay] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[replay] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

output_root="build/replay-smoke"
rm -rf "$output_root"
mkdir -p "$output_root"

run_and_replay() {
    local name="$1"
    local expect_success="$2"
    local output_dir="${output_root}/${name}"
    local run_log="${output_dir}.log"
    local replay_json="${output_dir}/replay.json"

    if ! "$runner_path" run --native "build/user-samples/${name}" --output "$output_dir" >"$run_log" 2>&1; then
        printf '\n[replay] native run failed for %s\n' "$name" >&2
        tail -n 80 "$run_log" >&2 || true
        exit 1
    fi

    "$runner_path" replay "$output_dir" --format json >"$replay_json"

    python3 - "$replay_json" "$expect_success" "$name" <<'PY'
import json
import pathlib
import sys

replay_path = pathlib.Path(sys.argv[1])
expect_success = sys.argv[2] == "1"
name = sys.argv[3]

result = json.loads(replay_path.read_text())
if result.get("schema_version") != "1.0":
    raise SystemExit(f"{name}: replay schema_version must be 1.0")
if result.get("ran") is not True:
    raise SystemExit(f"{name}: replay did not run: {result.get('error')}")
if result.get("exit_success") is not expect_success:
    raise SystemExit(
        f"{name}: expected exit_success={expect_success}, got {result.get('exit_success')}"
    )
if not pathlib.Path(result.get("binary_path", "")).exists():
    raise SystemExit(f"{name}: replay binary does not exist: {result.get('binary_path')}")
if not (replay_path.parent / "replay" / "results.json").exists():
    raise SystemExit(f"{name}: replay/results.json was not written")

print(json.dumps({
    "binary": name,
    "replay": str(replay_path),
    "exit_success": result.get("exit_success"),
    "exit_code": result.get("exit_code"),
}))
PY
}

printf '[replay] positive crashpack\n'
run_and_replay copy_overrun_case 1

printf '[replay] clean crashpack\n'
run_and_replay clean_malloc_free 1

printf '\n[replay] replay smoke passed\n'
