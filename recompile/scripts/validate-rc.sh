#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

printf '[rc] checking active Rust crates\n'
cargo check -q -p rerun -p re-escalate -p re-crashpack -p re-rules

printf '[rc] running rerun tests\n'
cargo test -q -p rerun

printf '[rc] validating golden Phase 1 baseline\n'
./scripts/validate-phase1.sh

printf '[rc] validating user-style external samples\n'
./scripts/validate-user-samples.sh

printf '\n[rc] Phase 1 RC validation passed\n'
