#!/usr/bin/env bash
set -euo pipefail

log() {
    printf '%s\n' "$*"
}

repo_dir="${RECOMPILE_REPO_DIR:-/workspace/recompile}"
skip_bootstrap="${RECOMPILE_SKIP_BOOTSTRAP:-0}"
build_native="${RECOMPILE_BUILD_NATIVE:-1}"
build_rust="${RECOMPILE_BUILD_RUST:-1}"
build_examples="${RECOMPILE_BUILD_EXAMPLES:-1}"

if [[ ! -d "$repo_dir" ]]; then
    log "recompile bootstrap: repository not found at $repo_dir"
    log "Mount the repository there or set RECOMPILE_REPO_DIR."
    exec "$@"
fi

project_dir="$repo_dir"
if [[ -f "$repo_dir/recompile/Cargo.toml" ]]; then
    project_dir="$repo_dir/recompile"
fi

cd "$project_dir"
export PATH="/root/.cargo/bin:$PATH"

if [[ "$skip_bootstrap" != "1" ]]; then
    log "recompile bootstrap: preparing native Linux workspace in $project_dir"

    if [[ "$build_native" == "1" ]]; then
        log "recompile bootstrap: generating BPF headers and objects"
        make -C runtime/bpf all

        log "recompile bootstrap: building re-mini"
        (
            cd runtime/agent
            clang -O2 -g -Wall -I../bpf -I../shared \
                -o re-mini re-mini.c -lelf -lz -lbpf -ldl
        )
    fi

    if [[ "$build_rust" == "1" ]]; then
        log "recompile bootstrap: building Rust workspace"
        cargo build --release -p recc -p rerun -p re-rules -p re-crashpack -p re-escalate -p re-harness
    fi

    if [[ "$build_examples" == "1" ]]; then
        log "recompile bootstrap: building example programs"
        ./scripts/build-examples.sh
    fi

    log "recompile bootstrap: workspace ready"
fi

if [[ $# -eq 0 ]]; then
    exec bash
fi

exec "$@"
