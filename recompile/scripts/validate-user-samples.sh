#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-user-samples.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

printf '[external] building user-style samples\n'
./scripts/build-user-samples.sh

printf '[external] building rerun release binary\n'
cargo build --release -p rerun
runner_path="${project_dir}/target/release/rerun"

samples=(
    "build/user-samples/copy_overrun_case:heap_overflow"
    "build/user-samples/cache_release_twice:double_free"
    "build/user-samples/free_stack_slot:invalid_free"
)

for entry in "${samples[@]}"; do
    binary_path="${entry%%:*}"
    expected_class="${entry##*:}"
    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-class "$expected_class" \
        --runner "$runner_path" \
        --output "build/user-sample-regression/$(basename "$binary_path")"
done

clean_samples=(
    "build/user-samples/clean_malloc_free"
    "build/user-samples/clean_bounded_memcpy"
    "build/user-samples/fd_leak_case"
    "build/user-samples/clean_fd_close"
)

for binary_path in "${clean_samples[@]}"; do
    ./scripts/validate-binary.sh \
        --binary "$binary_path" \
        --expect-none \
        --runner "$runner_path" \
        --output "build/user-sample-regression/$(basename "$binary_path")"
done

printf '\n[external] user-style sample regression passed\n'
