#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

cd "$project_dir"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'validate-tsan-fixtures.sh only supports Linux-native validation.\n' >&2
    exit 1
fi

CC=${CC:-cc}
if ! command -v "$CC" >/dev/null 2>&1; then
    printf 'TSan fixture smoke requires a C compiler in PATH: %s\n' "$CC" >&2
    exit 1
fi

smoke_dir="build/tsan-fixtures-smoke"
mkdir -p "$smoke_dir"

printf '[tsan-fixtures] checking compiler/runtime support\n'
if ! "$CC" -std=c11 -g -O1 -fno-omit-frame-pointer -fsanitize=thread -pthread \
    -x c -o "$smoke_dir/tsan_probe" - <<'C' 2>"$smoke_dir/tsan_probe.compile.stderr"; then
#include <stdio.h>
int main(void) {
    puts("tsan probe");
    return 0;
}
C
    cat >&2 <<MSG
TSan compiler probe failed.
Expected a Linux compiler that can build with -fsanitize=thread -pthread.
Compiler stderr: $smoke_dir/tsan_probe.compile.stderr
MSG
    exit 1
fi

if ! TSAN_OPTIONS="halt_on_error=1:exitcode=66" "$smoke_dir/tsan_probe" \
    >"$smoke_dir/tsan_probe.stdout" 2>"$smoke_dir/tsan_probe.stderr"; then
    cat >&2 <<MSG
TSan runtime probe failed.
The compiler accepted -fsanitize=thread, but the resulting binary did not run cleanly.
Runtime stderr: $smoke_dir/tsan_probe.stderr
MSG
    exit 1
fi

printf '[tsan-fixtures] building user-style samples with TSan enabled\n'
BUILD_TSAN=1 ./scripts/build-user-samples.sh

require_executable() {
    local binary="$1"
    if [[ ! -x "$binary" ]]; then
        printf 'missing executable fixture: %s\n' "$binary" >&2
        exit 1
    fi
}

require_tsan_marker() {
    local binary="$1"
    if ! strings "$binary" | grep -Eq '__tsan_|libtsan|ThreadSanitizer'; then
        printf 'fixture does not look TSan-instrumented: %s\n' "$binary" >&2
        exit 1
    fi
}

reject_tsan_marker() {
    local binary="$1"
    if strings "$binary" | grep -Eq '__tsan_|libtsan|ThreadSanitizer'; then
        printf 'non-TSan fixture unexpectedly contains TSan markers: %s\n' "$binary" >&2
        exit 1
    fi
}

run_positive_race() {
    local binary="$1"
    local name="$2"
    local stdout_path="$smoke_dir/${name}.stdout"
    local stderr_path="$smoke_dir/${name}.stderr"
    local status=0

    set +e
    TSAN_OPTIONS="halt_on_error=1:exitcode=66" "$binary" >"$stdout_path" 2>"$stderr_path"
    status=$?
    set -e

    if [[ "$status" -eq 0 ]]; then
        printf '%s: expected ThreadSanitizer to report a data race, but exit status was 0\n' "$name" >&2
        exit 1
    fi
    if ! grep -q 'WARNING: ThreadSanitizer: data race' "$stderr_path"; then
        printf '%s: expected a ThreadSanitizer data-race report in %s\n' "$name" "$stderr_path" >&2
        exit 1
    fi
    if ! grep -q 'SUMMARY: ThreadSanitizer: data race' "$stderr_path"; then
        printf '%s: expected a ThreadSanitizer data-race summary in %s\n' "$name" "$stderr_path" >&2
        exit 1
    fi

    printf '{"fixture":"%s","status":%d,"stderr":"%s"}\n' "$name" "$status" "$stderr_path"
}

run_clean_case() {
    local binary="$1"
    local name="$2"
    local stdout_path="$smoke_dir/${name}.stdout"
    local stderr_path="$smoke_dir/${name}.stderr"

    TSAN_OPTIONS="halt_on_error=1:exitcode=66" "$binary" >"$stdout_path" 2>"$stderr_path"
    if grep -q 'ThreadSanitizer' "$stderr_path"; then
        printf '%s: clean fixture unexpectedly emitted ThreadSanitizer output in %s\n' "$name" "$stderr_path" >&2
        exit 1
    fi

    printf '{"fixture":"%s","status":0,"stderr":"%s"}\n' "$name" "$stderr_path"
}

race_binary="build/user-samples-tsan/data_race"
mutex_binary="build/user-samples-tsan/clean_mutex"
atomic_binary="build/user-samples-tsan/clean_atomic"
normal_binary="build/user-samples/clean_malloc_free"

for binary in "$race_binary" "$mutex_binary" "$atomic_binary" "$normal_binary"; do
    require_executable "$binary"
done

for binary in "$race_binary" "$mutex_binary" "$atomic_binary"; do
    require_tsan_marker "$binary"
done
reject_tsan_marker "$normal_binary"

printf '[tsan-fixtures] running positive data-race fixture\n'
run_positive_race "$race_binary" data_race

printf '[tsan-fixtures] running clean mutex fixture\n'
run_clean_case "$mutex_binary" clean_mutex

printf '[tsan-fixtures] running clean atomic fixture\n'
run_clean_case "$atomic_binary" clean_atomic

printf '\n[tsan-fixtures] TSan fixture smoke passed\n'
