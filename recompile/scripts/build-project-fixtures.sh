#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

fixture_root="build/project-fixtures"
rm -rf "$fixture_root"
mkdir -p \
    "$fixture_root/multifile-heap" \
    "$fixture_root/clean-multifile" \
    "$fixture_root/args-cwd/run" \
    "$fixture_root/multi-binary" \
    "$fixture_root/shared-lib/lib" \
    "$fixture_root/valgrind-first" \
    "$fixture_root/timeout" \
    "$fixture_root/repeat-clean" \
    "$fixture_root/repeat-failing" \
    "$fixture_root/repeat-flaky/run" \
    "$fixture_root/repeat-timeout"

COMMON_FLAGS=(
  -g
  -O0
  -fno-omit-frame-pointer
  -fno-builtin
  -fno-builtin-memcpy
  -fno-builtin-memmove
  -fno-builtin-memset
  -fno-builtin-strcpy
  -fno-builtin-strncpy
  -fno-builtin-free
  -fno-builtin-malloc
  -fno-builtin-calloc
  -fno-builtin-realloc
  -fno-builtin-posix_memalign
  -fno-builtin-aligned_alloc
  -fno-builtin-strdup
)

cc "${COMMON_FLAGS[@]}" \
  -Isamples/project-fixtures/multifile-heap/include \
  -o "$fixture_root/multifile-heap/app" \
  samples/project-fixtures/multifile-heap/src/main.c \
  samples/project-fixtures/multifile-heap/src/packet.c

cc "${COMMON_FLAGS[@]}" \
  -Isamples/project-fixtures/clean-multifile/include \
  -o "$fixture_root/clean-multifile/app" \
  samples/project-fixtures/clean-multifile/src/main.c \
  samples/project-fixtures/clean-multifile/src/store.c

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/args-cwd/app" \
  samples/project-fixtures/args-cwd/src/main.c
python3 - <<'PY'
from pathlib import Path
payload = Path("build/project-fixtures/args-cwd/run/payload.bin")
payload.write_bytes(b"A" * 80)
PY

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/multi-binary/worker" \
  samples/project-fixtures/multi-binary/src/worker.c
cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/multi-binary/healthcheck" \
  samples/project-fixtures/multi-binary/src/healthcheck.c

cc "${COMMON_FLAGS[@]}" \
  -fPIC -shared \
  -o "$fixture_root/shared-lib/lib/libprojectbug.so" \
  samples/project-fixtures/shared-lib/src/buglib.c
cc "${COMMON_FLAGS[@]}" \
  -Isamples/project-fixtures/shared-lib/src \
  -o "$fixture_root/shared-lib/app" \
  samples/project-fixtures/shared-lib/src/main.c \
  -L"$fixture_root/shared-lib/lib" \
  -lprojectbug \
  -Wl,-rpath,'$ORIGIN/lib'

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/valgrind-first/app" \
  samples/project-fixtures/valgrind-first/src/main.c

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/timeout/app" \
  samples/project-fixtures/timeout/src/main.c

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/repeat-clean/repeat_clean" \
  samples/project-fixtures/repeat-clean/src/main.c

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/repeat-failing/repeat_failing" \
  samples/project-fixtures/repeat-failing/src/main.c

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/repeat-flaky/repeat_flaky" \
  samples/project-fixtures/repeat-flaky/src/main.c
printf '0\n' > "$fixture_root/repeat-flaky/run/attempt-state.txt"

cc "${COMMON_FLAGS[@]}" \
  -o "$fixture_root/repeat-timeout/repeat_timeout" \
  samples/project-fixtures/repeat-timeout/src/main.c

printf 'Built project fixtures under %s\n' "$fixture_root"
