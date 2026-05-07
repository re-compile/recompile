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
    "$fixture_root/timeout"

COMMON_FLAGS=(
  -g
  -O0
  -fno-omit-frame-pointer
  -fno-builtin
  -fno-builtin-memcpy
  -fno-builtin-free
  -fno-builtin-malloc
  -fno-builtin-calloc
  -fno-builtin-realloc
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

printf 'Built project fixtures under %s\n' "$fixture_root"
