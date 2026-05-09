#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/examples

# Build goldens in a probe-friendly way. Optimizer/builtin rewrites can
# eliminate the exact libc calls that the native agent attaches to.
COMMON_FLAGS=(
  -g
  -O0
  -fno-omit-frame-pointer
  -fno-builtin
  -fno-builtin-memcpy
  -fno-builtin-memmove
  -fno-builtin-memset
  -fno-builtin-free
  -fno-builtin-malloc
  -fno-builtin-calloc
  -fno-builtin-realloc
)

cc "${COMMON_FLAGS[@]}" -o build/examples/memcpy_overflow examples/memcpy_overflow.c
cc "${COMMON_FLAGS[@]}" -o build/examples/double_free examples/double_free.c
cc "${COMMON_FLAGS[@]}" -o build/examples/invalid_free examples/invalid_free.c
echo "Built examples under build/examples/"
