#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/user-samples

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

cc "${COMMON_FLAGS[@]}" -o build/user-samples/copy_overrun_case samples/user-binaries/copy_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/cache_release_twice samples/user-binaries/cache_release_twice.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/free_stack_slot samples/user-binaries/free_stack_slot.c

echo "Built user-style samples under build/user-samples/"
