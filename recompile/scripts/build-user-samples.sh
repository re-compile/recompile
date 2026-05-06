#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/user-samples build/user-samples-asan

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

ASAN_FLAGS=(
  "${COMMON_FLAGS[@]}"
  -fsanitize=address
  -fno-sanitize-recover=address
)

cc "${COMMON_FLAGS[@]}" -o build/user-samples/copy_overrun_case samples/user-binaries/copy_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/multi_overrun_case samples/user-binaries/multi_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/cache_release_twice samples/user-binaries/cache_release_twice.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/free_stack_slot samples/user-binaries/free_stack_slot.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/use_after_free_case samples/user-binaries/use_after_free_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/memory_leak_case samples/user-binaries/memory_leak_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/fd_leak_case samples/user-binaries/fd_leak_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_malloc_free samples/user-binaries/clean_malloc_free.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memcpy samples/user-binaries/clean_bounded_memcpy.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_fd_close samples/user-binaries/clean_fd_close.c

cc "${ASAN_FLAGS[@]}" -o build/user-samples-asan/use_after_free_case samples/user-binaries/use_after_free_case.c
cc "${ASAN_FLAGS[@]}" -o build/user-samples-asan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

echo "Built user-style samples under build/user-samples/"
echo "Built ASan-instrumented samples under build/user-samples-asan/"
