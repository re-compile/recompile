#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/user-samples build/user-samples-asan build/user-samples-lsan build/user-samples-ubsan

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

ASAN_FLAGS=(
  "${COMMON_FLAGS[@]}"
  -fsanitize=address
  -fno-sanitize-recover=address
)

LSAN_FLAGS=(
  "${COMMON_FLAGS[@]}"
  -fsanitize=leak
)

UBSAN_FLAGS=(
  "${COMMON_FLAGS[@]}"
  -fsanitize=undefined
  -fno-sanitize-recover=undefined
)

cc "${COMMON_FLAGS[@]}" -o build/user-samples/copy_overrun_case samples/user-binaries/copy_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/memmove_overrun_case samples/user-binaries/memmove_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/memset_overrun_case samples/user-binaries/memset_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/strcpy_overrun_case samples/user-binaries/strcpy_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/strncpy_overrun_case samples/user-binaries/strncpy_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/multi_overrun_case samples/user-binaries/multi_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/posix_memalign_overrun_case samples/user-binaries/posix_memalign_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/aligned_alloc_overrun_case samples/user-binaries/aligned_alloc_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/strdup_overrun_case samples/user-binaries/strdup_overrun_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/cache_release_twice samples/user-binaries/cache_release_twice.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/free_stack_slot samples/user-binaries/free_stack_slot.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/realloc_zero_double_free samples/user-binaries/realloc_zero_double_free.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/use_after_free_case samples/user-binaries/use_after_free_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/memory_leak_case samples/user-binaries/memory_leak_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/fd_leak_case samples/user-binaries/fd_leak_case.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_malloc_free samples/user-binaries/clean_malloc_free.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_realloc_grow samples/user-binaries/clean_realloc_grow.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_failed_realloc samples/user-binaries/clean_failed_realloc.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_realloc_null samples/user-binaries/clean_realloc_null.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_realloc_zero samples/user-binaries/clean_realloc_zero.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_posix_memalign samples/user-binaries/clean_posix_memalign.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_aligned_alloc samples/user-binaries/clean_aligned_alloc.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_strdup samples/user-binaries/clean_strdup.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memcpy samples/user-binaries/clean_bounded_memcpy.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memmove samples/user-binaries/clean_bounded_memmove.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memset samples/user-binaries/clean_bounded_memset.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_strcpy samples/user-binaries/clean_bounded_strcpy.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_strncpy samples/user-binaries/clean_bounded_strncpy.c
cc "${COMMON_FLAGS[@]}" -o build/user-samples/clean_fd_close samples/user-binaries/clean_fd_close.c

cc "${ASAN_FLAGS[@]}" -o build/user-samples-asan/use_after_free_case samples/user-binaries/use_after_free_case.c
cc "${ASAN_FLAGS[@]}" -o build/user-samples-asan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

cc "${LSAN_FLAGS[@]}" -o build/user-samples-lsan/direct_leak samples/user-binaries/memory_leak_case.c
cc "${LSAN_FLAGS[@]}" -o build/user-samples-lsan/indirect_leak samples/user-binaries/lsan_indirect_leak.c
cc "${LSAN_FLAGS[@]}" -o build/user-samples-lsan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

cc "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/signed_overflow samples/user-binaries/ubsan_signed_overflow.c
cc "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/shift_out_of_bounds samples/user-binaries/ubsan_shift_out_of_bounds.c
cc "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/null_pointer samples/user-binaries/ubsan_null_pointer.c
cc "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/misaligned_pointer samples/user-binaries/ubsan_misaligned_pointer.c
cc "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/bounds samples/user-binaries/ubsan_bounds.c
cc "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

echo "Built user-style samples under build/user-samples/"
echo "Built ASan-instrumented samples under build/user-samples-asan/"
echo "Built LSan-instrumented samples under build/user-samples-lsan/"
echo "Built UBSan-instrumented samples under build/user-samples-ubsan/"
