#!/usr/bin/env bash
set -euo pipefail

mkdir -p build/user-samples build/user-samples-asan build/user-samples-lsan build/user-samples-ubsan

CC=${CC:-cc}
CXX=${CXX:-c++}

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

TSAN_FLAGS=(
  -g
  -O1
  -fno-omit-frame-pointer
  -fsanitize=thread
  -pthread
)

BUILD_TSAN=${BUILD_TSAN:-0}

"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/copy_overrun_case samples/user-binaries/copy_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/memmove_overrun_case samples/user-binaries/memmove_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/memset_overrun_case samples/user-binaries/memset_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/strcpy_overrun_case samples/user-binaries/strcpy_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/strncpy_overrun_case samples/user-binaries/strncpy_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/multi_overrun_case samples/user-binaries/multi_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/interior_overrun_case samples/user-binaries/interior_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/posix_memalign_overrun_case samples/user-binaries/posix_memalign_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/aligned_alloc_overrun_case samples/user-binaries/aligned_alloc_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/strdup_overrun_case samples/user-binaries/strdup_overrun_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/cache_release_twice samples/user-binaries/cache_release_twice.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/free_stack_slot samples/user-binaries/free_stack_slot.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/realloc_zero_double_free samples/user-binaries/realloc_zero_double_free.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/use_after_free_case samples/user-binaries/use_after_free_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/memory_leak_case samples/user-binaries/memory_leak_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/fd_open_leak_case samples/user-binaries/fd_open_leak_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/fd_leak_case samples/user-binaries/fd_leak_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/fd_double_close_case samples/user-binaries/fd_double_close_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/fd_invalid_close_case samples/user-binaries/fd_invalid_close_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/fd_dup_leak_case samples/user-binaries/fd_dup_leak_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/fd_dup2_leak_case samples/user-binaries/fd_dup2_leak_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/crash_segv_case samples/user-binaries/crash_segv_case.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_malloc_free samples/user-binaries/clean_malloc_free.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_realloc_grow samples/user-binaries/clean_realloc_grow.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_failed_realloc samples/user-binaries/clean_failed_realloc.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_realloc_null samples/user-binaries/clean_realloc_null.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_realloc_zero samples/user-binaries/clean_realloc_zero.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_posix_memalign samples/user-binaries/clean_posix_memalign.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_aligned_alloc samples/user-binaries/clean_aligned_alloc.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_strdup samples/user-binaries/clean_strdup.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memcpy samples/user-binaries/clean_bounded_memcpy.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_interior_memcpy samples/user-binaries/clean_interior_memcpy.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memmove samples/user-binaries/clean_bounded_memmove.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_memset samples/user-binaries/clean_bounded_memset.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_strcpy samples/user-binaries/clean_bounded_strcpy.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_bounded_strncpy samples/user-binaries/clean_bounded_strncpy.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_fd_close samples/user-binaries/clean_fd_close.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_fd_dup_close samples/user-binaries/clean_fd_dup_close.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_fd_dup2_replace samples/user-binaries/clean_fd_dup2_replace.c
"$CC" "${COMMON_FLAGS[@]}" -o build/user-samples/clean_fd_fcntl_dup_close samples/user-binaries/clean_fd_fcntl_dup_close.c

"$CXX" -std=c++17 "${COMMON_FLAGS[@]}" -o build/user-samples/clean_cxx_new_delete samples/user-binaries/clean_cxx_new_delete.cpp
"$CXX" -std=c++17 "${COMMON_FLAGS[@]}" -o build/user-samples/cxx_new_free_mismatch samples/user-binaries/cxx_new_free_mismatch.cpp
"$CXX" -std=c++17 "${COMMON_FLAGS[@]}" -o build/user-samples/cxx_malloc_delete_mismatch samples/user-binaries/cxx_malloc_delete_mismatch.cpp
"$CXX" -std=c++17 "${COMMON_FLAGS[@]}" -o build/user-samples/cxx_new_array_delete_mismatch samples/user-binaries/cxx_new_array_delete_mismatch.cpp
"$CXX" -std=c++17 "${COMMON_FLAGS[@]}" -o build/user-samples/cxx_new_delete_array_mismatch samples/user-binaries/cxx_new_delete_array_mismatch.cpp

"$CC" "${ASAN_FLAGS[@]}" -o build/user-samples-asan/use_after_free_case samples/user-binaries/use_after_free_case.c
"$CC" "${ASAN_FLAGS[@]}" -o build/user-samples-asan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

"$CC" "${LSAN_FLAGS[@]}" -o build/user-samples-lsan/direct_leak samples/user-binaries/memory_leak_case.c
"$CC" "${LSAN_FLAGS[@]}" -o build/user-samples-lsan/indirect_leak samples/user-binaries/lsan_indirect_leak.c
"$CC" "${LSAN_FLAGS[@]}" -o build/user-samples-lsan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

"$CC" "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/signed_overflow samples/user-binaries/ubsan_signed_overflow.c
"$CC" "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/shift_out_of_bounds samples/user-binaries/ubsan_shift_out_of_bounds.c
"$CC" "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/null_pointer samples/user-binaries/ubsan_null_pointer.c
"$CC" "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/misaligned_pointer samples/user-binaries/ubsan_misaligned_pointer.c
"$CC" "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/bounds samples/user-binaries/ubsan_bounds.c
"$CC" "${UBSAN_FLAGS[@]}" -o build/user-samples-ubsan/clean_malloc_free samples/user-binaries/clean_malloc_free.c

if [[ "$BUILD_TSAN" == "1" ]]; then
  mkdir -p build/user-samples-tsan
  "$CC" -std=c11 "${TSAN_FLAGS[@]}" -o build/user-samples-tsan/data_race samples/user-binaries/tsan_data_race.c
  "$CC" -std=c11 "${TSAN_FLAGS[@]}" -o build/user-samples-tsan/clean_mutex samples/user-binaries/tsan_clean_mutex.c
  "$CC" -std=c11 "${TSAN_FLAGS[@]}" -o build/user-samples-tsan/clean_atomic samples/user-binaries/tsan_clean_atomic.c
fi

echo "Built user-style samples under build/user-samples/"
echo "Built ASan-instrumented samples under build/user-samples-asan/"
echo "Built LSan-instrumented samples under build/user-samples-lsan/"
echo "Built UBSan-instrumented samples under build/user-samples-ubsan/"
if [[ "$BUILD_TSAN" == "1" ]]; then
  echo "Built TSan-instrumented samples under build/user-samples-tsan/"
fi
