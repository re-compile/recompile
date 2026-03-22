#!/bin/bash

# Build script for RECC Sentinel example programs
# Compiles all example C programs with debug information

set -e

echo "Building RECC Sentinel example programs..."

# Build without builtin rewrites so the native agent sees the libc calls it
# attaches to under Linux native mode.
COMMON_FLAGS=(
  -g
  -O0
  -Wall
  -Wextra
  -std=c99
  -fno-omit-frame-pointer
  -fno-builtin
  -fno-builtin-memcpy
  -fno-builtin-free
  -fno-builtin-malloc
  -fno-builtin-calloc
  -fno-builtin-realloc
)

gcc "${COMMON_FLAGS[@]}" -o memcpy_overflow memcpy_overflow.c
gcc "${COMMON_FLAGS[@]}" -o double_free double_free.c
gcc "${COMMON_FLAGS[@]}" -o invalid_free invalid_free.c

echo "✓ All example programs built successfully"
echo "Available examples:"
echo "  - memcpy_overflow: Demonstrates heap buffer overflow"
echo "  - double_free: Demonstrates double free vulnerability"
echo "  - invalid_free: Demonstrates invalid free (freeing stack variable)"
