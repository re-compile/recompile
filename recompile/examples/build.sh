#!/bin/bash

# Build script for RECC Sentinel example programs
# Compiles all example C programs with debug information

set -e

echo "Building RECC Sentinel example programs..."

# Compile with debug information and common sanitizer flags
gcc -g -O0 -Wall -Wextra -std=c99 -o memcpy_overflow memcpy_overflow.c
gcc -g -O0 -Wall -Wextra -std=c99 -o double_free double_free.c  
gcc -g -O0 -Wall -Wextra -std=c99 -o invalid_free invalid_free.c

echo "✓ All example programs built successfully"
echo "Available examples:"
echo "  - memcpy_overflow: Demonstrates heap buffer overflow"
echo "  - double_free: Demonstrates double free vulnerability"
echo "  - invalid_free: Demonstrates invalid free (freeing stack variable)"
