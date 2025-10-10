#!/bin/bash
# Generic build script template for harnesses

set -e

HARNESS_NAME="{{harness_name}}"
SOURCE_FILE="${HARNESS_NAME}.c"
BINARY_FILE="${HARNESS_NAME}"

echo "Building harness: ${HARNESS_NAME}"

if [ ! -f "${SOURCE_FILE}" ]; then
    echo "Error: Source file ${SOURCE_FILE} not found"
    exit 1
fi

# Compile with sanitizer flags
echo "Compiling with flags: {{build_flags}}"
gcc {{build_flags}} -o "${BINARY_FILE}" "${SOURCE_FILE}"

echo "Build completed: ${BINARY_FILE}"
echo "Run with: ./${BINARY_FILE}"
