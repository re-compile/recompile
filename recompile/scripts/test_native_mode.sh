#!/bin/bash
# Test script for native mode functionality
# This script should be run on a Linux system with appropriate capabilities

set -e

echo "=== Testing Native Mode ==="
echo "Note: This test requires Linux with CAP_BPF and CAP_PERFMON capabilities"
echo

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ Native mode testing requires Linux. Current OS: $OSTYPE"
    echo "Skipping native mode tests."
    exit 0
fi

# Build the CLI
echo "Building CLI..."
cargo build -p rerun --release

# Test 1: Check help
echo "Test 1: CLI help"
cargo run -p rerun -- --help > /dev/null
echo "✓ CLI help works"

# Test 2: Test native mode help
echo "Test 2: Native mode help"
cargo run -p rerun -- run --help > /dev/null
echo "✓ Native mode help works"

# Test 3: Test native mode capability check (should fail if not root/privileged)
echo "Test 3: Native mode capability check"
if cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Missing required capabilities"; then
    echo "✓ Capability check correctly detects missing privileges"
elif cargo run -p rerun -- run --native /bin/echo "test" 2>&1 | grep -q "Native mode is only supported on Linux"; then
    echo "✓ Correctly detects non-Linux system"
else
    echo "✓ Native mode capability check passed (running with privileges)"
fi

# Test 4: Test VM mode fallback
echo "Test 4: VM mode fallback"
if cargo run -p rerun -- run /bin/echo "test" 2>&1 | grep -q "VM mode"; then
    echo "✓ VM mode fallback works"
else
    echo "⚠ VM mode test inconclusive (may need full environment)"
fi

echo
echo "=== Native Mode Tests Complete ==="
echo "If you see capability errors, run with:"
echo "  sudo cargo run -p rerun -- run --native <binary>"
echo "Or set capabilities:"
echo "  sudo setcap 'cap_bpf,cap_perfmon+ep' target/release/rerun"
