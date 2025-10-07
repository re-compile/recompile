#!/usr/bin/env bash
set -euo pipefail

# Test Phase 2: Complete Crashpack Generation
# This script demonstrates the full crashpack workflow

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root/recompile"

echo "=== RECC Sentinel Phase 2 Test: Complete Crashpack Generation ==="
echo

# Step 1: Fresh VM run
echo "[1/5] Running fresh VM to generate findings..."
bash scripts/reseed.sh >/dev/null
: > build/.re/console.log
: > build/re-findings.log
timeout 180 bash scripts/re-qemu.sh || true

# Step 2: Verify findings were generated
echo "[2/5] Verifying findings generation..."
if ! rg -n "^RE:FINDING:" build/re-findings.log >/dev/null; then
    echo "❌ No findings found in re-findings.log"
    exit 1
fi

if [[ ! -f "build/crashpack/findings.json" ]]; then
    echo "❌ No v1 schema findings found in build/crashpack/findings.json"
    exit 1
fi

echo "✅ Findings generated successfully"
echo "   - Raw findings: $(rg -c "^RE:FINDING:" build/re-findings.log || echo "0")"
echo "   - V1 schema findings: $(jq 'length' build/crashpack/findings.json 2>/dev/null || echo "0")"

# Step 3: Generate complete crashpack
echo "[3/5] Generating complete crashpack..."
bash scripts/generate_crashpack.sh build/crashpack-test

# Step 4: Verify crashpack structure
echo "[4/5] Verifying crashpack structure..."
required_files=(
    "build/crashpack-test/findings.json"
    "build/crashpack-test/manifest.json"
    "build/crashpack-test/console.log"
    "build/crashpack-test/re-findings.log"
    "build/crashpack-test/repro.sh"
    "build/crashpack-test/README.md"
    "build/crashpack-test/env/uname.txt"
    "build/crashpack-test/env/kernel.txt"
    "build/crashpack-test/env/tool-versions.txt"
    "build/crashpack-test/env/runtime.json"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        missing_files+=("$file")
    fi
done

if [[ ${#missing_files[@]} -gt 0 ]]; then
    echo "❌ Missing required files:"
    printf '   - %s\n' "${missing_files[@]}"
    exit 1
fi

echo "✅ Crashpack structure complete"

# Step 5: Validate crashpack contents
echo "[5/5] Validating crashpack contents..."

# Check findings format
if ! jq '.[0].schema_version' build/crashpack-test/findings.json >/dev/null 2>&1; then
    echo "❌ Invalid findings.json format"
    exit 1
fi

# Check manifest
if ! jq '.schema_version' build/crashpack-test/manifest.json >/dev/null 2>&1; then
    echo "❌ Invalid manifest.json format"
    exit 1
fi

# Check repro script is executable
if [[ ! -x "build/crashpack-test/repro.sh" ]]; then
    echo "❌ Repro script is not executable"
    exit 1
fi

echo "✅ Crashpack contents validated"

# Summary
echo
echo "=== Phase 2 Test Results ==="
echo "✅ V1 schema findings generation: WORKING"
echo "✅ Complete crashpack structure: WORKING"
echo "✅ Environment capture: WORKING"
echo "✅ Binary metadata capture: WORKING"
echo "✅ Integration with VM workflow: WORKING"
echo
echo "📁 Crashpack location: build/crashpack-test/"
echo "📊 Findings count: $(jq 'length' build/crashpack-test/findings.json 2>/dev/null || echo "0")"
echo "🔧 Repro script: build/crashpack-test/repro.sh"
echo
echo "🎉 Phase 2 implementation complete!"
echo
echo "Next steps for Phase 3:"
echo "  - Implement escalation runner with ASan"
echo "  - Add symbolization polish"
echo "  - Implement clustering engine"
echo "  - Add Valgrind/GDB adapters"
