#!/usr/bin/env bash
set -euo pipefail

# Generate complete crashpack from findings and logs
# Usage: generate_crashpack.sh [output_dir]

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root/recompile"

output_dir="${1:-build/crashpack-complete}"
findings_file="build/crashpack/findings.json"
console_log="build/.re/console.log"

echo "[crashpack] Generating complete crashpack to: $output_dir"

# Check if findings exist
if [[ ! -f "$findings_file" ]]; then
    echo "[crashpack] No findings found at $findings_file"
    echo "[crashpack] Run the VM first to generate findings"
    exit 1
fi

# Build the crashpack generator if needed
if [[ ! -f "target/debug/generate_crashpack" ]]; then
    echo "[crashpack] Building crashpack generator..."
    cargo build -p re-crashpack
fi

# Generate the crashpack
echo "[crashpack] Generating crashpack structure..."
./target/debug/generate_crashpack "$findings_file" "$output_dir" "$console_log"

# Copy additional artifacts if they exist
if [[ -f "build/re-findings.log" ]]; then
    cp "build/re-findings.log" "$output_dir/"
    echo "[crashpack] Copied re-findings.log"
fi

if [[ -f "build/.re/manifest.json" ]]; then
    cp "build/.re/manifest.json" "$output_dir/build.json"
    echo "[crashpack] Copied build manifest"
fi

# Create a summary
echo "[crashpack] Creating summary..."
cat > "$output_dir/README.md" << EOF
# RECC Crashpack

This crashpack contains all artifacts from a RECC Sentinel run.

## Contents

- \`findings.json\` - V1 schema findings from the Sentinel
- \`console.log\` - Console output from the VM run
- \`re-findings.log\` - Raw findings log with all events
- \`build.json\` - Build manifest information
- \`manifest.json\` - Crashpack metadata
- \`repro.sh\` - Reproduction script for the findings
- \`env/\` - Environment information (system, tools, runtime)
- \`bins/\` - Binary artifacts and metadata
- \`escalations/\` - Directories for escalation tool outputs
- \`sanitizer/\` - Sanitizer outputs
- \`gdb/\` - GDB outputs
- \`harnesses/\` - Repro harnesses
- \`inputs/\` - Input files
- \`symbols/\` - Symbol information

## Usage

To reproduce the findings:

\`\`\`bash
cd $output_dir
./repro.sh
\`\`\`

## Finding Details

$(jq -r '.[] | "- **\(.class)**: \(.id) (confidence: \(.confidence), severity: \(.severity))"' "$output_dir/findings.json" 2>/dev/null || echo "No findings found")

Generated on: $(date)
EOF

echo "[crashpack] Crashpack generated successfully at: $output_dir"
echo "[crashpack] Summary: $(jq 'length' "$output_dir/findings.json" 2>/dev/null || echo "0") findings"
