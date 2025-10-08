#!/bin/bash

# Generate complete crashpack with escalation
# Usage: generate_crashpack_with_escalation.sh <output_dir>

set -e

output_dir="${1:-build/crashpack-with-escalation}"

echo "[crashpack] Generating complete crashpack with escalation to: $output_dir"

# Generate base crashpack first
echo "[crashpack] Generating base crashpack..."
bash scripts/generate_crashpack.sh "$output_dir"

# Run escalation on the findings
echo "[crashpack] Running escalation on findings..."
if [ -f "$output_dir/findings.json" ]; then
    echo "[crashpack] Running ASan escalation..."
    cargo run --bin run_escalation -- "$output_dir/findings.json" || {
        echo "[crashpack] Warning: Escalation failed, continuing with base crashpack"
    }
    
    # Copy escalation results to crashpack
    if [ -d "build/escalations" ]; then
        echo "[crashpack] Copying escalation results..."
        cp -r build/escalations "$output_dir/"
        
        # Update manifest to include escalation info
        echo "[crashpack] Updating manifest with escalation info..."
        
        # Count escalation results
        asan_results=$(find "$output_dir/escalations/asan" -name "*.log" 2>/dev/null | wc -l)
        valgrind_results=$(find "$output_dir/escalations/valgrind" -name "*.log" 2>/dev/null | wc -l)
        gdb_results=$(find "$output_dir/escalations/gdb" -name "*.log" 2>/dev/null | wc -l)
        
        # Update README
        cat >> "$output_dir/README.md" << EOF

## Escalation Results

This crashpack includes escalation results from debugging tools:

- **ASan results**: $asan_results files
- **Valgrind results**: $valgrind_results files  
- **GDB results**: $gdb_results files

### Viewing Escalation Results

To view the escalation results:

\`\`\`bash
# View ASan results
find $output_dir/escalations/asan -name "*.log" -exec echo "=== {} ===" \; -exec cat {} \;

# View Valgrind results  
find $output_dir/escalations/valgrind -name "*.log" -exec echo "=== {} ===" \; -exec cat {} \;

# View GDB results
find $output_dir/escalations/gdb -name "*.log" -exec echo "=== {} ===" \; -exec cat {} \;
\`\`\`

EOF
    fi
else
    echo "[crashpack] No findings.json found, skipping escalation"
fi

echo "[crashpack] Complete crashpack with escalation generated at: $output_dir"
echo "[crashpack] Summary:"
echo "  - Findings: $(jq 'length' "$output_dir/findings.json" 2>/dev/null || echo "0")"
echo "  - ASan results: $(find "$output_dir/escalations/asan" -name "*.log" 2>/dev/null | wc -l)"
echo "  - Valgrind results: $(find "$output_dir/escalations/valgrind" -name "*.log" 2>/dev/null | wc -l)"
echo "  - GDB results: $(find "$output_dir/escalations/gdb" -name "*.log" 2>/dev/null | wc -l)"
