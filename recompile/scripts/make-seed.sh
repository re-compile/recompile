#!/usr/bin/env bash
set -euo pipefail

# Always work from repo root
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

UD="runtime/vm/user-data"
MD="runtime/vm/meta-data"
SEED="runtime/vm/seed.iso"

# Optional: bump instance-id automatically if it matches iid-re-*
if grep -qE '^instance-id:\s*iid-re-' "$MD"; then
  ts=$(date +%s)
  tmp=$(mktemp)
  awk -v ts="$ts" 'BEGIN{done=0}
    /^instance-id:/ && !done {print "instance-id: iid-re-" ts; done=1; next}
    {print}' "$MD" > "$tmp" && mv "$tmp" "$MD"
fi

tmpdir=$(mktemp -d)
cp -f "$UD" "$tmpdir/user-data"
cp -f "$MD" "$tmpdir/meta-data"

# IMPORTANT: volume name must be UPPERCASE exactly "CIDATA"
hdiutil makehybrid -hfs -joliet -iso -default-volume-name CIDATA \
  -o "$SEED" "$tmpdir" > /dev/null

rm -rf "$tmpdir"

echo "Seed ISO updated at $SEED"