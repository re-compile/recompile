#!/usr/bin/env bash
set -euo pipefail
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

cp -f runtime/vm/user-data runtime/vm/meta-data "$tmp/"

awk -v ts="$(date +%s)" '
  /^instance-id:/ {print "instance-id: iid-re-" ts; next}
  {print}
' "$tmp/meta-data" > "$tmp/meta-data.new" && mv "$tmp/meta-data.new" "$tmp/meta-data"

rm -f runtime/vm/seed.iso
hdiutil makehybrid -hfs -joliet -iso -default-volume-name CIDATA \
  -o runtime/vm/seed.iso "$tmp"

mnt="$(mktemp -d)"
hdiutil attach -readonly -mountpoint "$mnt" runtime/vm/seed.iso >/dev/null
echo "[seed] Verifying..."
rg -n "re-firstboot|RE:READY|bpftool" "$mnt/user-data" || true
hdiutil detach "$mnt" >/dev/null
echo "[seed] OK: runtime/vm/seed.iso"