#!/usr/bin/env python3
import json, os, re, sys

def main():
    if len(sys.argv) < 4:
        print("usage: make_crashpack.py <findings_log> <console_log> <out_dir>")
        return 2
    findings_log, console_log, out_dir = sys.argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    findings = []
    pat = re.compile(r'^RE:FINDING:\s*(\{.*\})\s*$')
    with open(findings_log, 'r', errors='ignore') as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                try:
                    findings.append(json.loads(m.group(1)))
                except json.JSONDecodeError:
                    pass
    with open(os.path.join(out_dir, 'findings.json'), 'w') as f:
        json.dump(findings, f, indent=2)
    # copy console
    with open(console_log, 'rb') as src, open(os.path.join(out_dir, 'console.log'), 'wb') as dst:
        dst.write(src.read())
    print(f"wrote crashpack to {out_dir} with {len(findings)} findings")

if __name__ == '__main__':
    sys.exit(main())


