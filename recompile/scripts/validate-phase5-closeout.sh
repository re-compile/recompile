#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"
cd "$project_dir"

python3 - <<'PY'
import json
import pathlib
import re

root = pathlib.Path('.')
scan_paths = [
    root / 'rerun' / 'src',
    root / 're-escalate' / 'src',
    root / 're-crashpack' / 'src',
    root / 'runtime' / 'agent',
    root / 'runtime' / 'bpf',
]
allowed_suffixes = {'.rs', '.c', '.h'}
stale_surface_files = [
    root / 'Makefile',
    root / 'runtime' / 'bpf' / 'Makefile',
    *[
        path
        for path in sorted((root / 'scripts').glob('*.sh'))
        if path.name != 'validate-phase5-closeout.sh'
    ],
]
forbidden_patterns = [
    re.compile(r'copy_overrun_case'),
    re.compile(r'memmove_overrun_case'),
    re.compile(r'memset_overrun_case'),
    re.compile(r'strcpy_overrun_case'),
    re.compile(r'strncpy_overrun_case'),
    re.compile(r'cache_release_twice'),
    re.compile(r'free_stack_slot'),
    re.compile(r'fd_leak_case'),
    re.compile(r'crash_segv_case'),
    re.compile(r'memcpy_overflow'),
    re.compile(r'double_free\.c'),
    re.compile(r'invalid_free\.c'),
    re.compile(r'build/examples'),
    re.compile(r'user-samples'),
    re.compile(r'project-fixtures'),
    re.compile(r'hotfix', re.IGNORECASE),
    re.compile(r'golden', re.IGNORECASE),
    re.compile(r'RECC Sentinel'),
    re.compile(r'\bRECC\b'),
    re.compile(r'Week-1'),
    re.compile(r'later Phase [0-9]'),
    re.compile(r'Use VM mode'),
    re.compile(r'manifest-driven VM'),
]
stale_surface_patterns = [
    re.compile(r'hotfix', re.IGNORECASE),
    re.compile(r'hardcod', re.IGNORECASE),
    re.compile(r'Use VM mode', re.IGNORECASE),
    re.compile(r'manifest-driven VM', re.IGNORECASE),
    re.compile(r'\bqemu\b', re.IGNORECASE),
    re.compile(r'\bDarwin\b'),
    re.compile(r'\bHomebrew\b', re.IGNORECASE),
    re.compile(r'\bmacOS\b', re.IGNORECASE),
    re.compile(r'\bApple clang\b', re.IGNORECASE),
]
allowed_comments = [
    'Native mode is only supported on Linux',
]

def strip_rust_test_modules(text: str) -> str:
    marker = '#[cfg(test)]'
    idx = text.find(marker)
    if idx == -1:
        return text
    return text[:idx]

def relevant_text(path: pathlib.Path) -> str:
    text = path.read_text(errors='replace')
    if path.suffix == '.rs':
        text = strip_rust_test_modules(text)
    return text

violations = []
for base in scan_paths:
    if not base.exists():
        continue
    for path in base.rglob('*'):
        if not path.is_file() or path.suffix not in allowed_suffixes:
            continue
        if path.name.endswith('.bpf.o'):
            continue
        text = relevant_text(path)
        for line_no, line in enumerate(text.splitlines(), start=1):
            if any(allowed in line for allowed in allowed_comments):
                continue
            for pattern in forbidden_patterns:
                if pattern.search(line):
                    violations.append({
                        'scope': 'active_source',
                        'path': str(path),
                        'line': line_no,
                        'pattern': pattern.pattern,
                        'text': line.strip(),
                    })

for path in stale_surface_files:
    if not path.exists() or not path.is_file():
        continue
    text = path.read_text(errors='replace')
    for line_no, line in enumerate(text.splitlines(), start=1):
        if any(allowed in line for allowed in allowed_comments):
            continue
        for pattern in stale_surface_patterns:
            if pattern.search(line):
                violations.append({
                    'scope': 'build_script_surface',
                    'path': str(path),
                    'line': line_no,
                    'pattern': pattern.pattern,
                    'text': line.strip(),
                })

agent_path = root / 'runtime' / 'agent' / 're-mini.c'
if agent_path.exists():
    agent_text = agent_path.read_text(errors='replace')
    marker = 'static void drain_fd_leaks(void)'
    start = agent_text.find(marker)
    if start != -1:
        next_function = agent_text.find('\nstatic ', start + len(marker))
        drain_body = agent_text[start:next_function if next_function != -1 else len(agent_text)]
        exact_pid_filter = re.search(
            r'target_pid\s*>\s*0\s*&&\s*key\.pid\s*!=\s*\(__u32\)target_pid',
            drain_body,
        )
        allowed_check = drain_body.find('ensure_pid_allowed(key.pid)')
        if exact_pid_filter and (allowed_check == -1 or exact_pid_filter.start() < allowed_check):
            violations.append({
                'scope': 'agent_invariant',
                'path': str(agent_path),
                'line': agent_text[:start + exact_pid_filter.start()].count('\n') + 1,
                'pattern': 'fd_drain_exact_pid_prefilter',
                'text': 'drain_fd_leaks must route PID filtering through ensure_pid_allowed()',
            })

if violations:
    print(json.dumps({'violations': violations}, indent=2))
    raise SystemExit('phase5 closeout scan found sample-specific or hotfix-like active code')

print(json.dumps({
    'schema_version': '1.0',
    'purpose': 'phase5_closeout_scan',
    'scanned_paths': [str(path) for path in scan_paths],
    'stale_surface_files': [str(path) for path in stale_surface_files if path.exists()],
    'forbidden_pattern_count': len(forbidden_patterns),
    'stale_surface_pattern_count': len(stale_surface_patterns),
    'violations': [],
}, indent=2))
PY

printf '\n[phase5-closeout] active-path stale/hotfix scan passed\n'
