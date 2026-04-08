# re:compile Issues Discussion

*Updated after the Linux-native stabilization pass and Docker validation of the three goldens.*

---

## Summary

The old blockers are no longer the main story.

The active Linux-native path is now working on the supported Docker flow:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

The remaining work is mostly **release-candidate cleanup**, not broad architecture repair.

What still matters now:

1. keep the Docker-native workflow explicit and repeatable
2. add regression coverage for the three goldens
3. remove stale code and warnings from active crates
4. keep symbolization good enough for user-visible primary locations

---

## Part 1: Current Issues And Constraints

### Issue #1: Docker Native Requires Shared PID Namespace

**Location**: `recompile/rerun/src/native.rs`, `recompile/runtime/agent/re-mini.c`
**Status**: Known constraint
**Severity**: High operationally

The supported native Docker flow requires `--privileged --pid=host`.

Without a shared PID namespace:

- the launched target PID seen by `rerun` and the kernel-visible PID seen by BPF events diverge
- PID-scoped filtering drops the real events
- the analysis can appear to succeed while producing no findings

This is no longer a hidden correctness bug. It is now a documented support constraint and the code errors early in the unsupported case.

### Issue #2: `invalid_free` Source Location May Still Be Missing

**Location**: `recompile/runtime/agent/re-mini.c`, native Docker arm64 builds
**Status**: Known limitation
**Severity**: Medium

After the symbolization and launch fixes:

- `memcpy_overflow` and `double_free` resolve user-code source paths correctly
- `invalid_free` still may not resolve beyond a raw binary offset / `_start` frame on the current arm64 Docker build

This does **not** block the finding class, severity, or provenance. It is a symbol-quality limitation, not a contract or plumbing failure.

### Issue #3: Active Crates Still Have Warning-Level Stale Code

**Location**: `recompile/re-crashpack`, `recompile/re-escalate`, `recompile/re-rules`
**Status**: Open
**Severity**: Medium

`cargo check` on the active workspace still reports warning-level dead code and unused imports.

Examples seen in the current state:

- unused re-exports/imports in `re-crashpack/src/lib.rs`
- unused config re-export and parameter in `re-escalate`
- dead code and unused imports in `re-rules`, especially the test/demo binary path

These are not blocking correctness issues, but they still make the supported OSS path look rough.

### Issue #4: Regression Coverage Needs To Stay Canonical

**Location**: repo workflow / Docker validation path
**Status**: Reduced
**Severity**: Medium

The repo now has a supported regression script:

- `recompile/scripts/validate-phase1.sh`
- `cd recompile && make phase1`

That fixes the worst ad hoc problem, but the discipline still matters:

- docs should keep pointing at that one command
- future cleanup should not reintroduce parallel “happy path” scripts that drift from it

---

## Part 2: Issues That Are Now Resolved

### Resolved: Findings Contract Mismatch Across Components

The code now treats:

- `findings.json` as the canonical persisted format
- `RE:FINDING:` and `re-findings.jsonl` as streaming/debug only

This is now aligned across the active native/crashpack/escalation flow.

### Resolved: VM And Native Mixed Assumptions In The Supported Path

VM mode is no longer treated as part of the supported workflow.

The stale VM launcher path and related stub/deferred code were removed from the active workspace path, and `rerun` is native-first.

### Resolved: Broken Subprocess Wiring For Escalation And Harnesses

The active path no longer depends on the old VM-era subprocess orchestration.

The supported flow now uses direct library wiring in the active native path.

### Resolved: Escalation Guessing Source/Binary Paths From Example Names

Escalation now consumes explicit finding provenance instead of inferring file paths from `finding.class` or binary basenames.

### Resolved: Crashpack Generation Assuming One Example Binary

Crashpack generation now accepts real inputs and no longer assumes one fixed example.

### Resolved: Symbolizer Test Failures In `re-rules`

The earlier symbolizer recursion/test failures were repaired and the targeted tests pass.

### Resolved: Demo/Stale Workspace Components In The Active Path

The following stale or deferred components were removed from the active workspace path:

- `vm-launcher`
- Rust agent stubs
- VM runtime remnants
- LSP/MCP stubs
- stale helper/generated assets tied to removed workflows

---

## Part 3: Recommended Next Order

1. Keep the supported Docker-native invocation explicit everywhere
2. Add one repeatable regression path for the three goldens
3. Clean warning-level stale code from active crates
4. Polish symbolization only where it improves user-visible findings
5. Then decide what belongs in Phase 2 versus remaining deferred

---

## Part 4: What We Are Explicitly Deferring

- VM-first support
- macOS-first support
- Rust runtime agent
- `recc` as a required MVP path
- CI rollout before the regression path is locked
- broader Phase 2 observability work
