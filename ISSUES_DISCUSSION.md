# re:compile Issues Discussion

*Updated after the Phase 1 RC gate slice.*

---

## Summary

The old blockers are no longer the main story.

The active Linux-native path is now working on the supported Docker flow:

- `memcpy_overflow` -> `heap_overflow`
- `double_free` -> `double_free`
- `invalid_free` -> `invalid_free`

Phase 1 is complete for the supported Linux-native MVP scope.

What still matters now:

1. keep the Docker-native workflow explicit and repeatable
2. add regression coverage for the three goldens
3. keep clean user-code patterns producing zero findings
4. keep symbolization good enough for user-visible primary locations
5. keep any remaining arm64 source-location gaps scoped as symbolization polish unless they break user-style findings

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

After the symbolization and launch fixes, user-code source paths are good for the current user-style finding samples. Some `invalid_free` paths may still degrade to raw binary offsets on the current arm64 Docker build.

This should not block the finding class, severity, or provenance, but it remains a finding-quality issue after the false-positive gate is closed.

### Issue #3: Phase 1 MVP Is Complete

**Location**: roadmap / release criteria
**Status**: Resolved
**Severity**: Medium

The major plumbing and user-code correctness blockers for the current MVP scope are no longer open.

What is now locked:

- the baseline regression path exists and passes
- the user-style external smoke path exists and passes
- the clean `malloc/free` and bounded-`memcpy` no-finding samples exist and pass
- stale output directories no longer leak findings across runs
- allocator tracking no longer depends on implicit BPF map-key padding
- the active-path crate warnings have been trimmed
- docs/scripts now point at the same supported flow
- `make rc` exists as the single Phase 1 release-candidate gate

For the current MVP definition, Phase 1 is complete. New feature work should go through Phase 2.

### Issue #4: Regression Coverage Needs To Stay Canonical

**Location**: repo workflow / Docker validation path
**Status**: Reduced
**Severity**: Medium

The repo now has a supported regression script:

- `recompile/scripts/validate-phase1.sh`
- `cd recompile && make phase1`
- `recompile/scripts/validate-binary.sh` for one external binary
- `cd recompile && make external-smoke` for user-style non-golden samples
- `recompile/samples/user-binaries/clean_malloc_free.c` and `recompile/samples/user-binaries/clean_bounded_memcpy.c` for the no-finding path

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

### Resolved: Stale Output Directories Could Re-report Old Findings

`rerun run --output <dir>` now removes known generated crashpack artifacts before a new analysis. This prevents old `findings.json`, `.re`, `bins`, logs, and manifests from being treated as current-run output.

### Resolved: Valid Bounded `memcpy` Could Report `invalid_free`

Allocator tracking used a shared BPF map key with implicit padding. The heap and copy probes could observe the same pointer with different key bytes, so the allocation was visible during `memcpy` but missing at `free`.

The key now has explicit zero-initialized padding, and `clean_bounded_memcpy` is part of `make external-smoke` as an expected no-finding regression.

---

## Part 3: Recommended Next Order

1. Keep the supported Docker-native invocation explicit everywhere
2. Keep `make rc` as the canonical Phase 1 guardrail
3. Treat remaining source-path resolution gaps as Phase 2 polish unless they break user-style findings
4. Start Phase 2 with real escalation adapters or broader user-binary regressions

---

## Part 4: What We Are Explicitly Deferring

- VM-first support
- macOS-first support
- Rust runtime agent
- `recc` as a required MVP path
- CI rollout before the regression path is locked
- broader Phase 2 observability work
