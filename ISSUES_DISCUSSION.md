# re:compile Issues Discussion

*Updated after codebase audit and validation run. This document is for planning, not as a claim that all items below are already fixed.*

---

## Summary

The codebase is not blocked by the same set of issues it had earlier.

Several previously reported `re-mini.c` problems have already been fixed. The larger problem now is **integration correctness**:

- contracts do not line up across crates
- native and VM paths expect different output shapes
- escalation and crashpack logic still contain hardcoded example assumptions
- some “production” binaries are still demo/test drivers

The practical priority is:

1. native Linux stabilization
2. contract cleanup
3. de-hardcoding
4. only then feature work

---

## Part 1: Still-Open Blocking Issues

These are the issues that currently matter most for the Linux-native MVP.

### Issue #1: Docker Native Runs Need A Shared PID Namespace

**Location**: `recompile/runtime/agent/re-mini.c`, `recompile/runtime/bpf/*.bpf.c`  
**Status**: Open  
**Severity**: High

The current Linux-native path is now working for the three goldens in a host-native
arm64 Docker container, but only when the container shares the PID namespace with
the traced process.

Observed during validation:

- with the default container PID namespace, `rerun` launches a target with one PID
  while BPF events arrive with a different kernel-visible PID
- `re-mini --pid <pid>` then drops the real target events because `/proc/<kernel-pid>`
  is not visible inside the container namespace
- running Docker with `--privileged --pid=host` resolves the mismatch and the three
  goldens now emit differentiated findings

This is now an operational/documentation issue more than a probe-attachment crash.
The supported Docker-native invocation needs to make the shared PID namespace explicit.

### Issue #2: Readlink Race In PID Validation

**Location**: `recompile/runtime/agent/re-mini.c`  
**Status**: Open  
**Severity**: High

`re-mini` still validates filtered PIDs by reading `/proc/<pid>/exe`. If the process exits quickly, `readlink` fails and the event is dropped.

Relevant code:
- `ensure_pid_allowed()` at `recompile/runtime/agent/re-mini.c:803`
- `readlink()` at `recompile/runtime/agent/re-mini.c:827`

This is still a real source of missed findings for short-lived programs.

### Issue #3: Findings Contract Mismatch Across Components

**Location**: multiple crates  
**Status**: Open  
**Severity**: Critical

Different components disagree on what the canonical findings format is.

Examples:
- `re-mini` appends line-oriented findings to `findings.json` in `recompile/runtime/agent/re-mini.c:224`
- native mode writes streaming output to `re-findings.jsonl` in `recompile/rerun/src/native.rs:196`
- crashpack validation expects `findings.json` to parse as object or array in `recompile/rerun/src/cli.rs:172`

Decision now made:
- canonical persisted format should be `findings.json`
- `RE:FINDING:` and `re-findings.jsonl` are streaming/debug only

This needs to be enforced everywhere.

### Issue #4: VM And Native Orchestration Use Different Assumptions

**Location**: `recompile/vm-launcher/src/lib.rs`, `recompile/rerun/src/vm.rs`  
**Status**: Open  
**Severity**: High

`vm-launcher` writes raw findings to `build/re-findings.log`, while `rerun` post-processing expects `output_dir/findings.json`.

Relevant code:
- `build/re-findings.log` at `recompile/vm-launcher/src/lib.rs:78`
- `last_finding.json` write at `recompile/vm-launcher/src/lib.rs:109`
- `output_dir/findings.json` expectation at `recompile/rerun/src/vm.rs:85`

This is one reason VM mode is not trustworthy as the primary path.

### Issue #5: `rerun` Uses Broken Subprocess Wiring For Escalation And Harnesses

**Location**: `recompile/rerun/src/vm.rs`  
**Status**: Open  
**Severity**: Critical

`rerun` shells out to binaries with arguments they do not support.

Examples:
- escalation call at `recompile/rerun/src/vm.rs:130`
- harness call at `recompile/rerun/src/vm.rs:193`
- escalation binary only supports `<findings_file> [config_file]` at `recompile/re-escalate/src/bin/run_escalation.rs:15`

This should be replaced with direct library integration.

### Issue #6: Escalation Is Hardcoded To Example Names

**Location**: `recompile/re-escalate/src/runner.rs`  
**Status**: Open  
**Severity**: High

Escalation resolves source files and binaries by interpolating `finding.class` into paths like `examples/<class>.c`.

Relevant code:
- source lookup at `recompile/re-escalate/src/runner.rs:203`
- binary lookup at `recompile/re-escalate/src/runner.rs:225`

This is not modular and breaks immediately for real binaries or even the current goldens (`heap_overflow` is not a filename).

### Issue #7: Crashpack Generation Still Assumes A Specific Example Binary

**Location**: `recompile/re-crashpack/src/bin/generate_crashpack.rs`  
**Status**: Fixed  
**Severity**: Resolved

This was previously hardcoded to analyze `build/examples/invalid_free`.

Current code accepts explicit inputs:

- `<findings_file> <output_dir>`
- optional `--binary <path>`
- optional `--console-log <path>`
- optional `--input <path>`

This is now a real CLI shape and no longer tied to one example.

### Issue #8: `recc` Is Not Yet A Reliable Native Wrapper

**Location**: `recompile/recc/src/main.rs`  
**Status**: Open  
**Severity**: High

`recc` currently:

- prefers `clang++` or `g++` unconditionally
- injects `-Wl,--export-dynamic`

Relevant code:
- compiler detection at `recompile/recc/src/main.rs:61`
- linker flag injection at `recompile/recc/src/main.rs:30`

This already failed in local validation on macOS, and it needs to be made Linux-native correct before it can be trusted as the default wrapper path.

### Issue #9: Symbolizer Logic And Tests Are Not Sound

**Location**: `recompile/re-rules/src/symbolizer.rs`  
**Status**: Fixed  
**Severity**: Resolved

This was failing during the initial audit. It has since been repaired and the targeted test suite now passes.

Relevant code:
- LLVM implementation at `recompile/re-rules/src/symbolizer.rs:177`
- LLVM single lookup at `recompile/re-rules/src/symbolizer.rs:206`
- addr2line implementation at `recompile/re-rules/src/symbolizer.rs:301`
- addr2line single lookup at `recompile/re-rules/src/symbolizer.rs:330`
- tests at `recompile/re-rules/src/symbolizer.rs:399`

### Issue #10: Harness Binary Is Still A Demo Driver

**Location**: `recompile/re-harness/src/bin/generate_harness.rs`  
**Status**: Fixed  
**Severity**: Resolved

This was previously a demo driver. It now accepts a findings file and output directory as explicit inputs.

Relevant code:
- main function at `recompile/re-harness/src/bin/generate_harness.rs:55`

It is still not fully wired into the top-level supported flow, but it is no longer a hardcoded `/tmp` demo binary.

### Issue #11: Docker Bootstrap Is Missing

**Location**: repo root / dev workflow  
**Status**: Open  
**Severity**: High

This was true at the start of the audit. It is now partially addressed, but still needs to be treated as a supported workflow and kept in sync with the real runtime.

We do have a partial helper:
- `scripts/docker-setup.sh`

What changed:

- a repo `Dockerfile` now exists
- `scripts/docker-setup.sh` now prepares the native workspace automatically

What is still required:

- keep the bootstrap path aligned with the actual supported runtime
- document the exact container invocation as part of the primary dev flow
- make `--privileged --pid=host` part of the supported Docker-native command

---

## Part 2: Previously Reported Issues That Are Now Fixed

These should not continue to drive planning as if they were still open.

### Fixed: Single-PID Locking In `re-mini`

Old concern: agent locked onto the first PID and dropped the rest.

Current code tracks multiple PIDs:
- `tracked_pids` at `recompile/runtime/agent/re-mini.c:120`
- `get_pid_entry()` at `recompile/runtime/agent/re-mini.c:782`

Status: fixed.

### Fixed: Hardcoded ARM64 `libc.so.6` In `re-mini`

Current code now searches common libc paths and detects a usable path at runtime:
- search paths at `recompile/runtime/agent/re-mini.c:33`
- detection at `recompile/runtime/agent/re-mini.c:69`

Status: fixed.

### Fixed: Hardcoded VM Output Path In `re-mini`

Current code defaults output to stdout unless `--out` is provided:
- `out_path` declaration at `recompile/runtime/agent/re-mini.c:113`

Status: fixed.

### Fixed: `system("mkdir -p ...")` Injection Risk

Current code uses `mkdir_p()`:
- helper at `recompile/runtime/agent/re-mini.c:45`
- finding emission path at `recompile/runtime/agent/re-mini.c:213`

Status: fixed.

### Fixed: `popen()` Symbolizer Injection Risk

Current code uses fork/exec for symbolization:
- `run_symbolizer()` at `recompile/runtime/agent/re-mini.c:933`

Status: fixed.

### Fixed: `vmlinux.h` Autogeneration In BPF Makefile

Current code autogenerates `vmlinux.h` and can fall back to a minimal header:
- `vmlinux.h` target at `recompile/runtime/bpf/Makefile:55`

Status: fixed.

### Fixed: Hardcoded Crashpack Output Path In `re-mini`

Current code takes `--crashpack` and defaults to `./crashpack`:
- option help at `recompile/runtime/agent/re-mini.c:1122`
- arg parse at `recompile/runtime/agent/re-mini.c:1145`

Status: fixed.

---

## Part 3: Hardcoded Or Hotfixed Areas To Remove

These are the areas most likely to produce “all goldens report the same thing” or other cooked behavior.

### A. Example-Coupled Escalation

- `recompile/re-escalate/src/runner.rs:206`
- `recompile/re-escalate/src/runner.rs:228`

This is not robust and can silently route unrelated findings into the wrong file/binary lookup.

### B. Hardcoded Crashpack Example Binary

- `recompile/re-crashpack/src/bin/generate_crashpack.rs:36`

This is direct example coupling.

### C. Stub Agent That Emits A Fake Sample Finding

- `recompile/runtime/agent/src/main.rs:28`

This is not the active runtime path for native work, but it is still misleading and should not be mistaken for production behavior.

### D. Demo Harness Binary Used As If It Were Production

- `recompile/re-harness/src/bin/generate_harness.rs:7`

The library may be useful; the current binary is a demo/test program.

### E. Script Layer With Overlapping “happy path” Assumptions

There are many scripts that appear to validate the system while depending on stale or partial plumbing.

This should be cleaned up only after the native path is stable.

---

## Part 4: Recommended Fix Order

1. Canonical findings contract
2. Native `rerun --native` stabilization for the three goldens
3. Remove hardcoded example coupling from escalation and crashpack
4. Replace cargo-in-cargo orchestration with library calls
5. Fix `recc` wrapper correctness for Linux-native use
6. Add Docker bootstrap automation
7. Clean up scripts
8. Only then move to CI and feature work

---

## Part 5: What We Are Explicitly Deferring

- Rust agent
- macOS-first support
- VM-first support
- CI rollout
- broader Phase 2 observability work
