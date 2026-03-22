# re:compile Roadmap

## Current Direction

The project is now **Linux-native first**.

We are explicitly **not** treating macOS VM mode as the primary development path anymore. The macOS VM path has too many host/guest mismatches:

- Apple clang vs Linux clang
- Mach-O vs ELF binaries
- ARM64 guest assumptions leaking into the host workflow
- cloud-init and QEMU setup overhead obscuring real native progress

The immediate goal is a **real native Linux MVP running inside Docker on Linux** with the three goldens:

- `memcpy_overflow`
- `double_free`
- `invalid_free`

---

## Principles

Before adding features, the system needs to be made consistent and modular.

- No hardcoded golden-specific behavior
- No cargo-in-cargo runtime orchestration
- No “test passes because paths happen to line up” integrations
- One canonical persisted findings format
- One supported dev path for the MVP

---

## Phase 0 - Native Stabilization

**Status**: Current priority  
**Goal**: make native Linux deterministic and reproducible before any Phase 2 feature work

### Acceptance Criteria

- `recc` can compile binaries correctly on Linux
- `rerun run --native <binary>` works for all three goldens
- Findings persist canonically as `findings.json`
- Streaming/debug lines stay in `re-findings.jsonl` only
- Crashpack generation consumes the canonical findings contract
- No hardcoded mapping to one example binary or one example source file
- Native workflow works in Docker with one bootstrap path

### Work Items

1. **Canonicalize findings contracts**
   - Persist `findings.json` as the canonical JSON array
   - Treat `RE:FINDING:` lines and `re-findings.jsonl` as streaming/debug only
   - Make native, crashpack, escalation, and validation consume the same schema

2. **Stabilize native execution path**
   - Make `rerun --native` the primary supported path
   - Validate the C agent (`re-mini`) as the only runtime agent for now
   - Ensure no event-routing assumptions depend on VM-only paths

3. **Remove hardcoded example coupling**
   - Eliminate class-to-example path assumptions in escalation
   - Eliminate hardcoded crashpack binary assumptions
   - Remove stub/demo binaries from runtime code paths

4. **Repair integration plumbing**
   - Replace cargo-in-cargo subprocess orchestration with direct library wiring
   - Implement `rerun escalate` properly
   - Align crashpack generation, escalation, and harness generation around shared inputs

5. **Fix correctness bugs exposed by tests**
   - Fix symbolizer test failure
   - Fix schema/format mismatches
   - Fix any cases where all goldens converge to the same finding due to bad plumbing

6. **Docker bootstrap**
   - Add a supported Docker image / bootstrap path
   - Container startup should install the required Linux/BPF toolchain and prepare the workspace automatically
   - Document one command to get from container boot to runnable native workflow

7. **Repair libc uprobe stability**
   - Validate that attaching to `malloc`, `calloc`, `realloc`, `free`, and `memcpy` does not crash traced processes
   - Eliminate any brittle symbol/offset attachment logic
   - Do not accept a native MVP until the three goldens produce differentiated findings without probe-induced crashes

### Non-Goals In Phase 0

- Rust agent
- macOS-first development
- VM parity
- LSP/MCP work
- CI hardening
- new detection classes

---

## Phase 1 - Native MVP Release Candidate

**Goal**: a small but honest OSS release candidate

### Scope

- Native Linux only
- Three validated goldens
- Stable JSON findings contract
- Basic crashpack output
- Minimal but real escalation entry point

### Acceptance Criteria

- Docker-native setup is documented and repeatable
- The three goldens produce the correct finding classes
- There is no known golden-specific hardcoding in the runtime path
- Docs match actual behavior

---

## Phase 2 - Feature Expansion

Only start this once Phase 0 and Phase 1 are stable.

### Candidate Work

- Use-after-free improvements
- Memory leak detection
- FD leak detection
- Better symbolization
- Better escalation adapters

These should be planned only after the core native contract is stable.

---

## Deferred

- VM mode as a first-class workflow
- macOS support
- Rust runtime agent
- LLVM pass wiring
- LSP/MCP
- CI rollout
- broader observability features

---

## Immediate Execution Order

1. Canonical findings contract
2. Native path stabilization for the three goldens
3. Repair libc uprobe stability
4. Remove hardcoded/example-specific behavior
5. Fix crashpack/escalation/harness plumbing
6. Add Docker bootstrap automation
7. Then document and test
