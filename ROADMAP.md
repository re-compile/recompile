# re:compile Roadmap

## Current Direction

The project is now **Linux-native first**.

The supported MVP path is:

- Linux-native execution inside Docker
- `rerun run --native <binary>`
- the C runtime agent at `recompile/runtime/agent/re-mini.c`
- canonical persisted output in `findings.json`

We are explicitly **not** treating VM mode, macOS-first development, or the Rust agent as part of the current delivery path.

The validated goldens are:

- `memcpy_overflow`
- `double_free`
- `invalid_free`

---

## Principles

Before adding features, keep the core path modular and honest.

- No hardcoded golden-specific behavior
- No cargo-in-cargo runtime orchestration
- One canonical persisted findings format
- One supported native workflow for the MVP
- Planning docs must match what the repo actually does

---

## Phase 0 - Native Stabilization

**Status**: Exit criteria met on the supported Docker-native path
**Goal**: make native Linux deterministic and reproducible before release-candidate work

### Exit Criteria Met

- `rerun run --native <binary>` works for all three goldens
- Findings persist canonically as `findings.json`
- Streaming/debug lines stay in `re-findings.jsonl` only
- Crashpack generation consumes the canonical findings contract
- Escalation uses explicit provenance instead of example-name guessing
- No known golden-specific hardcoding remains in the active runtime path
- Native workflow works in Docker with one bootstrap path and shared PID namespace (`--privileged --pid=host`)
- libc uprobes no longer crash the validated native golden runs

### Notes

- User-code source locations now resolve for the useful cases (`memcpy_overflow`, `double_free`).
- `invalid_free` still may not resolve to a user source file on the current arm64 Docker build, but the finding class and provenance are correct.
- VM mode, Rust agent, and `recc` are not part of this phase gate.

---

## Phase 1 - Native MVP

**Status**: Complete on the supported Docker-native path
**Goal**: turn the working native path into a small but honest OSS release candidate

### Scope

- Native Linux only
- Docker-native workflow as the supported dev/test path
- Three validated goldens
- Stable JSON findings contract
- Basic crashpack output
- Minimal but real escalation entry point
- `recc` optional, not required for the MVP

### Acceptance Criteria

- Docs match actual behavior and the supported Docker invocation
- The three goldens produce the correct finding classes in the supported container flow
- User-style non-golden samples produce expected findings through the generic binary validator
- A clean user-style sample produces no findings through the same native runner
- Findings include explicit provenance and are consumable by escalation/crashpack without guessing
- There is no known golden-specific hardcoding in the active path
- The active crates and scripts are trimmed enough that the supported workflow is obvious
- Known false positives in simple, valid user-code patterns are fixed or explicitly tracked outside the MVP scope

### Progress So Far

- canonical regression path exists: `recompile/scripts/validate-phase1.sh`
- equivalent make target exists: `cd recompile && make phase1`
- full release-candidate gate exists: `cd recompile && make rc`
- generic binary validator exists: `recompile/scripts/validate-binary.sh`
- user-style sample suite exists: `cd recompile && make external-smoke`
- clean no-finding samples exist: `recompile/samples/user-binaries/clean_malloc_free.c` and `recompile/samples/user-binaries/clean_bounded_memcpy.c`
- `rerun run --output <dir>` now refreshes generated crashpack artifacts before each run, so stale findings do not leak into the next analysis
- allocator tracking uses a deterministic shared BPF map key, avoiding padding-dependent lookup misses across heap and copy probes
- active-path `cargo check` is clean for `rerun`, `re-escalate`, `re-crashpack`, `re-harness`, and `re-rules`
- bootstrap/docs/scripts now align around the supported Docker-native path
- the valid `malloc -> bounded memcpy -> free` false positive is now covered by `make external-smoke`

### Exit Criteria Met

- `make rc` passes on the supported Docker-native path
- `make phase1` passes for the three goldens
- `make external-smoke` passes for user-style positive and clean samples
- user-style `invalid_free` resolves a source path
- clean `malloc/free` and bounded-`memcpy` samples produce zero findings
- docs point at Linux-native Docker as the supported workflow

### Known Non-Blocking Limitation

- Golden `invalid_free` may still show `source_path: null` on the current arm64 Docker build. This is symbolization polish because the finding class, severity, and provenance are correct, and the user-style invalid-free sample resolves source.

---

## Phase 2 - Feature Expansion

Phase 2 starts after the Phase 1 native MVP gate.

### Candidate Work

- use-after-free improvements
- memory leak detection
- FD leak detection
- better symbolization beyond primary user frames
- better escalation adapters
- `recc` hardening and LLVM pass wiring

---

## Deferred

- VM mode as a first-class workflow
- macOS support
- Rust runtime agent
- `recc` as a required compile-wrapper path
- LSP/MCP
- CI rollout
- broader observability features

---

## Immediate Execution Order

1. Keep `make rc` passing as the Phase 1 guardrail
2. Decide the first Phase 2 slice, with escalation as the recommended next focus
3. Add broader real-world user-binary regressions as Phase 2 work lands
