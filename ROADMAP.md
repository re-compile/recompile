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

## Phase 1 - Native MVP Release Candidate

**Status**: Current priority
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
- Findings include explicit provenance and are consumable by escalation/crashpack without guessing
- There is no known golden-specific hardcoding in the active path
- The active crates and scripts are trimmed enough that the supported workflow is obvious

### Current Work Items

1. **Lock the supported Docker-native workflow**
   - keep `Dockerfile`, bootstrap script, and docs aligned
   - make the `--privileged --pid=host` requirement impossible to miss

2. **Add regression coverage for the three goldens**
   - supported command: `recompile/scripts/validate-phase1.sh`
   - keep this lightweight for now; CI can follow later

3. **Clean the active path**
   - remove or trim remaining stale code and warnings in active crates
   - keep the supported workflow obvious to OSS users

4. **Polish symbolization where it matters**
   - keep user-code primary locations strong
   - treat unresolved libc/system frames as secondary unless they break findings quality

5. **Prepare release-candidate documentation**
   - make quickstart, architecture, and roadmap agree on the real supported path

---

## Phase 2 - Feature Expansion

Only start this after the Phase 1 release candidate is stable.

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

1. Keep the Docker-native release-candidate workflow aligned in docs and scripts
2. Keep `recompile/scripts/validate-phase1.sh` passing for the three goldens
3. Remove remaining stale code and warnings in active crates
4. Polish symbolization only where it improves user-visible findings quality
5. Then decide what enters Phase 2
