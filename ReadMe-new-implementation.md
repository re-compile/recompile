# ReCC Auto-Escalation Sentinel – Implementation Plan

This doc explains how to **implement the eBPF Sentinel + Auto-Escalation pipeline**.  
It is written for developers working on ReCC internals, not end users.  

The goal is to go from our design (see `README.md`) to a working system, with **no ambiguity** about steps, fallbacks, and edge cases.

---

## 1. Sentinel Implementation

### 1.1 eBPF probes
- Attach uprobes/kprobes to:
  - `malloc/free/new/delete`, `mmap/munmap`
  - `memcpy/memmove/strcpy/strlen`
  - `pthread_mutex_lock/unlock`, futex syscalls
  - `read/write/send/recv/pipe/dup2/epoll/inotify`
  - `signal/raise` and registered signal handlers
- Collect into a **BPF ring buffer**.

### 1.2 Maps maintained
- `alloc_map`:  
  `{ ptr → { size, alloc_site_id, timestamp } }`
- `fd_map`:  
  `{ fd → { path, type, opened_by, timestamp } }`
- `lock_map`:  
  `{ lock_id → acquisition order }`
- `event_buffer`:  
  Rolling N-second buffer of events, capped to avoid unbounded growth.

### 1.3 Event schema
Each event:  
`{ type, pid, tid, ts, site_id, addr/fd/lock, size, extra, stack_fingerprint }`

---

## 2. Rule Engine (Anomaly Classifier)

### 2.1 Deterministic rules

| Event Signature | Escalation Tool |
|-----------------|-----------------|
| memcpy length > alloc size | ASan (else Valgrind Memcheck) |
| free(p) then access | ASan (else Valgrind) |
| double free | ASan (else Valgrind) |
| suspicious uninit data → I/O | MSan (else Valgrind `--track-origins=yes`) |
| futex/mutex cycle | TSan (else Valgrind Helgrind/DRD) |
| misaligned/null deref/arithmetic UB | UBSan |
| leaks (RSS grows + allocs never freed) | LSan (via ASan) or Valgrind leak-check |
| segfault w/o context | Try ASan harness, else Valgrind |
| no anomaly > threshold | No escalation (clang passthrough) |

### 2.2 Thresholds & debounce
- Hold single anomalies for debounce window (1–3s).
- Require N repeated hits before escalation (configurable).
- Severe events (double free) trigger immediately.

### 2.3 Confidence
- Only escalate when confidence ≥ threshold.
- No false positives → if confidence < threshold → passthrough build.

---

## 3. Escalation Runner

### 3.1 Preferred path
- Generate a **Minimal Repro Harness (MRS)**.
- Recompile **driver TU + suspect TUs** with appropriate sanitizer:
  - ASan/UBSan/TSan/LSan/MSan.
- Link against existing `.o/.a/.so` artifacts from microVM.

### 3.2 Fallback path
- Run **Valgrind tools** if:
  - `compile_commands.json` missing, or
  - harness build fails, or
  - sanitizer incompatible (ASan vs MSan).
- Tools used:
  - Memcheck (OOB/UAF/uninit/leaks)
  - Helgrind/DRD (concurrency)
- Write logs + XML to `/host/findings`.

---

## 4. Minimal Repro Harness Strategy

### 4.1 Pure harness
- Replay alloc/copy/free directly from trace.
- Input sizes + ops exactly as in failing run.
- Used when bug is purely local.

### 4.2 Driver harness
- TU includes user headers.
- Calls failing function(s) with captured args.
- Links against `.o/.a/.so` from original build.
- Only driver + suspect TUs sanitized.

### 4.3 Linking details
- Use original flags (`compile_commands.json`).
- Partial sanitization OK for ASan/TSan/UBSan.
- MSan cannot mix with ASan → build harness separately.
- For vtables: assert `sizeof`, `alignof`, vtable symbols.
- ABI mismatch → fallback to Valgrind.

### 4.4 Multiple errors
- Cluster anomalies by `(type, symbol, offset, stack_fingerprint)`.
- Rank clusters by severity (double free > OOB > UB > race > leak).
- Escalate top-K (default 3).
- One harness per cluster.
- If causal chain shows shared root → collapse to single harness.

---

## 5. Input Handling

### 5.1 Input capture
- Record `argv`, `env`, working dir.
- Intercept `open` syscalls; store path/offset/length.
- Crashpack includes replay script.

### 5.2 Multi-case input isolation
- If input is `.txt` with many test cases:
  - Use delta debugging to bisect until smallest failing case.
  - Emit `failing_case.txt`.
- Harness replays only failing case.

---

## 6. Debug Recipes

### 6.1 gdb_recipe.txt
- Pre-seeded conditional breakpoints:
  - `break foo.cpp:271 if n>dst.size()`
- Watchpoints on suspicious buffers.
- For races: replay lock schedule (threads acquire locks in suspected inversion order).

### 6.2 Deadlocks
- Deterministic replay script with lock order from `lock_map`.

---

## 7. No-Issue Path

- If sentinel detects nothing:
  - Compile/run with exact clang flags (no sanitizers).
  - Emit report: “No anomalies observed during N seconds.”
- Guarantees:
  - No false positives.
  - No overhead beyond sentinel probes.

---

## 8. Tool Reliability & Fallbacks

- **ASan/UBSan/LSan**: reliable, low overhead. Default for memory errors.
- **TSan**: low false positives, high overhead. Use only on harnesses, not full app.
- **MSan**: precise but build friction (needs instrumented libc/libstdc++). Expect ~10–30% harnesses to fail → fallback Valgrind.
- **Valgrind**: slow (5–30×), but works on any binary. Last resort.
- **Fallback rules**:
  - Harness fails to build → broaden rebuild (suspect + dependent TUs).
  - If still fails → fallback to Valgrind.
  - Incompatibility (ASan vs MSan) → build separate harnesses.
  - Non-deterministic race → generate stress harness (loop + randomized timing). If unreproducible → emit replay recipe.

---

## 9. Crashpack Schema

crashpack-/
├── findings.json      # anomaly classification + sanitizer/valgrind logs
├── index.html         # human-readable summary
├── console.log        # runtime logs
├── mrs_harness.cc     # repro driver
├── build.sh           # sanitizer build/run script
├── failing_case.txt   # minimized failing input
└── gdb_recipe.txt     # seeded debug commands

Crashpack is the **single unit of output** for every incident.

---

## 10. Development Phases

### Phase 1 — Core Sentinel
- Implement uprobes for malloc/free/memcpy/futex/file ops.
- Event buffer + alloc_map + fd_map.

### Phase 2 — Rule Engine
- Implement anomaly signatures (OOB, UAF, double free, uninit, race, UB).
- Thresholds + debounce.

### Phase 3 — Escalation Runner
- Harness generator (pure + driver).
- Sanitizer invocation (ASan/UBSan/TSan/MSan).
- Fallback: Valgrind integration (Memcheck, Helgrind).

### Phase 4 — Multi-Error Handling
- Clustering logic.
- Top-K harness generation.

### Phase 5 — Input Capture & Delta Debugging
- argv/env/file path capture.
- Bisect input files to isolate failing case.

### Phase 6 — Debug Recipes
- gdb_recipe generation (conditional break/watchpoints).
- Deadlock replay scripts.

### Phase 7 — Polishing
- Crashpack HTML renderer.
- AI fix suggestions (optional).
- Packaging (CI integration, CLI commands).

---

## 11. Core Principles

- Sentinel always on, but low overhead.
- Escalate only on strong signals.
- Never escalate when clean.
- Harness per anomaly cluster.
- Regression tests from every harness.
- Valgrind only as fallback.
- Crashpack = canonical artifact.

---

## 12. Open Questions (for later phases)

- Better heuristics for MSan escalation vs Valgrind trade-off.
- Automated suppression generation for Valgrind noise.
- How to handle external services (DB/network) in repro harness.
- Integration of static checks (ODR/ABI, iterator invalidation, etc.) into same Crashpack schema.

---