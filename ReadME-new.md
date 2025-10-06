# ReCC Auto-Escalation Sentinel (Developer README)

This doc describes the **eBPF Sentinel + Auto Escalation pipeline** in ReCC.  
The goal: automatically classify runtime anomalies, escalate to the correct tool (ASan/UBSan/TSan/MSan/LSan/Valgrind), generate minimal repro harnesses, and emit structured findings.

This is **not a user-facing doc**. It is an engineering reference for how we’re building the escalation system.

---

## 1. Sentinel Overview

- Sentinel is a **low-overhead eBPF probe set** attached at runtime.
- Always-on during `recc run`.
- Observes:
  - **Allocators**: `malloc/free`, `mmap/munmap`, `new/delete`.
  - **Memory ops**: `memcpy/memmove/strcpy/strlen`, page faults.
  - **Concurrency**: `pthread_mutex*`, futex wait/wake, thread create/join.
  - **Syscalls / I/O**: `read/write/send/recv/pipe/dup2/epoll/inotify`.
  - **Signals**: handlers + forbidden calls inside them.
- Maintains in-memory maps:
  - `alloc_map`: ptr → {size, alloc_site, timestamp}
  - `fd_map`: fd → {path, type, opened_by, timestamp}
  - `lock_map`: lock_id → acquisition order graph
  - `event_buffer`: rolling ring buffer of N seconds for anomaly context

Sentinel emits structured events into a ring buffer.  
A rule engine consumes them → **anomaly classification**.

---

## 2. Anomaly → Escalation Mapping

**Deterministic rules** based on signatures:

| Anomaly Signature | Escalation Tool (preferred) | Fallback (binary-only) |
|-------------------|-----------------------------|-------------------------|
| memcpy/memmove length > alloc size | **ASan** (harness) | **Valgrind Memcheck** |
| free(p) then later access | **ASan** (harness) | **Valgrind Memcheck** |
| double free | **ASan** (harness) | **Valgrind Memcheck** |
| suspicious uninit data → I/O | **MSan** (harness) | **Valgrind Memcheck (track-origins)** |
| futex cycles / mutex graph cycles | **TSan** (harness) | **Valgrind Helgrind/DRD** |
| misaligned/null deref/arithmetic UB | **UBSan** (harness) | GDB recipe + Valgrind |
| long-lived allocations / leaks | **LSan** (via ASan run) | **Valgrind leak-check** |
| kernel crash / segfault (no sanitizer) | **ASan harness** if buildable | **Valgrind** |
| no high-confidence anomalies | passthrough (clang build only) | – |

### Thresholds
- Single anomaly → hold for debounce window (1–3s).
- Repeated anomalies or critical (double-free) → immediate escalation.
- Confidence is required; no false-positive escalations.

---

## 3. Escalation Engine

- **Preferred path**: build **Minimal Repro Harness (MRS)** and run with appropriate sanitizer.
- **Fallback path**: run **Valgrind** tools on binary when rebuild impossible.

---

## 4. Minimal Repro Harness (MRS)

Two types:

1. **Pure harness**
   - Replays alloc/copy/free directly from trace (sizes, strides, call order).
   - Used for local OOB, UAF, double free patterns.

2. **Driver harness**
   - TU that `#include`s headers and calls the function(s) where anomaly occurred.
   - Links against existing `.o/.a/.so` from the build.
   - Sanitizes only driver + suspect TUs; rest unsanitized.

**Linking notes:**
- Use same compiler flags as original build (`compile_commands.json`).
- Partial sanitization works (ASan + unsanitized objects).
- MSan cannot mix with ASan; run as isolated harness build.
- For vtables/ABI: assert `sizeof` and vtable consistency.
- If ABI mismatch → fallback to Valgrind.

---

## 5. Multi-Error Handling

- Sentinel may emit many anomalies.
- We **cluster** by fingerprint:
  - (event type, module/symbol, offset, stack hash, addresses)
- Clusters ranked:
  - Priority: double-free > OOB/UAF > UB > races > leaks.
  - Frequency and severity factored.
- Escalation generates **one harness per cluster** (top-K clusters, default K=3).
- If multiple clusters share causal root (alloc→write→use chain), collapse to **one harness**.

Harnesses must stay **isolated**. We do not build “mega-harnesses”.

---

## 6. Input Handling

- Sentinel records argv/env, working dir, file opens, offsets.
- Crashpack includes replay script (exact command + required files).
- For multi-case `.txt` inputs:
  - **Delta debugging** to minimize failing case (bisect input).
  - Output `failing_case.txt`.
- Harness consumes failing input only.

---

## 7. Debug Recipes

Crashpack includes optional `gdb_recipe.txt`:
- Pre-seeded conditional breakpoints (e.g., `break foo.cpp:271 if n>dst.size()`).
- Watchpoints (`watch *p`).
- Deterministic replay schedule for deadlocks.

This makes debugging faster than raw gdb (no manual hunting).

---

## 8. No-Issue Path

- If sentinel sees no anomalies above threshold:
  - No escalation.
  - Build behaves exactly like Clang (same compile, same binary).
  - Report: “No high-confidence anomalies observed during N seconds/M iterations.”
- Absolutely **no false positives** allowed.

---

## 9. Tool Reliability

- **ASan/UBSan/LSan**: highly reliable, fast, partial builds ok.
- **TSan**: low false positives, heavy runtime overhead. Harness must be small.
- **MSan**: precise, but build friction (libstdc++ interceptors needed). Expect 10–30% harnesses to fail and require fallback.
- **Valgrind**: always works on binaries, but 5–30× overhead. Last resort.

---

## 10. Failure Modes & Fallbacks

- Missing `compile_commands.json`: try `bear` to regenerate. Else → fallback Valgrind.
- Harness link fails: broaden surgical rebuild. If still fails → fallback Valgrind.
- Sanitizer incompatibilities (ASan vs MSan): run separate harnesses, not combined.
- Non-deterministic races: generate stress harness (loop + randomized schedules). If not reproducible → emit replay recipe.

---

## 11. Output (Crashpack)

Each escalation produces a **Crashpack**:

crashpack-/
├── findings.json        # structured findings, anomaly classification
├── index.html           # human-readable report
├── console.log          # captured runtime logs
├── mrs_harness.cc       # harness driver
├── build.sh             # one-command sanitizer build
├── failing_case.txt     # minimized input (if applicable)
└── gdb_recipe.txt       # preseeded debug commands

---

## 12. Development Phases

1. Sentinel probes for malloc/free/memcpy/futex/file ops.
2. Rule engine for anomaly classification (deterministic).
3. Escalation runner (sanitize harness or valgrind).
4. Harness generator (pure + driver).
5. Crashpack builder.
6. Clustering + top-K harness generation.
7. Input isolation + delta debugging.
8. Debug recipe generator (gdb).

---

## 13. Core Principles

- **Sentinel always on, low overhead.**
- **Escalate only on high-confidence signals.**
- **Never escalate when no bug → behave like Clang.**
- **Harness per anomaly cluster → regression tests.**
- **Valgrind only as fallback.**
- **Crashpacks are the single unit of output.**