# 🧠 RECC v0.1.0 Sprint – “Lock-In Week”

Goal: Deliver the first **end-to-end AI-native compiler-debugger for C/C++** — the only tool a C/C++ developer needs to detect, classify, and fix runtime errors automatically.

---

## ✅ Current Baseline (Complete)

- [x] **eBPF Sentinel**  
  - Heap tracking (malloc/free/calloc/realloc)  
  - Memcpy/memmove bounds checking  
  - Syscall/lock/signal monitors  
  - Stack tracing (addr2line) + ringbuf emission  

- [x] **Agent (C, re-mini.c)**  
  - Consumes events, applies basic rule logic  
  - Emits JSON findings (heap_overflow, double_free, invalid_free)  

- [x] **Crashpack-v1**  
  - Manifest, metadata, and findings summary  
  - Directory structure + environment capture  
  - ASan escalation integration  

- [x] **Escalation Runner (re-escalate)**  
  - ASan orchestration + cooldown logic  
  - Output capture + Crashpack merge  
  - Working with VM build and native binary  

---

## 🟡 Partially Complete

- [ ] **Rule Engine (re-rules crate)**  
  - Currently: hardcoded in C  
  - Needs Rust migration + JSON-configurable rules  
  - Add debounce, confidence scoring, cooldowns

- [ ] **Symbolization**  
  - Currently: addr2line fallback only  
  - Add full llvm-symbolizer support, demangling, inline frames  
  - Add `--no-symbolize` flag for CI  

---

## 🔴 Not Started

- [ ] **Rust Agent Migration (Critical)**  
  - Create `re-agent` crate in Rust  
  - Consume eBPF ringbuf directly (via libbpf-rs / FFI)  
  - Integrate `re-rules` + `re-crashpack`  
  - Replace `re-mini.c` in all pipelines  

- [ ] **Clustering + Rule Engine**
  - Port your existing logic (memcpy_overflow, double_free, invalid_free) as the first rules.
  - Add confidence + debounce fields.
  - Fingerprint = (kind + top2_frames + ptr_bucket)  
  - Dedup identical findings  
  - Confidence merge + Top-K selection  
  - Evidence summary list  

- [ ] **Symbolization Polish**  
  - Switch to LLVM’s symbolizer binary (with demangling). 
  - Cache lookups per binary to reduce cost.  
  - Include inline frames & source:line in evidence.  
  - Support --no-symbolize for CI speed.  

- [ ] **Repro Harness Generator (re-harness crate)**  
  - Parse finding → reconstruct alloc/copy/free trace  
  - Generate minimal C harness (`repro_<id>.c`)  
  - Include captured inputs + compiler flags  
  - Compile harness with ASan/UBSan for repro  
  - Store harness & build.sh inside Crashpack  

- [ ] **Escalation Extensions (re-escalate)**  
  - Add TSan, MSan, UBSan, and LSan integration  
  - Add Valgrind Memcheck + GDB script runners  
  - Add watchdog for sanitizer job timeouts  
  - Merge escalation logs + fix hints into Crashpack  

- [ ] **CLI Integration (`re` command)**  
  - `re run [--native|--vm]`  
  - `re escalate <binary>`  
  - `re crashpack open`  
  - Connect agent + escalation pipeline behind single command  

- [ ] **Native Mode**  
  - Add `--native` runner for local builds  
  - Keep VM mode for sandboxed reproductions  

---

## 🧩 New Additions (not in old plan)

- [ ] **Top-K prioritization & causal chain collapse**  
  - Group related crashes into a single root cause  

- [ ] **Crashpack Schema Versioning**  
  - Add `"schema_version"` + `"tool_version"` to manifest  

- [ ] **LLM Fix Hint Stubs**  
  - Placeholder: `ai_hint` key for later local/offline enrichment  

- [ ] **Integration Tests (e2e)**  
  - `examples/memcpy_overflow.c` → heap_overflow finding  
  - `examples/double_free.c` → double_free finding  
  - Validate harness runs & reproduces  

- [ ] **CI Pipeline**  
  - Build BPF + Rust crates  
  - Run integration tests  
  - Export `build/crashpack/` artifacts  

---

## ⚡️ Execution Timeline (7-Day Breakdown)

| Day | Phase | Deliverable | Notes |
|-----|--------|-------------|-------|
| **Day 1–2** | 🦀 **Rust Agent Migration** | Create `re-agent` crate, FFI ringbuf, integrate with `re-rules` + `re-crashpack` | Replace C agent entirely |
| **Day 2–3** | ⚙️ **Rule Engine + Clustering** | Port rules, add debounce/confidence, dedup & clustering | Fingerprint + Top-K |
| **Day 3–4** | 🔍 **Symbolization Polish** | Switch to llvm-symbolizer, demangle, cache results | Support inline frames |
| **Day 4–5** | 🧩 **Repro Harness Generation** | Implement `re-harness` crate, integrate in Crashpack | Include `build.sh` |
| **Day 5–6** | 🚀 **Escalation Extensions** | Add TSan, MSan, UBSan, Valgrind, GDB runners | Watchdog + unified output |
| **Day 6–7** | 🧠 **CLI + Native Mode + Tests** | Integrate full CLI, native mode, e2e tests, release tag | Validate full RECC pipeline |

---

## 🔬 Testing & Validation Targets

- [ ] `re run examples/memcpy_overflow.c` → emits `heap_overflow`
- [ ] `re run examples/double_free.c` → emits `double_free`
- [ ] Crashpack includes:
  - findings.json  
  - repro harness (compilable)  
  - escalation logs  
  - build manifest  
  - environment metadata  
- [ ] `re run --native` works outside VM  
- [ ] ASan, UBSan, TSan, MSan, Valgrind all integrated with unified JSON output  

---

## 🧠 Long-Term (v0.2+ Roadmap)

- [ ] **AI Fix Generation** (`re fix --ai`)  
  - LLM model integration for local/offline fix hints  

- [ ] **IDE Integration (LSP/MCP)**  
  - Expose findings + hints in editors directly  

- [ ] **Team CI Mode**  
  - Batch analysis + auto triage for large repos  

---

## 🧩 Guiding Principles

- **Zero false positives** — never report what you can’t reproduce.  
- **Deterministic repro** — every Crashpack must build and reproduce exactly once.  
- **Speed without compromise** — sub-3 µs probe overhead, sub-2 min escalation budget.  
- **Clarity above all** — findings should read like a human QA report, not a sanitizer log.  

---
