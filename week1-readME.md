re:compile — Week 1 Implementation Guide (Fast‑Triage MVP)

Objective (Week 1): Ship a walking skeleton that compiles a C/C++ target with recc, runs it inside a bundled microVM, attaches eBPF probes, and emits actionable Finding JSON + terminal diagnostics for: (a) double/invalid free and (b) classic memcpy/str* overflows — with stacks for alloc, call‑site, and crash.

Non‑goals (Week 1): TSan/MSan/rr orchestration, native‑mode sandboxing, FD/thread leak trackers (can stub), fancy LSP/MCP polish. We add these in Week 2.

⸻

Table of Contents
	•	1. Scope & Acceptance
	•	2. Repo Scaffold
	•	3. Toolchain Prereqs
	•	4. Build System Bootstrap
	•	5. Data Contracts
	•	6. recc Compiler Wrapper (Rust)
	•	7. LLVM Breadcrumb Pass (C++17, minimal)
	•	8. MicroVM Runtime (Firecracker/QEMU)
	•	9. eBPF Programs (CO‑RE)
	•	10. VM Agent (Rust)
	•	11. Orchestrator: re run
	•	12. Examples & Smoke Tests
	•	13. Perf/Safety Defaults
	•	14. Known Gaps for Week 2

⸻

1. Scope & Acceptance

Week‑1 Deliverables
	•	recc injects debug flags and emits a run manifest.
	•	MicroVM boots and runs a VM Agent that loads heap_tracker and copy_checker BPF programs.
	•	We emit Finding JSON v1 with alloc stack, call‑site stack, optional crash stack, and numeric evidence.
	•	Terminal diagnostic shows file:line and a fix hint.

Acceptance Tests
	•	examples/memcpy_overflow.c → finding heap_overflow with alloc + memcpy stacks.
	•	examples/double_free.c → finding double_free with double‑free call site.
	•	Event drop counters = 0 on examples.
	•	Fast‑triage overhead on examples ≤ 5%.

Mermaid Overview

flowchart LR
  A[recc] -->|compile + manifest| B[(Target Binary)]
  B --> C[re run]
  C --> D[MicroVM Launcher]
  D --> E[(Linux MicroVM)]
  E --> F[eBPF: heap_tracker, copy_checker]
  F --> G[Ringbuf events + stack ids]
  G --> H[VM Agent: symbolize + build Finding]
  H --> I[(Finding JSON v1)]
  I --> J[Terminal Diagnostics]


⸻

2. Repo Scaffold

recompile/
  Cargo.toml                 # workspace
  recc/                      # Rust crate: compiler wrapper
  rerun/                     # Rust crate: host orchestrator (re run)
  vm-launcher/               # Rust crate: microVM boot + vsock
  llvm-passes/               # C++ pass(es) — minimal for Week 1
  runtime/
    bpf/                     # eBPF C sources (CO‑RE) + headers
    agent/                   # Rust crate inside VM
    shared/                  # C headers shared (event structs)
    vm/                      # kernel, rootfs build scripts, BTF assets
  schemas/                   # finding.schema.json (v1)
  examples/                  # buggy programs for smoke tests
  scripts/                   # build, pack, dev helpers


⸻

3. Toolchain Prereqs
	•	Rust stable (≥ 1.77), cargo.
	•	Clang/LLVM ≥ 16 (host) – also provides llvm-strip, llvm-symbolizer.
	•	bpftool (≥ v7), libbpf headers (we vendor minimal headers).
	•	QEMU (with HVF on macOS / WHVP on Windows) or Firecracker on Linux.
	•	BTF kernel assets (we ship a known‑good vmlinux for the microVM).

For reliable stacks: we inject -g -fno-omit-frame-pointer and prefer -Og/-O1 during analysis.

⸻

4. Build System Bootstrap
	•	Cargo workspace for all Rust crates.
	•	CMake for llvm-passes and runtime/bpf (we call from scripts/build.sh).
	•	Make targets for convenience:

make vm          # build kernel+rootfs image (zstd compressed)
make bpf         # compile eBPF objs + generate skeleton headers
make passes      # build LLVM pass .so
make agent       # build VM agent static binary (musl if possible)
make toolchain   # assemble bundle: launcher+images+bpf+agent


⸻

5. Data Contracts

5.1 Manifest (host → VM)

{
  "binary": "/host/ws/build/a.out",
  "argv": ["a.out", "--", "arg1"],
  "env": {"RE_FRAMEPTR": "1"},
  "build_id": "<ELF build-id>",
  "dsos": ["/lib/x86_64-linux-gnu/libc.so.6"],
  "cwd": "/host/ws",
  "policy": {"sampling": 0, "stack_depth": 64}
}

5.2 Finding JSON v1 (VM → host)

{
  "id": "F-heap-overflow-001",
  "origin": "ebpf",
  "kind": "heap_overflow",
  "severity": "error",
  "confidence": 0.95,
  "primaryLocation": {"uri":"file:///src/foo.c","range":{"start":{"line":123,"character":17},"end":{"line":123,"character":23}}},
  "evidence": {
    "api": "memcpy",
    "len": 64,
    "dst_size": 32,
    "stacks": {
      "alloc": ["foo.c:98: makeBuf"],
      "call":  ["foo.c:123: memcpy"],
      "crash": ["foo.c:124: <signal>"]
    }
  },
  "fixHints": ["Bound len to capacity", "Allocate len bytes"]
}

5.3 Shared C Header (runtime/shared/re_events.h)

#pragma once
#include <linux/types.h>

struct re_alloc_info { __u32 size; int alloc_stack_id; };

struct re_alloc_event { __u64 ts; __u32 pid, tid; void *ptr; __u32 size; int stack_id; };
struct re_free_event  { __u64 ts; __u32 pid, tid; void *ptr; int error; int stack_id; };
struct re_copy_event  { __u64 ts; __u32 pid, tid; void *dst, *src; __u64 len; __u32 dst_size; int stack_id_call; int stack_id_alloc; };
struct re_crash_event { __u64 ts; __u32 pid, tid; int sig; void *addr; int stack_id; };


⸻

6. recc Compiler Wrapper (Rust)

Responsibilities
	•	Pass‑through to clang++/g++ with injected flags: -g -fno-omit-frame-pointer -rdynamic -Wl,--export-dynamic.
	•	Include the LLVM pass (when built) with -Xclang -load -Xclang <pass>.so.
	•	Emit manifest.json: binary, argv, env, build_id (from readelf --build-id), detected DSOs (ldd parsing), cwd.
	•	Write manifest to build/.re/manifest.json.

CLI sketch

recc [clang++ args ...]
re run <path/to/binary> [-- arg1 arg2]

Edge cases now: we can skip CU list and full DSO resolution in Week 1 (keep minimal list).

⸻

7. LLVM Breadcrumb Pass (C++17, minimal)

Goal (Week 1): seed heap extents and memcpy sites with stable IDs; do not instrument every load/store.

What to emit
	•	.note.re.bounds ELF note listing global/static objects with their symbol size (closes part of the non‑heap extent gap).
	•	Optionally attach IDs to llvm.memcpy intrinsic call sites (for later correlation).

Pass outline
	•	New PassManager ModulePass:
	•	Iterate globals → collect size/name → write an ELF SHT_NOTE section (emit via inline asm blob or llvm::Module section).
	•	Iterate functions → find llvm.memcpy.* calls → attach metadata !re.site with a stable hash of (CU, line, col, discriminator).

If tight on time: globals note only. We’ll rely on heap extents for Week 1.

⸻

8. MicroVM Runtime (Firecracker/QEMU)

Layout

runtime/vm/
  kernel/          # bzImage + vmlinux BTF
  rootfs/          # init, /usr/bin/agent, /usr/bin/llvm-symbolizer
  pack.sh          # builds a compressed image (zstd)

Boot flow

sequenceDiagram
  participant Host as Host (re run)
  participant VM as Linux MicroVM
  Host->>VM: boot(kernel, rootfs, vsock)
  Host->>VM: send manifest.json over vsock
  VM->>VM: agent loads BPF (heap_tracker, copy_checker)
  VM->>Target: exec target binary (from virtio-fs mount /host)
  Target-->>VM: syscalls enter/exit → uprobes fire
  VM->>Host: Finding JSON over vsock/stdout

Mounting source/binary
	•	Use virtio‑fs (or 9p) to mount the host workspace at /host inside VM.

⸻

9. eBPF Programs (CO‑RE)

Common maps (define once per .o):

// allocs: ptr -> {size, alloc_stack_id}
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, void *); __type(value, struct re_alloc_info); __uint(max_entries, 131072); } allocs SEC(".maps");

// ring buffer for events
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<24); } events SEC(".maps"); // 16MB

// user stacks storage
struct { __uint(type, BPF_MAP_TYPE_STACK_TRACE); __uint(key_size, sizeof(__u32)); __uint(value_size, 127 * sizeof(__u64)); __uint(max_entries, 8192); } ustacks SEC(".maps");

9.1 heap_tracker.bpf.c

Hooks:
	•	malloc/calloc/realloc entry/ret, operator new/delete (C++), free.

Pattern:
	•	On entry to alloc: store size in a per‑CPU scratch map keyed by TID.
	•	On ret: get return ptr, lookup scratch size, capture stack_id = bpf_get_stackid(..., BPF_F_USER_STACK), update allocs[ptr] = {size, stack_id} and emit re_alloc_event.
	•	On free/delete: if ptr !in allocs → invalid_free; if present but previously freed → double_free; else remove and emit re_free_event.

9.2 copy_checker.bpf.c

Hooks:
	•	memcpy/memmove/strcpy/strncpy (add more later if time).

Pattern:
	•	Read args: (dst, src, len).
	•	Lookup dst in allocs by walking backwards through known allocs if you maintain slabs; for Week 1 we treat exact match (simple) — good for classic overflows on the first byte.
	•	Compare len > size ⇒ emit re_copy_event with dst_size and both stack_id_call and stack_id_alloc (if found).

Stacks to collect (Week 1):
	•	Allocation stack at alloc return → alloc_stack_id (stored in allocs).
	•	Call‑site stack at memcpy/free → stack_id_call.
	•	Crash stack: see §10.3 (ptrace path for Week 1).

⸻

10. VM Agent (Rust)

10.1 Responsibilities
	•	Load BPF objs; pin as needed; attach uprobes to the target binary + DSOs.
	•	Consume ringbuf; lazily read stack traces by stack_id from ustacks.
	•	Symbolize with llvm-symbolizer --inlines (spawn-once, reuse stdin/stdout). Cache results.
	•	Join evidence → Finding JSON v1; print terminal diagnostics.

10.2 Symbolizer shim
	•	Protocol: write "<binary> <addr>\n", read lines until blank, parse “file:line:function”; collect inlines.
	•	Cache by (binary, addr).

10.3 Crash capture (Week 1 pragmatic)
	•	Run target under a tiny supervisor using ptrace(SEIZE).
	•	On SIGSEGV/SIGABRT, read siginfo_t.si_addr and a userspace backtrace (e.g., libunwind inside VM) → synthesize a re_crash_event with a crash stack.
	•	(Week 2: swap to BPF signal:signal_deliver and unify with ringbuf flow.)

10.4 Building the Finding
	•	Choose primaryLocation from the topmost user frame of the call‑site (or crash) stack.
	•	explanation is deterministic text built from numbers (len, dst_size).
	•	Add fixHints (bounds check or size‑based allocation suggestions).
	•	Include dataQuality.eventsDropped from a counter maintained by the agent (ringbuf backpressure).

⸻

11. Orchestrator: re run

Host responsibilities
	•	Ensure binary exists; if compiled with recc, a manifest is already present; else build a minimal one.
	•	Launch microVM with virtio‑fs mount of the workspace at /host and a vsock channel.
	•	Send manifest to VM Agent; stream back Finding JSON and render terminal diagnostics.

CLI sketch

re run ./build/a.out -- arg1 arg2
re run --vm.log --vm.keep # debug flags


⸻

12. Examples & Smoke Tests

Create failing examples and golden outputs in examples/:
	•	memcpy_overflow.c (copy 64 into 32) → heap_overflow with alloc+call stacks.
	•	double_free.c → double_free with call stack.
	•	invalid_free.c → invalid_free with call stack.
	•	segv_null.c (optional) → crash stack (ptrace path).

Make target

make examples && re run ./examples/memcpy_overflow

Expected terminal snippet

❌ [CWE-787] Heap overflow at examples/memcpy_overflow.c:23
   memcpy writes 64 bytes into a 32-byte heap buffer 'buf'.
   alloc: examples/memcpy_overflow.c:12 (makeBuf)
   hint: Bound len to capacity or allocate len bytes.


⸻

13. Perf/Safety Defaults
	•	Flags: inject -g -fno-omit-frame-pointer and prefer -Og/-O1 when using recc.
	•	Ringbuf: 16 MB; warn if drops > 0.
	•	Stack depth: 64 (cap at 32 if perf dips on large apps).
	•	Sampling: OFF by default in Week 1 (we only hook mem* + allocs).
	•	Security: microVM is no‑net, seccomp basic; host receives only findings.

⸻

14. Known Gaps for Week 2
	•	FD/thread leak trackers and leak summary output.
	•	Last‑N per‑thread breadcrumbs & memcpy sampling/allowlists.
	•	Auto‑escalation to ASan+UBSan(+LSan) with dual‑build cache.
	•	Native mode (Linux) with caps check + namespaces + cgroup.
	•	Allocator presets: jemalloc (then tcmalloc), custom mapping.
	•	MCP/LSP v1 with actionable code actions.
	•	BPF signal path (replace ptrace crash path).

⸻

Appendix A — Minimal BPF Snippets (illustrative)

// heap_tracker.bpf.c (sketch)
SEC("uprobe/malloc") int BPF_KPROBE(re_malloc_enter, size_t size) { /* store size in percpu map by tid */ return 0; }
SEC("uretprobe/malloc") int BPF_KRETPROBE(re_malloc_ret) {
  void *ptr = (void *)PT_REGS_RC(ctx);
  int sid = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
  struct re_alloc_info info = {.size = size_for_tid(), .alloc_stack_id = sid};
  bpf_map_update_elem(&allocs, &ptr, &info, BPF_ANY);
  return 0;
}
SEC("uprobe/free") int BPF_KPROBE(re_free, void *ptr) {
  int sid = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
  struct re_alloc_info *p = bpf_map_lookup_elem(&allocs, &ptr);
  if (!p) { emit_invalid_free(ptr, sid); return 0; }
  if (is_marked_freed(ptr)) { emit_double_free(ptr, sid); return 0; }
  mark_freed(ptr); return 0;
}

// copy_checker.bpf.c (sketch)
SEC("uprobe/memcpy") int BPF_KPROBE(re_memcpy, void *dst, const void *src, size_t len) {
  int call_sid = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
  __u32 dst_size = 0; int alloc_sid = -1;
  struct re_alloc_info *a = bpf_map_lookup_elem(&allocs, &dst);
  if (a) { dst_size = a->size; alloc_sid = a->alloc_stack_id; }
  if (dst_size && len > dst_size) emit_overflow(dst, src, len, dst_size, call_sid, alloc_sid);
  return 0;
}

These are sketches for orientation; implement with proper per‑CPU scratch, error handling, and event emission.

⸻

Appendix B — Symbolizer Adapter (Rust, pseudocode)

struct LlvmSymbolizer { child: Child, cache: HashMap<(PathBuf,u64), Vec<Frame>> }
impl LlvmSymbolizer {
  fn symbolize(&mut self, bin: &Path, addr: u64) -> &[Frame] { /* spawn once, cache, parse */ }
}


⸻

Appendix C — Make Targets (starter)

.PHONY: vm bpf passes agent toolchain examples
vm: scripts/build-vm.sh           # builds kernel+rootfs zstd image
bpf: runtime/bpf/Makefile         # clang -target bpf -g -O2; bpftool gen skeleton
passes: llvm-passes/CMakeLists.txt
agent: runtime/agent/Cargo.toml   # build static if possible (musl)
examples: scripts/build-examples.sh