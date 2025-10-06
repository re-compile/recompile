Interfaces & Schema

✅ Decisions (short)
	•	compile_commands.json: hard requirement (fail fast) for Phases 1–2. No silent Valgrind fallback yet.
	•	Numeric fields everywhere (addresses, IDs, counts). No stringified hex in the wire format.
	•	Sequence numbers and drop counters per PID/TID in events to detect reordering/loss.
	•	Raw BPF stack_id included alongside a 32-bit stack_fp (for clustering). Symbolization uses stack_id.
	•	Syscall returns: capture ret and bytes_ret (+ errno when negative).
	•	Concurrency: explicit lock_kind, lock_addr, and lock_site_id.
	•	extra: bounded K/V (values ≤ 32 bytes); reject oversize at emit.
	•	Crashpack AI hints: stable key present, empty unless enrichment runs; HTML hides it by default.
	•	Per-rule debounce, cooldown_ms, and fallback arrays (to chain actions).
	•	Harness plan: add entrypoint, build_env, timeout_sec, requires_user_input, and binary input packaging via tarball reference (preferred) or base64 blob (cap size).

⸻

1) Sentinel Event Schema (v0)

1.1 Field definitions (wire format)
	•	version (u16): schema version. Start at 1.
	•	seq (u64): per-PID monotonic sequence (agent tracks per PID; wraps on u64).
	•	pid (u32), tid (u32)
	•	ts_ns (u64): monotonic timestamp (CLOCK_MONOTONIC_RAW).
	•	type (u16 enum): see table below.
	•	site_id (u32): optional breadcrumb/site hash (0 if unknown).
	•	stack_id (s32): BPF stackmap ID (−1 if not captured).
	•	stack_fp (u32): folded hash/fingerprint of userland frames (0 if unknown).
	•	addr (u64): pointer address for memory events; 0 if not applicable.
	•	len (u32): length (memcpy/read/write); 0 if N/A.
	•	alloc_size (u32): dest/src recorded alloc size if known; 0 if unknown.
	•	fd (s32): file descriptor for I/O; −1 if N/A.
	•	bytes_ret (s32): return value of I/O syscalls (e.g., read/write/recv/send). <0 → error; pair with errno_code.
	•	errno_code (s32): errno captured on negative returns; 0 otherwise.
	•	lock_kind (u8 enum): 0=NA, 1=mutex, 2=rwlock_r, 3=rwlock_w, 4=futex, 5=spin.
	•	lock_addr (u64): address of the lock object or futex word; 0 if N/A.
	•	lock_site_id (u32): site hash for lock acquisition/release; 0 if N/A.
	•	flags (bitfield u16):
	•	bit0=throttled, bit1=dropped_batch, bit2=kernel_space, others reserved.
	•	drop_count (u32): number of events dropped since previous emit (per PID) — lets userland infer gaps precisely.
	•	extra_kv (bounded): up to 4 K/V pairs; keys are small u8 enums; value is a fixed 32-byte byte-array (length prefix u8; rest zero-padded).

Byte budget: keep per-event ≤ ~96–128 bytes on average. Avoid strings; use enums/ints.

1.2 Event type enums (type)

Enum	Meaning
1	malloc
2	free
3	mmap
4	munmap
5	memcpy
6	memmove
7	strcpy
8	strlen
9	read
10	write
11	send
12	recv
13	dup/dup2
14	pipe
15	epoll_ctl
16	inotify_add
20	lock_acq
21	lock_rel
22	futex_wait
23	futex_wake
30	signal_enter
31	signal_forbidden_call
40	segv/sigbus trap marker
50	mark_flush (Sentinel control event)

We can extend; keep versioned.

1.3 Example (binary read→memcpy OOB)

{
  "version": 1,
  "seq": 9142,
  "pid": 22310,
  "tid": 22310,
  "ts_ns": 13610293840123,
  "type": 5,
  "site_id": 0,
  "stack_id": 17,
  "stack_fp": 2971453321,
  "addr": 140737353539584,
  "len": 128,
  "alloc_size": 64,
  "fd": -1,
  "bytes_ret": 0,
  "errno_code": 0,
  "lock_kind": 0,
  "lock_addr": 0,
  "lock_site_id": 0,
  "flags": 0,
  "drop_count": 0,
  "extra_kv": [
    {"k":1,"v_len":1,"v":"\u0001"},   // k=1 might be direction flag
    {"k":2,"v_len":4,"v":"\u0000\u0000\u0000\u0001"} // exemplar
  ]
}


⸻

2) Findings (Clusters) Schema (v0)

We keep your additions: primary_location and evidence_summary.

{
  "version": 1,
  "run_manifest": {
    "argv": ["./bin/app","--size","256"],
    "env": {"LC_ALL":"C"},
    "cwd": "/work/app",
    "opened_files": [
      {"path":"inputs/cases.txt","ranges":[[0,2048],[4096,8192]],"sha256":"..."}
    ]
  },
  "clusters": [
    {
      "id": "C1",
      "class": "oob_write",             // enum: oob_write|oob_read|uaf|double_free|race|deadlock|uninit|ub|leak
      "confidence": 0.92,
      "fingerprint": {
        "symbol": "foo::copy_chunk",
        "offset": "0x1a3",
        "stack_fp": 2971453321
      },
      "stats": { "hits": 11, "first_ts_ns": 13610, "last_ts_ns": 13640 },
      "primary_location": {
        "uri": "file://src/foo.cpp",
        "line": 271,
        "column": 18
      },
      "evidence_summary": [
        {"ts_ns":13610293840123, "seq":9139, "event_type":"memcpy", "addr":140737353539584, "len":128, "alloc_size":64, "stack_id":17},
        {"ts_ns":13610293840211, "seq":9142, "event_type":"segv"}
      ],
      "escalation": {
        "tool": "asan",
        "reason": "len>alloc_size",
        "estimated_cost": "low",
        "cooldown_ms": 5000
      },
      "ai_hint": { "status": "not_enriched", "details": [] }
    }
  ],
  "high_confidence": ["C1"],
  "low_confidence": [],
  "rule_engine": {
    "ruleset": "rules.default.json",
    "confidence_hi": 0.8,
    "confidence_lo": 0.5
  }
}


⸻

3) Rule Table (v0)

Split predicate vs debounce, add cooldown and fallback arrays.

{
  "version": 1,
  "rules": [
    {
      "id": "R-memcpy-oob",
      "match": { "type": "memcpy", "len_gt_alloc": true },
      "debounce": { "min_hits": 2, "window_ms": 1500 },
      "escalate": "asan",
      "fallback": ["valgrind_memcheck"],
      "severity": "critical",
      "cooldown_ms": 10000
    },
    {
      "id": "R-free-then-access",
      "match": { "type": "free_then_access", "max_delta_ms": 10000 },
      "debounce": { "min_hits": 1, "window_ms": 0 },
      "escalate": "asan",
      "fallback": ["valgrind_memcheck"],
      "severity": "high",
      "cooldown_ms": 5000
    },
    {
      "id": "R-double-free",
      "match": { "type": "double_free" },
      "debounce": { "min_hits": 1, "window_ms": 0 },
      "escalate": "asan",
      "fallback": ["valgrind_memcheck"],
      "severity": "critical",
      "cooldown_ms": 0
    },
    {
      "id": "R-uninit-to-io",
      "match": { "type": "uninit_to_io" },
      "debounce": { "min_hits": 2, "window_ms": 2000 },
      "escalate": "msan",
      "fallback": ["valgrind_memcheck"],
      "severity": "medium",
      "cooldown_ms": 8000
    },
    {
      "id": "R-lock-cycle",
      "match": { "type": "lock_cycle|futex_cycle" },
      "debounce": { "min_hits": 1, "window_ms": 0 },
      "escalate": "tsan",
      "fallback": ["valgrind_helgrind","gdb_recipe"],
      "severity": "high",
      "cooldown_ms": 10000
    },
    {
      "id": "R-ub-misalign",
      "match": { "type": "ub_misalign|null_deref|overflow" },
      "debounce": { "min_hits": 1, "window_ms": 0 },
      "escalate": "ubsan",
      "fallback": ["gdb_recipe"],
      "severity": "medium",
      "cooldown_ms": 3000
    }
  ],
  "thresholds": { "confidence_hi": 0.8, "confidence_lo": 0.5 }
}

Notes
	•	The engine enforces cooldown per (rule, cluster) so we don’t spam escalations on long runs.
	•	free_then_access and double_free are derived events the router synthesizes from base events.

⸻

4) Harness Plan (v0)

{
  "version": 1,
  "cluster_id": "C1",
  "mode": "pure",                      // pure | driver
  "entrypoint": "replay_copy_oob",     // function name to generate/call
  "suspect_symbols": ["foo::copy_chunk"],
  "suspect_tus": ["src/foo.cpp"],
  "includes": ["include/foo.h"],
  "link_with": ["build/libfoo.a", "build/libbar.a", "libvendor.so"],
  "sanitizer": "asan",                 // asan|tsan|msan|ubsan
  "flags": ["-g","-fno-omit-frame-pointer"],
  "build_env": {
    "CC": "clang",
    "CXX": "clang++",
    "CFLAGS": ["-O1","-fPIC"],
    "CXXFLAGS": ["-O1","-stdlib=libc++"],
    "LDFLAGS": ["-fuse-ld=lld"]
  },
  "inputs": {
    "argv": ["./harness","--n","128"],
    "env": {"LC_ALL":"C"},
    "files": [
      {
        "path": "inputs/cases.txt",
        "ranges": [[0,2048]],
        "sha256": "abc...",
        "pack": { "kind":"tar", "relpath":"inputs/cases.txt" }
      }
    ],
    "blobs": [
      {
        "name":"seed_buffer",
        "base64":"AAECAwQF...",           // cap to, say, 64KB; else use tarball
        "len": 4096
      }
    ]
  },
  "timeout_sec": 60,
  "requires_user_input": false
}

Binary inputs
	•	Prefer tarball packaging of referenced files (pack.kind="tar" with a relative path inside the Crashpack tar).
	•	Allow base64 blobs for small in-memory buffers; cap to ≤ 64 KB.

⸻

5) Open questions — answers
	1.	Emit syscall return?
Yes. We record bytes_ret and errno_code for read/write/send/recv and friends. This is key for uninit-to-I/O and partial I/O heuristics.
	2.	Numeric addresses vs strings?
Numeric (u64). If a consumer wants hex, render at the edge.
	3.	Stack IDs and symbolization?
We carry stack_id (BPF map key) and stack_fp (u32). Userland resolves stack_id → frames using /proc/<pid>/maps, perf/debuginfod, etc. Clustering uses stack_fp.
	4.	Event ordering/drops?
seq and drop_count give deterministic detection of missing events and reordering. The router maintains per-PID state.
	5.	Concurrency disambiguation?
lock_kind, lock_addr, lock_site_id distinguish mutex/rwlock/futex/spin and locations.
	6.	AI hints field
Present but empty by default:
"ai_hint": { "status":"not_enriched", "details":[] }
HTML hides it unless enrichment is requested.

⸻

6) Byte/Perf budgets (so BPF stays safe)
	•	Per-event target: ≤ 112 bytes average (fits 128-byte records comfortably).
	•	Ring buffer per PID: default 8 MB cap (configurable). Drop-oldest behavior; set flags.throttled + drop_count.
	•	Sentinel CPU budget: ≤ 3% of target process under synthetic memcpy/lock churn (Phase-1 perf gate).
	•	Max extra_kv: 4 entries; value length ≤ 32 bytes, elide otherwise.

⸻

7) Minimal examples: end-to-end

Rule hit → cluster → harness plan (snippets)
	•	Event: memcpy with len=128, alloc_size=64 (twice in 1.5s window).
	•	Rule R-memcpy-oob fires (debounce met).
	•	Cluster C1 created (class="oob_write", confidence=0.92).
	•	Harness plan:
	•	mode=pure (we can replay alloc/copy/free).
	•	sanitizer=asan.
	•	entrypoint=replay_copy_oob.
	•	timeout=60s.
	•	Runner builds and executes harness; ASan pinpoints src/foo.cpp:271.
	•	Crashpack contains findings.json, mrs_harness.cc, build.sh, index.html, gdb_recipe.txt.

⸻

Canonical tables to append to the schema doc

extra_kv key map (u8 → meaning)

Reserved range policy:
	•	1–31: common, cross-platform keys (stable).
	•	32–127: ReCC experimental (may change between minor versions).
	•	128–255: app/user extensions (won’t be parsed by core; carried through).

Key (u8)	Name	Value encoding (≤32B)	Notes / Example
1	direction	u8: 0=NA, 1=src→dst, 2=dst→src	memcpy/memmove
2	copy_kind	u8: 0=memcpy, 1=memmove, 2=strcpy, 3=other	memory ops
3	page_fault_sig	u8: 0=NA, 11=SIGSEGV, 7=SIGBUS	trap marker
4	io_kind	u8: 0=NA, 1=file, 2=socket, 3=pipe, 4=tty	read/write/recv/send
5	net_proto	u8: 0=NA, 6=TCP, 17=UDP	sockets
6	errno_hint	s32 (little-endian)	mirrors errno_code when packed via extra_kv (optional)
7	thread_role	u8: 0=NA, 1=main, 2=worker, 3=io, 4=sig	userland annot. later
8	asan_shadow	u64 shadow addr (LE)	optional shadow snapshot
9	alloc_kind	u8: 0=heap, 1=mmap_private, 2=mmap_shared	alloc/mmap events
10	rwlock_mode	u8: 0=NA, 1=read, 2=write	lock events
11	partial_io	u8: 0=no, 1=yes	bytes_ret < requested len

Encoding rule: first byte = v_len (0–32), followed by v_len bytes of data, zero-padded to 32 total. Multi-byte integers are LE.

flags bitfield (u16)

Bit	Name	Meaning
0	throttled	Sentinel rate-limited emission for this PID/TID window (events/sec cap hit).
1	dropped_batch	Kernel or userland dropped one or more events in this batch. See drop_count.
2	kernel_space	Event originated in kernel context (rare; reserved).
3	derived	Event is synthesized by router (e.g., free_then_access, double_free).
4–15	reserved	Keep 0; future use.

Language bindings should expose flags as a struct/bitset (e.g., flags.throttled: bool).

Defaults & knobs
	•	Ring buffer per PID: 8 MB default. Drop-oldest behavior; set flags.throttled and increment drop_count.
Env/CLI override later: RECC_RB_SIZE_MB=<int> or re config set sentinel.ring_mb 4.
	•	Per-event size target: ~112 B average (upper bound 128 B).
	•	Max extra_kv entries: 4 per event; values hard-capped to 32 B each.

Why this is good
	•	Numeric-only (+ explicit sizes) means zero string→int churn and predictable BPF verifier behavior.
	•	The reserved key ranges let us evolve without breaking third-party consumers.
	•	flags → named bits gives clean codegen for Rust/Go/TS.

Compatibility note: Producers MUST NOT emit unknown extra_kv keys in the 1–31 range. Consumers MUST pass through unknown keys (32–255) unchanged. flags.reserved must be 0 on emit; consumers must ignore unknown set bits ≥4.

Implementation nits (so we don’t trip later)
	•	Validate v_len ≤ 32 at emit; if larger, truncate and set extra_kv key 11 (partial_io) or a new 12 (truncated_kv) to signal truncation occurred.
	•	Keep a tiny, shared header (sentinel_enums.h) with:
	•	enum event_type : uint16_t
	•	enum lock_kind : uint8_t
	•	enum extra_key : uint8_t
	•	enum flags_bits : uint16_t
	•	Generate bindings (Rust/Go/TS) from that header or from a single JSON source of truth so clients don’t drift.