// runtime/bpf/copy_checker.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* macOS host toolchain won't bring this in; kernel default is 127 */
#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif


/* ---- Shared map from heap_tracker (same spec!) ---- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, __u64);   // size
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allocs SEC(".maps");

/* ---- Ring buffer for findings ---- */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB
} events SEC(".maps");

/* ---- Optional user stack store (ids) ---- */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * PERF_MAX_STACK_DEPTH);
    __uint(max_entries, 1024);
} ustacks SEC(".maps");

// add near other maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
  } hits SEC(".maps");

/* ---- Event payload (keep it POD & stable) ---- */
struct copy_event {
    __u64 ts_ns;
    __u64 dst;
    __u64 src;
    __u64 len;
    __u64 dst_size;   // 0 if unknown
    __s32 call_sid;   // stack id (user)
    __u8  api;        // 1 = memcpy (future: 2=memmove, 3=strcpy, etc.)
    __u8  severity;   // rule-of-thumb: 2=warn, 3=error
    __u16 _pad;
};

enum {
    API_MEMCPY = 1,
};

static __always_inline void fill_basic(struct pt_regs *ctx,
    struct copy_event *e,
    void *dst, const void *src, __u64 len)
{
    e->ts_ns   = bpf_ktime_get_ns();
    e->dst     = (__u64)dst;
    e->src     = (__u64)src;
    e->len     = len;
    e->api     = API_MEMCPY;
    e->severity= 2;
    e->call_sid= bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
}

/* We read args from pt_regs for portability. */
SEC("uprobe/memcpy")
int BPF_KPROBE(on_memcpy)
{
    void *dst        = (void *)PT_REGS_PARM1(ctx);
    const void *src  = (const void *)PT_REGS_PARM2(ctx);
    __u64 len        = (__u64)PT_REGS_PARM3(ctx);
    __u32 k = 0;
    __u64 one = 1;
    __u64 *c = bpf_map_lookup_elem(&hits, &k);
    if (c) (*c)++;

    if (!dst) return 0;

    // Look up heap capacity if we have it
    __u64 key = (__u64)dst;
    __u64 *psz = bpf_map_lookup_elem(&allocs, &key);
    __u64 cap = psz ? *psz : 0;

    // Emit an event whenever cap is unknown or len > cap
    if (cap && len <= cap)
        return 0; // fast-path: safe heap copy

    struct copy_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_basic(ctx, e, dst, src, len);
    e->dst_size = cap;

    // quick severity heuristic
    if (cap && len > cap) e->severity = 3; // overflow

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";