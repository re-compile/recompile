// runtime/bpf/heap_tracker.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---- Maps ---- */

// ptr -> size (capacity). Shared with other objs (copy_checker).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);   // heap pointer as u64
    __type(value, __u64);   // size
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allocs SEC(".maps");

// tid -> pending size for malloc/calloc/realloc (entry -> return)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);   // TID
    __type(value, __u64);   // size
    __uint(map_flags, BPF_F_NO_PREALLOC);
} pending SEC(".maps");

// tid -> pending OLD pointer for realloc (to handle success/failure correctly)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);   // TID
    __type(value, __u64);   // old pointer (as u64)
    __uint(map_flags, BPF_F_NO_PREALLOC);
} realloc_old SEC(".maps");

/* ---- Helpers ---- */

/* ---- 64-bit overflow helpers (no 128-bit builtins in eBPF) ---- */
#ifndef U64_MAX
#define U64_MAX (__u64)0xFFFFFFFFFFFFFFFFull
#endif

// 64-bit multiply overflow check without 128-bit ops or division.
// Computes a*b into *out, returns 1 if overflow would occur, else 0.
static __always_inline int mul_overflow_u64(__u64 a, __u64 b, __u64 *out)
{
    __u32 ah = (__u32)(a >> 32), al = (__u32)a;
    __u32 bh = (__u32)(b >> 32), bl = (__u32)b;

    // If both high halves are non-zero, product needs >= 64+ bits -> overflow
    if (ah && bh)
        return 1;

    // Cross terms: (ah*bl + bh*al) must fit in 32 bits, otherwise overflow
    __u64 mid = (__u64)ah * bl + (__u64)bh * al;
    if (mid > 0xFFFFFFFFULL)
        return 1;

    // Low term (al*bl) is 64-bit; add shifted cross term (<<32) safely
    __u64 low  = (__u64)al * bl;
    __u64 high = mid << 32;

    // Check carry on the final add (wrap means overflow)
    __u64 res = high + low;
    if (res < low)
        return 1;

    *out = res;
    return 0;
}

static __always_inline int add_overflow_u64(__u64 a, __u64 b, __u64 *out)
{
    __u64 r = a + b;
    *out = r;
    return r < a;            /* wraparound => overflow */
}

static __always_inline __u32 get_tid(void)
{
    return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline void remember_size(__u64 sz)
{
    __u32 tid = get_tid();
    if (sz == 0) return; // 0 means "unknown/overflow" => do not create mapping
    bpf_map_update_elem(&pending, &tid, &sz, BPF_ANY);
}

static __always_inline __u64 take_pending_size(void)
{
    __u32 tid = get_tid();
    __u64 *p = bpf_map_lookup_elem(&pending, &tid);
    __u64 v = p ? *p : 0;
    if (p) bpf_map_delete_elem(&pending, &tid);
    return v;
}

/* ---- malloc/calloc/realloc/free uprobes ----
 * We read arguments from pt_regs with PT_REGS_PARMx to be arch-safe.
 * aarch64: first 3 args are x0/x1/x2; return value in x0.
 */

SEC("uprobe/malloc")
int BPF_KPROBE(u_malloc_enter)
{
    __u64 size = (__u64)PT_REGS_PARM1(ctx);
    remember_size(size);
    return 0;
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(u_malloc_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = take_pending_size();
    if (ret && size) {
        __u64 key = (__u64)ret;
        bpf_map_update_elem(&allocs, &key, &size, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/calloc")
int BPF_KPROBE(u_calloc_enter)
{
    __u64 nmemb = (__u64)PT_REGS_PARM1(ctx);
    __u64 size  = (__u64)PT_REGS_PARM2(ctx);
    __u64 total = 0;
    if (mul_overflow_u64((__u64)nmemb, (__u64)size, &total))
        total = 0;           /* overflow => unknown; skip mapping on exit */
    remember_size(total);
    return 0;
}

SEC("uretprobe/calloc")
int BPF_KRETPROBE(u_calloc_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = take_pending_size();
    if (ret && size) {
        __u64 key = (__u64)ret;
        bpf_map_update_elem(&allocs, &key, &size, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/realloc")
int BPF_KPROBE(u_realloc_enter)
{
    void *oldp   = (void *)PT_REGS_PARM1(ctx);
    __u64 new_sz = (__u64)PT_REGS_PARM2(ctx);
    // record desired new size and stash old pointer; DO NOT delete yet
    if (oldp) {
        __u32 tid = get_tid();
        __u64 k = (__u64)oldp;
        bpf_map_update_elem(&realloc_old, &tid, &k, BPF_ANY);
    }
    remember_size(new_sz);
    return 0;
}

SEC("uretprobe/realloc")
int BPF_KRETPROBE(u_realloc_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = take_pending_size();
    __u32 tid = get_tid();
    __u64 *pold = bpf_map_lookup_elem(&realloc_old, &tid);
    __u64 old = pold ? *pold : 0;
    if (pold) bpf_map_delete_elem(&realloc_old, &tid);
    if (!ret) {
        // failure path
        if (size == 0 && old) {
            // glibc: realloc(old, 0) frees old and returns NULL
            bpf_map_delete_elem(&allocs, &old);
        }
        // else: keep old mapping as-is (failure, size > 0)
        return 0;
    }

    // success path: new pointer is 'ret'
    if (old && old != (__u64)ret)
        bpf_map_delete_elem(&allocs, &old);
    if (size) {
        __u64 key = (__u64)ret;
        bpf_map_update_elem(&allocs, &key, &size, BPF_ANY);
    }
    return 0;
}

SEC("uprobe/free")
int BPF_KPROBE(u_free_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    if (p) {
        __u64 key = (__u64)p;
        bpf_map_delete_elem(&allocs, &key);
    }
    return 0;
}