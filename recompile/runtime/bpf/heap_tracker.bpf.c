// runtime/bpf/heap_tracker.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "../shared/re_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ----------------------------------------------------------------------
 * Shared maps
 * ---------------------------------------------------------------------- */

// ptr -> alloc info (size + alloc stack). Shared with copy_checker.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct re_alloc_key);
    __type(value, struct re_alloc_info);
} allocs SEC(".maps");

// cache for recently freed allocations (detect double/invalid frees)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct re_alloc_key);
    __type(value, struct re_alloc_info);
} freed SEC(".maps");

// tid -> pending size for malloc/calloc/realloc (entry -> return)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);   // TID
    __type(value, __u64);   // encoded size (size+1, U64_MAX sentinel)
} pending SEC(".maps");

// tid -> pending OLD pointer for realloc (to handle success/failure correctly)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);   // TID
    __type(value, __u64);   // old pointer (as u64)
} realloc_old SEC(".maps");

// tid -> pending output pointer slot for APIs that return status separately.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);   // TID
    __type(value, __u64);   // user-space pointer slot address
} pending_out_ptr SEC(".maps");

// Sentinel ring buffer (shared with other programs)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20); // 8 MiB per PID default budget
} sentinel_events SEC(".maps");

// Per-PID sequence/drop state for sentinel events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key,   __u32);
    __type(value, struct re_sentinel_state);
} sentinel_state SEC(".maps");

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * PERF_MAX_STACK_DEPTH);
    __uint(max_entries, 2048);
} ustacks SEC(".maps");

/* ----------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

#ifndef U64_MAX
#define U64_MAX (__u64)0xFFFFFFFFFFFFFFFFull
#endif

static __always_inline struct re_sentinel_state *sentinel_get_state(__u32 pid)
{
    struct re_sentinel_state *st = bpf_map_lookup_elem(&sentinel_state, &pid);
    if (!st) {
        struct re_sentinel_state zero = {};
        if (bpf_map_update_elem(&sentinel_state, &pid, &zero, BPF_NOEXIST) == 0)
            st = bpf_map_lookup_elem(&sentinel_state, &pid);
    }
    return st;
}

static __always_inline struct re_sentinel_event *sentinel_event_reserve(struct re_sentinel_state *st, __u64 pid_tgid)
{
    if (!st)
        return NULL;

    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    struct re_sentinel_event *evt = bpf_ringbuf_reserve(&sentinel_events, sizeof(*evt), 0);
    if (!evt) {
        st->drops += 1;
        return NULL;
    }

    evt->version = RE_SENTINEL_EVENT_VERSION;
    evt->type = 0;
    evt->flags = 0;
    evt->lock_kind = RE_SENTINEL_LOCK_NONE;
    evt->pid = pid;
    evt->tid = tid;
    evt->site_id = 0;
    evt->stack_id = -1;
    evt->stack_fp = 0;
    evt->lock_site_id = 0;
    evt->drop_count = 0;
    evt->len = 0;
    evt->alloc_size = 0;
    evt->fd = -1;
    evt->bytes_ret = 0;
    evt->errno_code = 0;
    evt->extra_count = 0;
    evt->seq = 0;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->addr = 0;
    evt->lock_addr = 0;

    __u64 seq = st->seq + 1;
    evt->seq = seq;
    evt->drop_count = st->drops;
    st->seq = seq;
    st->drops = 0;
    return evt;
}

static __always_inline void sentinel_event_submit(struct re_sentinel_event *evt)
{
    if (evt)
        bpf_ringbuf_submit(evt, 0);
}

static __always_inline __u32 saturate_u32(__u64 value)
{
    return value > (__u64)0xffffffff ? (__u32)0xffffffff : (__u32)value;
}

static __always_inline __u32 get_tid(void)
{
    return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline void remember_size(__u64 sz)
{
    __u32 tid = get_tid();
    __u64 enc = (sz == U64_MAX) ? U64_MAX : (sz + 1);
    bpf_map_update_elem(&pending, &tid, &enc, BPF_ANY);
}

static __always_inline bool take_pending_size(__u64 *out)
{
    __u32 tid = get_tid();
    __u64 *p = bpf_map_lookup_elem(&pending, &tid);
    if (!p)
        return false;
    __u64 enc = *p;
    bpf_map_delete_elem(&pending, &tid);
    if (enc == U64_MAX)
        *out = U64_MAX;
    else
        *out = enc - 1;
    return true;
}

static __always_inline void remember_out_ptr(void *slot)
{
    __u32 tid = get_tid();
    __u64 addr = (__u64)slot;
    bpf_map_update_elem(&pending_out_ptr, &tid, &addr, BPF_ANY);
}

static __always_inline bool take_pending_out_ptr(__u64 *out)
{
    __u32 tid = get_tid();
    __u64 *p = bpf_map_lookup_elem(&pending_out_ptr, &tid);
    if (!p)
        return false;
    *out = *p;
    bpf_map_delete_elem(&pending_out_ptr, &tid);
    return true;
}

static __always_inline void remember_string_size(const char *src)
{
    char buf[256];

    if (!src) {
        remember_size(0);
        return;
    }

    long len = bpf_probe_read_user_str(buf, sizeof(buf), src);
    if (len <= 0 || len >= (long)sizeof(buf))
        remember_size(U64_MAX);
    else
        remember_size((__u64)len);
}

static __always_inline void mark_allocation_freed(__u32 pid, struct re_alloc_key *key)
{
    struct re_alloc_info *info = bpf_map_lookup_elem(&allocs, key);
    if (!info)
        return;

    struct re_alloc_info snapshot = *info;
    bpf_map_delete_elem(&allocs, key);
    bpf_map_update_elem(&freed, key, &snapshot, BPF_ANY);
}

static __always_inline int record_allocation_return(struct pt_regs *ctx, void *ret,
                                                    __u64 size, bool have_size)
{
    if (!ret)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    int stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);

    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (!st)
        return 0;

    struct re_alloc_key key = {
        .pid = pid,
        .addr = (__u64)ret,
    };

    if (have_size) {
        st->flags |= RE_SENTINEL_STATE_ARMED;
        bpf_map_delete_elem(&freed, &key);
        struct re_alloc_info info = {
            .size = size,
            .alloc_stack_id = stack_id,
        };
        bpf_map_update_elem(&allocs, &key, &info, BPF_ANY);
    }

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        return 0;

    evt->type = RE_SENTINEL_TYPE_MALLOC;
    evt->addr = (__u64)ret;
    evt->stack_id = stack_id;
    if (stack_id >= 0)
        evt->stack_fp = (__u32)stack_id;
    evt->len = have_size ? saturate_u32(size) : 0;
    evt->alloc_size = evt->len;

    sentinel_event_submit(evt);
    return 0;
}

/* ---- 64-bit overflow helpers (no 128-bit builtins in eBPF) ---- */
static __always_inline int mul_overflow_u64(__u64 a, __u64 b, __u64 *out)
{
    __u32 ah = (__u32)(a >> 32), al = (__u32)a;
    __u32 bh = (__u32)(b >> 32), bl = (__u32)b;

    if (ah && bh)
        return 1;

    __u64 mid = (__u64)ah * bl + (__u64)bh * al;
    if (mid > 0xFFFFFFFFULL)
        return 1;

    __u64 low  = (__u64)al * bl;
    __u64 high = mid << 32;
    __u64 res = high + low;
    if (res < low)
        return 1;

    *out = res;
    return 0;
}

/* ----------------------------------------------------------------------
 * Uprobes
 * ---------------------------------------------------------------------- */

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
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    return record_allocation_return(ctx, ret, size, have_size);
}

SEC("uprobe/calloc")
int BPF_KPROBE(u_calloc_enter)
{
    __u64 nmemb = (__u64)PT_REGS_PARM1(ctx);
    __u64 size  = (__u64)PT_REGS_PARM2(ctx);
    __u64 total = 0;
    if (mul_overflow_u64(nmemb, size, &total))
        total = 0;
    remember_size(total);
    return 0;
}

SEC("uretprobe/calloc")
int BPF_KRETPROBE(u_calloc_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    return record_allocation_return(ctx, ret, size, have_size);
}

SEC("uprobe/realloc")
int BPF_KPROBE(u_realloc_enter)
{
    void *oldp   = (void *)PT_REGS_PARM1(ctx);
    __u64 new_sz = (__u64)PT_REGS_PARM2(ctx);
    if (oldp) {
        __u32 tid = get_tid();
        __u64 addr = (__u64)oldp;
        bpf_map_update_elem(&realloc_old, &tid, &addr, BPF_ANY);
    }
    remember_size(new_sz);
    return 0;
}

SEC("uretprobe/realloc")
int BPF_KRETPROBE(u_realloc_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    __u32 tid = get_tid();
    __u64 *pold = bpf_map_lookup_elem(&realloc_old, &tid);
    __u64 old = pold ? *pold : 0;
    if (pold)
        bpf_map_delete_elem(&realloc_old, &tid);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct re_alloc_key old_key = {
        .pid = pid,
        .addr = old,
    };

    if (!ret) {
        if (have_size && size == 0 && old)
            mark_allocation_freed(pid, &old_key);
        return 0;
    }

    if (old && old != (__u64)ret)
        mark_allocation_freed(pid, &old_key);

    return record_allocation_return(ctx, ret, size, have_size);
}

SEC("uprobe/posix_memalign")
int BPF_KPROBE(u_posix_memalign_enter)
{
    void *memptr = (void *)PT_REGS_PARM1(ctx);
    __u64 size = (__u64)PT_REGS_PARM3(ctx);
    remember_out_ptr(memptr);
    remember_size(size);
    return 0;
}

SEC("uretprobe/posix_memalign")
int BPF_KRETPROBE(u_posix_memalign_exit)
{
    long rc = PT_REGS_RC(ctx);
    __u64 size = 0;
    __u64 out_slot = 0;
    bool have_size = take_pending_size(&size);
    bool have_slot = take_pending_out_ptr(&out_slot);
    __u64 ret_addr = 0;

    if (rc != 0 || !have_slot || !out_slot)
        return 0;
    if (bpf_probe_read_user(&ret_addr, sizeof(ret_addr), (void *)out_slot) != 0)
        return 0;

    return record_allocation_return(ctx, (void *)ret_addr, size, have_size);
}

SEC("uprobe/aligned_alloc")
int BPF_KPROBE(u_aligned_alloc_enter)
{
    __u64 size = (__u64)PT_REGS_PARM2(ctx);
    remember_size(size);
    return 0;
}

SEC("uretprobe/aligned_alloc")
int BPF_KRETPROBE(u_aligned_alloc_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    return record_allocation_return(ctx, ret, size, have_size);
}

SEC("uprobe/strdup")
int BPF_KPROBE(u_strdup_enter)
{
    const char *src = (const char *)PT_REGS_PARM1(ctx);
    remember_string_size(src);
    return 0;
}

SEC("uretprobe/strdup")
int BPF_KRETPROBE(u_strdup_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    return record_allocation_return(ctx, ret, size, have_size);
}

SEC("uprobe/free")
int BPF_KPROBE(u_free_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    if (!p)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct re_alloc_key key = {
        .pid = pid,
        .addr = (__u64)p,
    };

    struct re_alloc_info *info = bpf_map_lookup_elem(&allocs, &key);
    struct re_alloc_info *prev = bpf_map_lookup_elem(&freed, &key);

    __u8 status = RE_SENTINEL_FREE_OK;
    __u64 size = 0;
    __s32 alloc_stack = -1;

    if (!info) {
        if (prev) {
            status = RE_SENTINEL_FREE_DOUBLE;
            size = prev->size;
            alloc_stack = prev->alloc_stack_id;
        } else {
            status = RE_SENTINEL_FREE_INVALID;
        }
    } else {
        size = info->size;
        alloc_stack = info->alloc_stack_id;
    }

    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (!st)
        return 0;

    // Invalid and double frees must still be reported even when this PID never
    // performed a tracked allocation. Keep the arming gate only for benign frees.
    if (!(st->flags & RE_SENTINEL_STATE_ARMED) && status == RE_SENTINEL_FREE_OK)
        return 0;

    int stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        return 0;

    evt->type = RE_SENTINEL_TYPE_FREE;
    evt->addr = key.addr;
    evt->stack_id = stack_id;
    if (stack_id >= 0)
        evt->stack_fp = (__u32)stack_id;
    evt->alloc_size = saturate_u32(size);
    evt->errno_code = status;

    if (alloc_stack >= 0)
        evt->site_id = (unsigned)(alloc_stack + 1);

    if (info) {
        struct re_alloc_info snapshot = *info;
        bpf_map_delete_elem(&allocs, &key);
        bpf_map_update_elem(&freed, &key, &snapshot, BPF_ANY);
    }

    sentinel_event_submit(evt);
    return 0;
}
