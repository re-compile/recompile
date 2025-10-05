// runtime/bpf/copy_checker.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "../shared/re_events.h"

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

/* Shared maps (re-used from heap_tracker) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, struct re_alloc_info);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20);
} sentinel_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key,   __u32);
    __type(value, struct re_sentinel_state);
} sentinel_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * PERF_MAX_STACK_DEPTH);
    __uint(max_entries, 1024);
} ustacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} hits SEC(".maps");

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

enum {
    RE_MEM_API_MEMCPY = 1,
};

SEC("uprobe/memcpy")
int BPF_KPROBE(on_memcpy)
{
    void *dst        = (void *)PT_REGS_PARM1(ctx);
    __u64 len        = (__u64)PT_REGS_PARM3(ctx);

    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&hits, &k);
    if (c)
        *c += 1;

    if (!dst)
        return 0;

    __u64 key = (__u64)dst;
    struct re_alloc_info *info = bpf_map_lookup_elem(&allocs, &key);
    __u64 cap = info ? info->size : 0;
    __s32 alloc_sid = info ? info->alloc_stack_id : -1;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (!st)
        return 0;

    if (!(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        return 0;

    int stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);

    evt->type = RE_SENTINEL_TYPE_MEMCPY;
    evt->addr = key;
    evt->stack_id = stack_id;
    evt->stack_fp = (__u32)stack_id;
    evt->len = saturate_u32(len);
    evt->alloc_size = saturate_u32(cap);

    evt->errno_code = RE_MEM_API_MEMCPY;
    if (alloc_sid >= 0)
        evt->site_id = (unsigned)(alloc_sid + 1);

    sentinel_event_submit(evt);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
