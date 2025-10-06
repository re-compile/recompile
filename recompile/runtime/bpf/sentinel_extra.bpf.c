// runtime/bpf/sentinel_extra.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "../shared/re_events.h"

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_CMD_MASK 0x3f

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Shared maps (reused across objects) */
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

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

/* Pending contexts */
struct pid_tid_key {
    __u32 pid;
    __u32 tid;
};

struct io_pending_ctx {
    __u32 fd;
    __u64 len;
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key,   struct pid_tid_key);
    __type(value, struct io_pending_ctx);
} io_pending SEC(".maps");

struct mutex_ctx {
    __u64 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key,   struct pid_tid_key);
    __type(value, struct mutex_ctx);
} mutex_pending SEC(".maps");

struct futex_ctx {
    __u32 op;
    __u32 val;
    __u64 uaddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key,   struct pid_tid_key);
    __type(value, struct futex_ctx);
} futex_pending SEC(".maps");

static __always_inline __u32 get_tid(void)
{
    return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline __u32 saturate_u32(__u64 value)
{
    return value > (__u64)0xffffffff ? (__u32)0xffffffff : (__u32)value;
}

static __always_inline struct re_sentinel_state *sentinel_lookup_state(__u32 pid)
{
    return bpf_map_lookup_elem(&sentinel_state, &pid);
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
    evt->drop_count = st->drops;
    st->drops = 0;
    evt->len = 0;
    evt->alloc_size = 0;
    evt->fd = -1;
    evt->bytes_ret = 0;
    evt->errno_code = 0;
    evt->extra_count = 0;
    evt->seq = st->seq + 1;
    st->seq = evt->seq;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->addr = 0;
    evt->lock_addr = 0;
    return evt;
}

static __always_inline void sentinel_event_submit(struct re_sentinel_event *evt)
{
    if (evt)
        bpf_ringbuf_submit(evt, 0);
}

/* ---------------- I/O (read/write) ---------------- */

SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct io_pending_ctx pending = {
        .fd = (__u32)ctx->args[0],
        .len = ctx->args[2],
        .buf = ctx->args[1],
    };
    bpf_map_update_elem(&io_pending, &key, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };

    struct io_pending_ctx *info = bpf_map_lookup_elem(&io_pending, &key);
    if (!info)
        return 0;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt) {
        bpf_map_delete_elem(&io_pending, &key);
        return 0;
    }

    evt->type = RE_SENTINEL_TYPE_READ;
    evt->fd = (__s32)info->fd;
    evt->len = saturate_u32(info->len);
    evt->addr = info->buf;
    evt->bytes_ret = ctx->ret;
    if (ctx->ret < 0)
        evt->errno_code = (int)(-ctx->ret);

    sentinel_event_submit(evt);
    bpf_map_delete_elem(&io_pending, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct io_pending_ctx pending = {
        .fd = (__u32)ctx->args[0],
        .len = ctx->args[2],
        .buf = ctx->args[1],
    };
    bpf_map_update_elem(&io_pending, &key, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };

    struct io_pending_ctx *info = bpf_map_lookup_elem(&io_pending, &key);
    if (!info)
        return 0;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt) {
        bpf_map_delete_elem(&io_pending, &key);
        return 0;
    }

    evt->type = RE_SENTINEL_TYPE_WRITE;
    evt->fd = (__s32)info->fd;
    evt->len = saturate_u32(info->len);
    evt->addr = info->buf;
    evt->bytes_ret = ctx->ret;
    if (ctx->ret < 0)
        evt->errno_code = (int)(-ctx->ret);

    sentinel_event_submit(evt);
    bpf_map_delete_elem(&io_pending, &key);
    return 0;
}

/* ---------------- Mutex lock/unlock ---------------- */

SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(u_mutex_lock_enter)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct mutex_ctx pending = {
        .addr = (__u64)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&mutex_pending, &key, &pending, BPF_ANY);
    return 0;
}

SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(u_mutex_lock_exit)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        goto out;

    long ret = PT_REGS_RC(ctx);
    if (ret != 0)
        goto out;

    struct mutex_ctx *pending = bpf_map_lookup_elem(&mutex_pending, &key);
    if (!pending)
        goto out;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        goto out;

    evt->type = RE_SENTINEL_TYPE_LOCK_ACQ;
    evt->lock_kind = RE_SENTINEL_LOCK_MUTEX;
    evt->lock_addr = pending->addr;

    sentinel_event_submit(evt);
out:
    bpf_map_delete_elem(&mutex_pending, &key);
    return 0;
}

SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(u_mutex_unlock_enter)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        return 0;

    evt->type = RE_SENTINEL_TYPE_LOCK_REL;
    evt->lock_kind = RE_SENTINEL_LOCK_MUTEX;
    evt->lock_addr = (__u64)PT_REGS_PARM1(ctx);

    sentinel_event_submit(evt);
    return 0;
}

/* ---------------- Futex wait/wake ---------------- */

SEC("tracepoint/syscalls/sys_enter_futex")
int tp_sys_enter_futex(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    __u32 op = (__u32)ctx->args[1];
    __u32 cmd = op & FUTEX_CMD_MASK;
    if (cmd != FUTEX_WAIT && cmd != FUTEX_WAKE)
        return 0;

    struct futex_ctx pending = {
        .op = op,
        .val = (__u32)ctx->args[2],
        .uaddr = ctx->args[0],
    };
    bpf_map_update_elem(&futex_pending, &key, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int tp_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct pid_tid_key key = {
        .pid = pid,
        .tid = (__u32)pid_tgid,
    };
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        goto out;

    struct futex_ctx *info = bpf_map_lookup_elem(&futex_pending, &key);
    if (!info)
        goto out;

    __u32 cmd = info->op & FUTEX_CMD_MASK;
    __u16 event_type = 0;
    if (cmd == FUTEX_WAIT)
        event_type = RE_SENTINEL_TYPE_FUTEX_WAIT;
    else if (cmd == FUTEX_WAKE)
        event_type = RE_SENTINEL_TYPE_FUTEX_WAKE;
    if (!event_type)
        goto out;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        goto out;

    evt->type = event_type;
    evt->lock_kind = RE_SENTINEL_LOCK_FUTEX;
    evt->lock_addr = info->uaddr;
    evt->len = info->val;
    evt->bytes_ret = ctx->ret;
    if (ctx->ret < 0)
        evt->errno_code = (int)(-ctx->ret);

    sentinel_event_submit(evt);
out:
    bpf_map_delete_elem(&futex_pending, &key);
    return 0;
}

/* ---------------- Signal delivery ---------------- */

SEC("tracepoint/signal/signal_deliver")
int tp_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_sentinel_state *st = sentinel_lookup_state(pid);
    if (!st || !(st->flags & RE_SENTINEL_STATE_ARMED))
        return 0;

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        return 0;

    evt->type = RE_SENTINEL_TYPE_SIGNAL_ENTER;
    evt->len = ctx->sig;
    evt->errno_code = ctx->errno;
    evt->addr = 0;

    sentinel_event_submit(evt);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
