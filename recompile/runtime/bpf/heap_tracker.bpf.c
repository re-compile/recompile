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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct re_alloc_range_key);
    __type(value, struct re_alloc_range_bucket);
} alloc_ranges SEC(".maps");

// cache for recently freed allocations (detect double/invalid frees)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct re_alloc_key);
    __type(value, struct re_alloc_info);
} freed SEC(".maps");

// pid/fd -> open lifecycle info. Drained by userland on target exit to detect leaks.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct re_fd_key);
    __type(value, struct re_fd_info);
} open_fds SEC(".maps");

// pid/fd -> recently closed lifecycle info. Used to distinguish double-close from invalid-close.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct re_fd_key);
    __type(value, struct re_fd_info);
} closed_fds SEC(".maps");

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

struct re_pending_close {
    __s32 fd;
    __s32 stack_id;
};

struct re_pending_dup {
    __s32 old_fd;
    __s32 requested_new_fd;
    __s32 stack_id;
};

// tid -> close(fd) entry metadata, consumed by close return.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);
    __type(value, struct re_pending_close);
} pending_close SEC(".maps");

// tid -> dup-family entry metadata, consumed by dup-family return.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);
    __type(value, struct re_pending_dup);
} pending_dup SEC(".maps");

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
    evt->alloc_offset = 0;
    evt->fd = -1;
    evt->bytes_ret = 0;
    evt->errno_code = 0;
    evt->extra_count = 0;
    evt->seq = 0;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->addr = 0;
    evt->lock_addr = 0;
    evt->alloc_base = 0;

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

static __always_inline void remember_close_fd(__s32 fd, __s32 stack_id)
{
    __u32 tid = get_tid();
    struct re_pending_close info = {
        .fd = fd,
        .stack_id = stack_id,
    };
    bpf_map_update_elem(&pending_close, &tid, &info, BPF_ANY);
}

static __always_inline bool take_pending_close_fd(struct re_pending_close *out)
{
    __u32 tid = get_tid();
    struct re_pending_close *p = bpf_map_lookup_elem(&pending_close, &tid);
    if (!p)
        return false;
    if (out)
        *out = *p;
    bpf_map_delete_elem(&pending_close, &tid);
    return true;
}

static __always_inline void remember_dup_fd(__s32 old_fd, __s32 requested_new_fd, __s32 stack_id)
{
    __u32 tid = get_tid();
    struct re_pending_dup info = {
        .old_fd = old_fd,
        .requested_new_fd = requested_new_fd,
        .stack_id = stack_id,
    };
    bpf_map_update_elem(&pending_dup, &tid, &info, BPF_ANY);
}

static __always_inline bool take_pending_dup_fd(struct re_pending_dup *out)
{
    __u32 tid = get_tid();
    struct re_pending_dup *p = bpf_map_lookup_elem(&pending_dup, &tid);
    if (!p)
        return false;
    if (out)
        *out = *p;
    bpf_map_delete_elem(&pending_dup, &tid);
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

static __always_inline void store_range_slot(struct re_alloc_range_bucket *bucket,
                                             __u64 addr,
                                             const struct re_alloc_info *info)
{
    bool stored = false;

#pragma unroll
    for (int i = 0; i < RE_ALLOC_RANGE_SLOTS; ++i) {
        struct re_alloc_range_info *slot = &bucket->slots[i];
        if (!stored && (slot->base == addr || slot->base == 0)) {
            slot->base = addr;
            slot->size = info->size;
            slot->alloc_stack_id = info->alloc_stack_id;
            slot->family = info->family;
            stored = true;
        }
    }

    if (!stored) {
        bucket->slots[0].base = addr;
        bucket->slots[0].size = info->size;
        bucket->slots[0].alloc_stack_id = info->alloc_stack_id;
        bucket->slots[0].family = info->family;
    }
}

static __always_inline void clear_range_slot(struct re_alloc_range_bucket *bucket, __u64 addr)
{
#pragma unroll
    for (int i = 0; i < RE_ALLOC_RANGE_SLOTS; ++i) {
        struct re_alloc_range_info *slot = &bucket->slots[i];
        if (slot->base == addr) {
            slot->base = 0;
            slot->size = 0;
            slot->alloc_stack_id = -1;
            slot->family = RE_SENTINEL_ALLOC_UNKNOWN;
        }
    }
}

static __always_inline void index_allocation_range(__u32 pid,
                                                   __u64 addr,
                                                   const struct re_alloc_info *info)
{
    if (!addr || !info || info->size == 0)
        return;

    __u64 first_page = addr >> RE_ALLOC_PAGE_SHIFT;
    __u64 last_byte = addr + info->size - 1;
    if (last_byte < addr)
        last_byte = addr;
    __u64 last_page = last_byte >> RE_ALLOC_PAGE_SHIFT;
    __u64 page_count = last_page - first_page + 1;
    if (page_count > RE_ALLOC_PAGE_SPAN_MAX)
        page_count = RE_ALLOC_PAGE_SPAN_MAX;

#pragma unroll
    for (int i = 0; i < RE_ALLOC_PAGE_SPAN_MAX; ++i) {
        if ((__u64)i >= page_count)
            break;
        struct re_alloc_range_key range_key = {
            .pid = pid,
            .page = first_page + (__u64)i,
        };
        struct re_alloc_range_bucket *bucket = bpf_map_lookup_elem(&alloc_ranges, &range_key);
        if (!bucket) {
            struct re_alloc_range_bucket empty = {};
            bpf_map_update_elem(&alloc_ranges, &range_key, &empty, BPF_NOEXIST);
            bucket = bpf_map_lookup_elem(&alloc_ranges, &range_key);
        }
        if (bucket)
            store_range_slot(bucket, addr, info);
    }
}

static __always_inline void remove_allocation_range(__u32 pid,
                                                    __u64 addr,
                                                    const struct re_alloc_info *info)
{
    if (!addr || !info || info->size == 0)
        return;

    __u64 first_page = addr >> RE_ALLOC_PAGE_SHIFT;
    __u64 last_byte = addr + info->size - 1;
    if (last_byte < addr)
        last_byte = addr;
    __u64 last_page = last_byte >> RE_ALLOC_PAGE_SHIFT;
    __u64 page_count = last_page - first_page + 1;
    if (page_count > RE_ALLOC_PAGE_SPAN_MAX)
        page_count = RE_ALLOC_PAGE_SPAN_MAX;

#pragma unroll
    for (int i = 0; i < RE_ALLOC_PAGE_SPAN_MAX; ++i) {
        if ((__u64)i >= page_count)
            break;
        struct re_alloc_range_key range_key = {
            .pid = pid,
            .page = first_page + (__u64)i,
        };
        struct re_alloc_range_bucket *bucket = bpf_map_lookup_elem(&alloc_ranges, &range_key);
        if (bucket)
            clear_range_slot(bucket, addr);
    }
}

static __always_inline void mark_allocation_freed(__u32 pid, struct re_alloc_key *key)
{
    struct re_alloc_info *info = bpf_map_lookup_elem(&allocs, key);
    if (!info)
        return;

    struct re_alloc_info snapshot = *info;
    snapshot.dealloc_family = RE_SENTINEL_DEALLOC_FREE;
    remove_allocation_range(pid, key->addr, info);
    bpf_map_delete_elem(&allocs, key);
    bpf_map_update_elem(&freed, key, &snapshot, BPF_ANY);
}

static __always_inline bool alloc_family_matches_dealloc(__u8 alloc_family, __u8 dealloc_family)
{
    if (alloc_family == RE_SENTINEL_ALLOC_MALLOC)
        return dealloc_family == RE_SENTINEL_DEALLOC_FREE;
    if (alloc_family == RE_SENTINEL_ALLOC_NEW)
        return dealloc_family == RE_SENTINEL_DEALLOC_DELETE;
    if (alloc_family == RE_SENTINEL_ALLOC_NEW_ARRAY)
        return dealloc_family == RE_SENTINEL_DEALLOC_DELETE_ARRAY;
    return true;
}

static __always_inline int record_allocation_return(struct pt_regs *ctx, void *ret,
                                                    __u64 size, bool have_size, __u8 family)
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

    bool should_track = have_size || family != RE_SENTINEL_ALLOC_MALLOC;
    if (should_track) {
        st->flags |= RE_SENTINEL_STATE_ARMED;
        bpf_map_delete_elem(&freed, &key);
        struct re_alloc_info info = {
            .size = have_size ? size : 0,
            .alloc_stack_id = stack_id,
            .family = family,
        };
        struct re_alloc_info *old_info = bpf_map_lookup_elem(&allocs, &key);
        if (old_info)
            remove_allocation_range(pid, key.addr, old_info);
        bpf_map_update_elem(&allocs, &key, &info, BPF_ANY);
        index_allocation_range(pid, key.addr, &info);
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
    evt->alloc_base = (__u64)ret;

    sentinel_event_submit(evt);
    return 0;
}

static __always_inline int record_deallocation(struct pt_regs *ctx, void *p, __u8 dealloc_family)
{
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

    if (!info && prev
        && (prev->dealloc_family == RE_SENTINEL_DEALLOC_DELETE
            || prev->dealloc_family == RE_SENTINEL_DEALLOC_DELETE_ARRAY)) {
        if (dealloc_family == RE_SENTINEL_DEALLOC_FREE)
            bpf_map_delete_elem(&freed, &key);
        return 0;
    }

    __u8 status = RE_SENTINEL_FREE_OK;
    __u64 size = 0;
    __s32 alloc_stack = -1;
    __u8 alloc_family = RE_SENTINEL_ALLOC_UNKNOWN;

    if (!info) {
        if (prev) {
            status = RE_SENTINEL_FREE_DOUBLE;
            size = prev->size;
            alloc_stack = prev->alloc_stack_id;
            alloc_family = prev->family;
        } else {
            status = RE_SENTINEL_FREE_INVALID;
        }
    } else {
        size = info->size;
        alloc_stack = info->alloc_stack_id;
        alloc_family = info->family;
        if (!alloc_family_matches_dealloc(alloc_family, dealloc_family))
            status = RE_SENTINEL_FREE_MISMATCH;
    }

    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (!st)
        return 0;

    // Invalid, double, and family-mismatch frees must still be reported even
    // when this PID never performed a tracked allocation. Keep the arming gate
    // only for benign frees.
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
    evt->len = alloc_family;
    evt->bytes_ret = dealloc_family;

    if (alloc_stack >= 0)
        evt->site_id = (unsigned)(alloc_stack + 1);

    if (info) {
        struct re_alloc_info snapshot = *info;
        snapshot.dealloc_family = dealloc_family;
        remove_allocation_range(pid, key.addr, info);
        bpf_map_delete_elem(&allocs, &key);
        bpf_map_update_elem(&freed, &key, &snapshot, BPF_ANY);
    }

    sentinel_event_submit(evt);
    return 0;
}

static __always_inline int record_fd_open_return(struct pt_regs *ctx, long ret)
{
    __s64 rc = (__s64)ret;
    if (rc < 0 || rc > 0x7fffffff)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __s32 fd = (__s32)rc;
    int stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);

    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (st)
        st->flags |= RE_SENTINEL_STATE_ARMED;

    struct re_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    struct re_fd_info info = {
        .open_stack_id = stack_id,
        .close_stack_id = -1,
        .origin_stack_id = stack_id,
        ._pad = 0,
        .opened_ts_ns = bpf_ktime_get_ns(),
        .closed_ts_ns = 0,
    };

    bpf_map_delete_elem(&closed_fds, &key);
    bpf_map_update_elem(&open_fds, &key, &info, BPF_ANY);
    return 0;
}

static __always_inline int record_fd_close_return(struct pt_regs *ctx, long ret)
{
    struct re_pending_close pending_info = {};
    if (!take_pending_close_fd(&pending_info))
        return 0;

    __s32 fd = pending_info.fd;
    if (fd < 0 && ret == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_fd_key key = {
        .pid = pid,
        .fd = fd,
    };
    struct re_fd_info *active = bpf_map_lookup_elem(&open_fds, &key);

    if (ret == 0) {
        if (active) {
            struct re_fd_info snapshot = *active;
            snapshot.close_stack_id = pending_info.stack_id;
            snapshot.closed_ts_ns = bpf_ktime_get_ns();
            bpf_map_delete_elem(&open_fds, &key);
            bpf_map_update_elem(&closed_fds, &key, &snapshot, BPF_ANY);
        }
        return 0;
    }

    // If libc reports a close failure for a descriptor we still consider open,
    // do not emit a lifecycle bug. The descriptor ownership is unresolved.
    if (active)
        return 0;

    struct re_fd_info *closed = bpf_map_lookup_elem(&closed_fds, &key);
    __u8 status = RE_SENTINEL_FD_INVALID_CLOSE;
    __s32 open_stack = -1;
    if (closed) {
        status = RE_SENTINEL_FD_DOUBLE_CLOSE;
        open_stack = closed->open_stack_id;
    }

    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (!st)
        return 0;

    int stack_id = pending_info.stack_id;
    if (stack_id < 0)
        stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);

    struct re_sentinel_event *evt = sentinel_event_reserve(st, pid_tgid);
    if (!evt)
        return 0;

    evt->type = RE_SENTINEL_TYPE_FD_CLOSE;
    evt->fd = fd;
    evt->addr = (__u64)(__u32)fd;
    evt->stack_id = stack_id;
    if (stack_id >= 0)
        evt->stack_fp = (__u32)stack_id;
    evt->errno_code = status;
    evt->bytes_ret = (__s32)ret;
    if (open_stack >= 0)
        evt->site_id = (__u32)(open_stack + 1);

    sentinel_event_submit(evt);
    return 0;
}

static __always_inline int record_fd_dup_return(long ret)
{
    struct re_pending_dup pending_info = {};
    if (!take_pending_dup_fd(&pending_info))
        return 0;

    __s64 rc = (__s64)ret;
    if (rc < 0 || rc > 0x7fffffff)
        return 0;

    __s32 old_fd = pending_info.old_fd;
    __s32 new_fd = (__s32)rc;
    if (old_fd < 0 || new_fd < 0)
        return 0;

    // dup2/dup3(old, old) is a documented no-op and should not create a
    // second ownership record.
    if (pending_info.requested_new_fd == old_fd && new_fd == old_fd)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct re_fd_key old_key = {
        .pid = pid,
        .fd = old_fd,
    };
    struct re_fd_key new_key = {
        .pid = pid,
        .fd = new_fd,
    };

    struct re_fd_info info = {
        .open_stack_id = pending_info.stack_id,
        .close_stack_id = -1,
        .origin_stack_id = pending_info.stack_id,
        ._pad = 0,
        .opened_ts_ns = bpf_ktime_get_ns(),
        .closed_ts_ns = 0,
    };

    struct re_fd_info *old_info = bpf_map_lookup_elem(&open_fds, &old_key);
    if (old_info) {
        info = *old_info;
        // The duplicate descriptor becomes a new owner at the dup call site.
        info.open_stack_id = pending_info.stack_id;
        info.close_stack_id = -1;
        if (info.origin_stack_id < 0)
            info.origin_stack_id = old_info->open_stack_id;
        info.opened_ts_ns = bpf_ktime_get_ns();
        info.closed_ts_ns = 0;
    }

    struct re_sentinel_state *st = sentinel_get_state(pid);
    if (st)
        st->flags |= RE_SENTINEL_STATE_ARMED;

    bpf_map_delete_elem(&closed_fds, &new_key);
    bpf_map_update_elem(&open_fds, &new_key, &info, BPF_ANY);
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
    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_MALLOC);
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
    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_MALLOC);
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

    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_MALLOC);
}

SEC("uprobe/_Znwm")
int BPF_KPROBE(u_cxx_new_enter)
{
    __u64 size = (__u64)PT_REGS_PARM1(ctx);
    remember_size(size);
    return 0;
}

SEC("uretprobe/_Znwm")
int BPF_KRETPROBE(u_cxx_new_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_NEW);
}

SEC("uprobe/_Znam")
int BPF_KPROBE(u_cxx_new_array_enter)
{
    __u64 size = (__u64)PT_REGS_PARM1(ctx);
    remember_size(size);
    return 0;
}

SEC("uretprobe/_Znam")
int BPF_KRETPROBE(u_cxx_new_array_exit)
{
    void *ret = (void *)PT_REGS_RC(ctx);
    __u64 size = 0;
    bool have_size = take_pending_size(&size);
    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_NEW_ARRAY);
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

    return record_allocation_return(ctx, (void *)ret_addr, size, have_size, RE_SENTINEL_ALLOC_MALLOC);
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
    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_MALLOC);
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
    return record_allocation_return(ctx, ret, size, have_size, RE_SENTINEL_ALLOC_MALLOC);
}

SEC("uprobe/free")
int BPF_KPROBE(u_free_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    return record_deallocation(ctx, p, RE_SENTINEL_DEALLOC_FREE);
}

SEC("uprobe/_ZdlPv")
int BPF_KPROBE(u_cxx_delete_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    return record_deallocation(ctx, p, RE_SENTINEL_DEALLOC_DELETE);
}

SEC("uprobe/_ZdlPvm")
int BPF_KPROBE(u_cxx_delete_sized_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    return record_deallocation(ctx, p, RE_SENTINEL_DEALLOC_DELETE);
}

SEC("uprobe/_ZdaPv")
int BPF_KPROBE(u_cxx_delete_array_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    return record_deallocation(ctx, p, RE_SENTINEL_DEALLOC_DELETE_ARRAY);
}

SEC("uprobe/_ZdaPvm")
int BPF_KPROBE(u_cxx_delete_array_sized_enter)
{
    void *p = (void *)PT_REGS_PARM1(ctx);
    return record_deallocation(ctx, p, RE_SENTINEL_DEALLOC_DELETE_ARRAY);
}

SEC("uretprobe/open")
int BPF_KRETPROBE(u_open_exit)
{
    return record_fd_open_return(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe/open64")
int BPF_KRETPROBE(u_open64_exit)
{
    return record_fd_open_return(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe/openat")
int BPF_KRETPROBE(u_openat_exit)
{
    return record_fd_open_return(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe/openat64")
int BPF_KRETPROBE(u_openat64_exit)
{
    return record_fd_open_return(ctx, PT_REGS_RC(ctx));
}

SEC("uretprobe/creat")
int BPF_KRETPROBE(u_creat_exit)
{
    return record_fd_open_return(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe/dup")
int BPF_KPROBE(u_dup_enter)
{
    __s32 old_fd = (__s32)PT_REGS_PARM1(ctx);
    __s32 stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    remember_dup_fd(old_fd, -1, stack_id);
    return 0;
}

SEC("uretprobe/dup")
int BPF_KRETPROBE(u_dup_exit)
{
    return record_fd_dup_return(PT_REGS_RC(ctx));
}

SEC("uprobe/dup2")
int BPF_KPROBE(u_dup2_enter)
{
    __s32 old_fd = (__s32)PT_REGS_PARM1(ctx);
    __s32 new_fd = (__s32)PT_REGS_PARM2(ctx);
    __s32 stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    remember_dup_fd(old_fd, new_fd, stack_id);
    return 0;
}

SEC("uretprobe/dup2")
int BPF_KRETPROBE(u_dup2_exit)
{
    return record_fd_dup_return(PT_REGS_RC(ctx));
}

SEC("uprobe/dup3")
int BPF_KPROBE(u_dup3_enter)
{
    __s32 old_fd = (__s32)PT_REGS_PARM1(ctx);
    __s32 new_fd = (__s32)PT_REGS_PARM2(ctx);
    __s32 stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    remember_dup_fd(old_fd, new_fd, stack_id);
    return 0;
}

SEC("uretprobe/dup3")
int BPF_KRETPROBE(u_dup3_exit)
{
    return record_fd_dup_return(PT_REGS_RC(ctx));
}

SEC("uprobe/fcntl")
int BPF_KPROBE(u_fcntl_enter)
{
    __s32 old_fd = (__s32)PT_REGS_PARM1(ctx);
    int cmd = (int)PT_REGS_PARM2(ctx);
    // Linux values: F_DUPFD=0, F_DUPFD_CLOEXEC=1030.
    if (cmd != 0 && cmd != 1030)
        return 0;
    __s32 min_fd = (__s32)PT_REGS_PARM3(ctx);
    __s32 stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    remember_dup_fd(old_fd, min_fd, stack_id);
    return 0;
}

SEC("uretprobe/fcntl")
int BPF_KRETPROBE(u_fcntl_exit)
{
    return record_fd_dup_return(PT_REGS_RC(ctx));
}

SEC("uprobe/close")
int BPF_KPROBE(u_close_enter)
{
    __s32 fd = (__s32)PT_REGS_PARM1(ctx);
    __s32 stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    remember_close_fd(fd, stack_id);
    return 0;
}

SEC("uretprobe/close")
int BPF_KRETPROBE(u_close_exit)
{
    return record_fd_close_return(ctx, PT_REGS_RC(ctx));
}

SEC("uprobe/__close_nocancel")
int BPF_KPROBE(u_close_nocancel_enter)
{
    __s32 fd = (__s32)PT_REGS_PARM1(ctx);
    __s32 stack_id = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    remember_close_fd(fd, stack_id);
    return 0;
}

SEC("uretprobe/__close_nocancel")
int BPF_KRETPROBE(u_close_nocancel_exit)
{
    return record_fd_close_return(ctx, PT_REGS_RC(ctx));
}
