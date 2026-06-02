#pragma once

#include <linux/types.h>

/* ----------------------------------------------------------------------
 * Shared runtime data structures for the sentinel pipeline.
 * These types are consumed both by eBPF programs and the userland agent.
 * ---------------------------------------------------------------------- */

/* Versioned sentinel event format */
#define RE_SENTINEL_EVENT_VERSION 1

/* Limits for the small extra key/value payload embedded in each event */
#define RE_SENTINEL_EXTRA_MAX         4
#define RE_SENTINEL_EXTRA_VALUE_MAX   32

/* Flags bitmask (u16) */
#define RE_SENTINEL_FLAG_THROTTLED     (1u << 0)
#define RE_SENTINEL_FLAG_DROPPED_BATCH (1u << 1)
#define RE_SENTINEL_FLAG_KERNEL_SPACE  (1u << 2)

/* Sentinel event type identifiers (u16) */
enum re_sentinel_type {
    RE_SENTINEL_TYPE_MALLOC        = 1,
    RE_SENTINEL_TYPE_FREE          = 2,
    RE_SENTINEL_TYPE_MMAP          = 3,
    RE_SENTINEL_TYPE_MUNMAP        = 4,
    RE_SENTINEL_TYPE_MEMCPY        = 5,
    RE_SENTINEL_TYPE_MEMMOVE       = 6,
    RE_SENTINEL_TYPE_STRCPY        = 7,
    RE_SENTINEL_TYPE_STRLEN        = 8,
    RE_SENTINEL_TYPE_READ          = 9,
    RE_SENTINEL_TYPE_WRITE         = 10,
    RE_SENTINEL_TYPE_SEND          = 11,
    RE_SENTINEL_TYPE_RECV          = 12,
    RE_SENTINEL_TYPE_DUP           = 13,
    RE_SENTINEL_TYPE_PIPE          = 14,
    RE_SENTINEL_TYPE_EPOLL_CTL     = 15,
    RE_SENTINEL_TYPE_INOTIFY_ADD   = 16,
    RE_SENTINEL_TYPE_MEMSET        = 17,
    RE_SENTINEL_TYPE_STRNCPY       = 18,
    RE_SENTINEL_TYPE_LOCK_ACQ      = 20,
    RE_SENTINEL_TYPE_LOCK_REL      = 21,
    RE_SENTINEL_TYPE_FUTEX_WAIT    = 22,
    RE_SENTINEL_TYPE_FUTEX_WAKE    = 23,
    RE_SENTINEL_TYPE_SIGNAL_ENTER  = 30,
    RE_SENTINEL_TYPE_SIGNAL_FAULT  = 31,
    RE_SENTINEL_TYPE_SEGFAULT      = 40,
    RE_SENTINEL_TYPE_MARK_FLUSH    = 50,
    RE_SENTINEL_TYPE_FD_CLOSE      = 60,
};

/* Lock kinds (u8) for concurrency events */
enum re_sentinel_lock_kind {
    RE_SENTINEL_LOCK_NONE       = 0,
    RE_SENTINEL_LOCK_MUTEX      = 1,
    RE_SENTINEL_LOCK_RWLOCK_R   = 2,
    RE_SENTINEL_LOCK_RWLOCK_W   = 3,
    RE_SENTINEL_LOCK_FUTEX      = 4,
    RE_SENTINEL_LOCK_SPIN       = 5,
};

/* Extra payload keys (u8) */
enum re_sentinel_extra_key {
    RE_SENTINEL_EXTRA_MEM_API        = 1, /* u8  */
    RE_SENTINEL_EXTRA_FREE_STATUS    = 2, /* u8  */
    RE_SENTINEL_EXTRA_ALLOC_STACK_ID = 3, /* s32 */
    RE_SENTINEL_EXTRA_SRC_STACK_ID   = 4, /* s32 */
    RE_SENTINEL_EXTRA_REASON_CODE    = 5, /* u32 */
    RE_SENTINEL_EXTRA_USER_RESERVED0 = 240,
};

/* Free status values (stored via EXTRA_FREE_STATUS) */
enum re_sentinel_free_status {
    RE_SENTINEL_FREE_OK      = 0,
    RE_SENTINEL_FREE_DOUBLE  = 1,
    RE_SENTINEL_FREE_INVALID = 2,
    RE_SENTINEL_FREE_MISMATCH = 3,
};

enum re_sentinel_alloc_family {
    RE_SENTINEL_ALLOC_UNKNOWN   = 0,
    RE_SENTINEL_ALLOC_MALLOC    = 1,
    RE_SENTINEL_ALLOC_NEW       = 2,
    RE_SENTINEL_ALLOC_NEW_ARRAY = 3,
};

enum re_sentinel_dealloc_family {
    RE_SENTINEL_DEALLOC_UNKNOWN      = 0,
    RE_SENTINEL_DEALLOC_FREE         = 1,
    RE_SENTINEL_DEALLOC_DELETE       = 2,
    RE_SENTINEL_DEALLOC_DELETE_ARRAY = 3,
};

enum re_sentinel_fd_status {
    RE_SENTINEL_FD_OK           = 0,
    RE_SENTINEL_FD_DOUBLE_CLOSE = 1,
    RE_SENTINEL_FD_INVALID_CLOSE = 2,
    RE_SENTINEL_FD_LEAK         = 3,
};

struct re_sentinel_extra {
    __u8  key;                             /* enum re_sentinel_extra_key */
    __u8  len;                             /* number of valid bytes in data */
    __u8  reserved[6];
    __u8  data[RE_SENTINEL_EXTRA_VALUE_MAX];
};

struct re_sentinel_event {
    __u16 version;        /* RE_SENTINEL_EVENT_VERSION */
    __u16 type;           /* enum re_sentinel_type */
    __u16 flags;          /* RE_SENTINEL_FLAG_* */
    __u16 lock_kind;      /* enum re_sentinel_lock_kind */
    __u32 pid;
    __u32 tid;
    __u32 site_id;
    __s32 stack_id;       /* BPF stack-trace id (-1 if unknown) */
    __u32 stack_fp;       /* Folded stack fingerprint (optional) */
    __u32 lock_site_id;
    __u32 drop_count;     /* events dropped since previous emit for pid */
    __u32 len;            /* bytes requested/read/written */
    __u32 alloc_size;     /* known allocation size */
    __u32 alloc_offset;   /* byte offset from allocation base to addr */
    __s32 fd;             /* file descriptor for I/O; -1 if N/A */
    __s32 bytes_ret;      /* syscall return value */
    __s32 errno_code;     /* errno on failure */
    __u8  extra_count;    /* number of populated extras */
    __u8  reserved[7];
    __u64 seq;            /* monotonic per-PID sequence */
    __u64 ts_ns;          /* timestamp */
    __u64 addr;           /* pointer/lock address */
    __u64 lock_addr;      /* futex/lock address */
    __u64 alloc_base;     /* allocation base for interior heap writes */
    struct re_sentinel_extra extra[RE_SENTINEL_EXTRA_MAX];
};

struct re_sentinel_state {
    __u64 seq;
    __u32 drops;
    __u32 flags;
};

#define RE_SENTINEL_STATE_ARMED (1u << 0)

/* Shared heap allocation metadata */
struct re_alloc_key {
    __u32 pid;
    /* Keep map keys deterministic across BPF programs; implicit padding is key material. */
    __u32 _pad;
    __u64 addr;
};

struct re_alloc_info {
    __u64 size;
    __s32 alloc_stack_id;
    __u8 family;
    __u8 dealloc_family;
    __u8 _pad[2];
};

#define RE_ALLOC_PAGE_SHIFT 12
#define RE_ALLOC_PAGE_SPAN_MAX 64
#define RE_ALLOC_RANGE_SLOTS 4

struct re_alloc_range_key {
    __u32 pid;
    __u32 _pad;
    __u64 page;
};

struct re_alloc_range_info {
    __u64 base;
    __u64 size;
    __s32 alloc_stack_id;
    __u8 family;
    __u8 _pad[3];
};

struct re_alloc_range_bucket {
    struct re_alloc_range_info slots[RE_ALLOC_RANGE_SLOTS];
};

struct re_fd_key {
    __u32 pid;
    __s32 fd;
};

struct re_fd_info {
    __s32 open_stack_id;
    __s32 close_stack_id;
    __s32 origin_stack_id;
    __s32 _pad;
    __u64 opened_ts_ns;
    __u64 closed_ts_ns;
};
