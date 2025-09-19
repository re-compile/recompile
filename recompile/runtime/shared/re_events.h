#pragma once
#include <linux/types.h>

struct re_alloc_info { __u32 size; int alloc_stack_id; };

struct re_alloc_event { __u64 ts; __u32 pid, tid; void *ptr; __u32 size; int stack_id; };
struct re_free_event  { __u64 ts; __u32 pid, tid; void *ptr; int error; int stack_id; };
struct re_copy_event  { __u64 ts; __u32 pid, tid; void *dst, *src; __u64 len; __u32 dst_size; int stack_id_call; int stack_id_alloc; };
struct re_crash_event { __u64 ts; __u32 pid, tid; int sig; void *addr; int stack_id; };


