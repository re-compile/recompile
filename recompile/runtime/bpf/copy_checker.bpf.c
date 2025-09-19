#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../shared/re_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, void *); __type(value, struct re_alloc_info); __uint(max_entries, 131072); } allocs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<24); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_STACK_TRACE); __uint(key_size, sizeof(__u32)); __uint(value_size, 127 * sizeof(__u64)); __uint(max_entries, 8192); } ustacks SEC(".maps");

SEC("uprobe/memcpy")
int BPF_KPROBE(re_memcpy, void *dst, const void *src, size_t len) {
    int call_sid = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    __u32 dst_size = 0; int alloc_sid = -1;
    struct re_alloc_info *a = bpf_map_lookup_elem(&allocs, &dst);
    if (a) { dst_size = a->size; alloc_sid = a->alloc_stack_id; }
    if (dst_size && len > dst_size) {
        // TODO: emit re_copy_event
    }
    return 0;
}


