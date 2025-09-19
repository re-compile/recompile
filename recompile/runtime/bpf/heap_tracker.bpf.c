#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../shared/re_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, void *); __type(value, struct re_alloc_info); __uint(max_entries, 131072); } allocs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<24); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_STACK_TRACE); __uint(key_size, sizeof(__u32)); __uint(value_size, 127 * sizeof(__u64)); __uint(max_entries, 8192); } ustacks SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __type(key, __u32); __type(value, __u32); __uint(max_entries, 16384); } scratch SEC(".maps");

SEC("uprobe/malloc")
int BPF_KPROBE(re_malloc_enter, size_t size) {
    __u32 tid = bpf_get_current_pid_tgid();
    __u32 s = size;
    bpf_map_update_elem(&scratch, &tid, &s, BPF_ANY);
    return 0;
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(re_malloc_ret) {
    void *ptr = (void *)PT_REGS_RC(ctx);
    __u32 tid = bpf_get_current_pid_tgid();
    __u32 *sp = bpf_map_lookup_elem(&scratch, &tid);
    int sid = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    struct re_alloc_info info = { .size = sp ? *sp : 0, .alloc_stack_id = sid };
    bpf_map_update_elem(&allocs, &ptr, &info, BPF_ANY);
    return 0;
}

SEC("uprobe/free")
int BPF_KPROBE(re_free, void *ptr) {
    int sid = bpf_get_stackid(ctx, &ustacks, BPF_F_USER_STACK);
    struct re_alloc_info *p = bpf_map_lookup_elem(&allocs, &ptr);
    if (!p) {
        // TODO: emit invalid_free event
        return 0;
    }
    // TODO: mark freed and detect double_free
    bpf_map_delete_elem(&allocs, &ptr);
    return 0;
}


