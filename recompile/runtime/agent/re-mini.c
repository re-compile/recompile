// runtime/agent/re-mini.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../shared/re_events.h"

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

static volatile sig_atomic_t stop = 0;
static const char *obj_path = NULL;
static const char *heap_path = NULL;
static const char *libc_path = "/usr/lib/aarch64-linux-gnu/libc.so.6";
static const char *binary_path = NULL;
static const char *sentinel_path = NULL;
static char binary_realpath_buf[PATH_MAX];
static bool binary_realpath_ok = false;
static const char *func_filter = NULL;
static const char *out_path = "/dev/virtio-ports/re.findings";
static int out_fd = -1;
static int ustacks_fd = -1;
static __u32 self_pid = 0;
static __u32 target_pid = 0;
static bool memcpy_finding_emitted = false;
static unsigned free_finding_mask = 0;

#define MAX_TRACKED_PIDS 32
struct pid_entry { __u32 pid; bool allowed; };
static struct pid_entry tracked_pids[MAX_TRACKED_PIDS];
static int tracked_pid_count = 0;
static char last_drop_reason[128];

struct frame_info {
    char function[128];
    char file[PATH_MAX];
    char module[PATH_MAX];
    __u64 address;
    __u64 offset;
    int line;
    int column;
    bool has_symbol;
    char summary[256];
};

#define MAX_CALL_FRAMES 8

static size_t json_escape(const char *in, char *out, size_t out_sz);
static bool ensure_pid_allowed(__u32 pid);
static void debug_drop(__u32 pid, const char *reason);
static bool already_reported(__u32 pid, __u64 dst);
static void mark_reported(__u32 pid, __u64 dst);
static int collect_call_frames(__u32 pid, __s32 stack_id, struct frame_info *frames, int max_frames);

static const struct frame_info *select_primary(const struct frame_info *frames, int count)
{
    const struct frame_info *primary = NULL;
    for (int i = 0; i < count; ++i) {
        if (!frames[i].has_symbol)
            continue;
        if (!primary) {
            primary = &frames[i];
            continue;
        }
        bool primary_is_system = primary->file[0] && strstr(primary->file, "/usr/") != NULL;
        bool current_is_system = frames[i].file[0] && strstr(frames[i].file, "/usr/") != NULL;
        if (primary_is_system && !current_is_system)
            primary = &frames[i];
    }
    if (!primary && count > 0)
        primary = &frames[0];
    return primary;
}

static void build_stack_json(const struct frame_info *frames, int count, char *out, size_t out_sz)
{
    size_t off = 0;
    if (out_sz == 0) return;
    out[0] = '\0';
    off += snprintf(out + off, out_sz - off, "[");
    for (int i = 0; i < count && off + 4 < out_sz; ++i) {
        const struct frame_info *fr = &frames[i];
        char escaped[512];
        const char *text = fr->summary[0] ? fr->summary : "<unknown>";
        json_escape(text, escaped, sizeof(escaped));
        off += snprintf(out + off, out_sz - off, "%s\"%s\"", (i == 0 ? "" : ","), escaped);
    }
    if (off + 2 < out_sz) {
        out[off++] = ']';
        out[off] = '\0';
    } else if (out_sz > 2) {
        out[out_sz - 2] = ']';
        out[out_sz - 1] = '\0';
    }
}

static void on_sig(int sig){ (void)sig; stop = 1; }

static int libbpf_vprintf(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
  char buf[512];
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  if (n > 0 && out_fd >= 0) dprintf(out_fd, "RE:LIBBPF: %s", buf);
  return n;
}

static void log_line(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (out_fd >= 0) {
        dprintf(out_fd, "RE:AGENT: ");
        vdprintf(out_fd, fmt, ap);
        dprintf(out_fd, "\n");
    } else {
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    va_end(ap);
}

// V1 schema finding emission
static void emit_v1_finding(const char *finding_json, const char *crashpack_dir)
{
    // Create crashpack directory if it doesn't exist
    char mkdir_cmd[PATH_MAX + 32];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", crashpack_dir);
    system(mkdir_cmd);
    
    // Write to crashpack/findings.json
    char crashpack_findings_path[PATH_MAX];
    snprintf(crashpack_findings_path, sizeof(crashpack_findings_path), "%s/findings.json", crashpack_dir);
    
    int findings_fd = open(crashpack_findings_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (findings_fd >= 0) {
        dprintf(findings_fd, "%s\n", finding_json);
        close(findings_fd);
        log_line("V1 finding written to %s", crashpack_findings_path);
    } else {
        log_line("Failed to open %s for writing: %s", crashpack_findings_path, strerror(errno));
    }
    
    // Also write to .re/last_finding.json
    char last_finding_path[PATH_MAX];
    snprintf(last_finding_path, sizeof(last_finding_path), "%s/.re/last_finding.json", crashpack_dir);
    
    // Create .re directory if it doesn't exist
    char re_dir[PATH_MAX];
    snprintf(re_dir, sizeof(re_dir), "%s/.re", crashpack_dir);
    char mkdir_re_cmd[PATH_MAX + 32];
    snprintf(mkdir_re_cmd, sizeof(mkdir_re_cmd), "mkdir -p %s", re_dir);
    system(mkdir_re_cmd);
    
    int last_fd = open(last_finding_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (last_fd >= 0) {
        dprintf(last_fd, "%s\n", finding_json);
        close(last_fd);
        log_line("V1 finding written to %s", last_finding_path);
    } else {
        log_line("Failed to open %s for writing: %s", last_finding_path, strerror(errno));
    }
}

static void emit_memcpy_finding(const struct re_sentinel_event *ev,
    struct frame_info *call_frames, int call_count,
    struct frame_info *alloc_frames, int alloc_count)
{
    const struct frame_info *primary_call = select_primary(call_frames, call_count);
    const struct frame_info *primary_alloc = select_primary(alloc_frames, alloc_count);
    const struct frame_info *primary = primary_call ? primary_call : primary_alloc;

    bool known_cap = ev->alloc_size > 0;
    bool hard_overflow = known_cap && ev->len > ev->alloc_size;
    const char *severity = hard_overflow ? "error" : "warning";

    char call_stack_json[1536];
    char alloc_stack_json[1536];
    build_stack_json(call_frames, call_count, call_stack_json, sizeof(call_stack_json));
    build_stack_json(alloc_frames, alloc_count, alloc_stack_json, sizeof(alloc_stack_json));

    const char *location_summary = (primary && primary->summary[0]) ? primary->summary : "unknown location";
    char message[512];
    if (known_cap) {
        snprintf(message, sizeof(message),
                 "memcpy overflow: copied %llu bytes into 0x%llx (capacity %u) at %s",
                 (unsigned long long)ev->len,
                 (unsigned long long)ev->addr,
                 ev->alloc_size,
                 location_summary);
    } else {
        snprintf(message, sizeof(message),
                 "memcpy overflow suspicion: copied %llu bytes into 0x%llx (capacity unknown) at %s",
                 (unsigned long long)ev->len,
                 (unsigned long long)ev->addr,
                 location_summary);
    }

    char escaped_message[512];
    json_escape(message, escaped_message, sizeof(escaped_message));

    char fix_hint[512];
    if (known_cap) {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Bound copy to <= %u bytes or grow the destination buffer to >= %llu bytes",
                 ev->alloc_size,
                 (unsigned long long)ev->len);
    } else {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Grow the destination allocation to at least %llu bytes or re-run with heap tracking enabled to capture its size",
                 (unsigned long long)ev->len);
    }
    char escaped_fix[512];
    json_escape(fix_hint, escaped_fix, sizeof(escaped_fix));

    char primary_uri[PATH_MAX + 8] = "file://unknown";
    int primary_line = 0;
    int primary_col = 0;
    if (primary && primary->has_symbol && primary->file[0]) {
        snprintf(primary_uri, sizeof(primary_uri), "file://%s", primary->file);
        primary_line = primary->line > 0 ? primary->line - 1 : 0;
        primary_col = primary->column > 0 ? primary->column - 1 : 0;
    }

    char primary_json[256];
    snprintf(primary_json, sizeof(primary_json),
             "{\"uri\":\"%s\",\"range\":{\"start\":{\"line\":%d,\"character\":%d},\"end\":{\"line\":%d,\"character\":%d}}}",
             primary_uri, primary_line, primary_col, primary_line, primary_col + 1);

    char finding[4096];
    snprintf(finding, sizeof(finding),
             "RE:FINDING: {\"id\":\"F-heap-overflow-%llu\",\"origin\":\"ebpf\",\"kind\":\"heap_overflow\","
             "\"severity\":\"%s\",\"message\":\"%s\",\"primaryLocation\":%s,"
             "\"evidence\":{\"api\":\"memcpy\",\"len\":%llu,\"dest_alloc\":{\"ptr\":\"0x%llx\",\"size\":%u},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s}},\"fixHints\":[\"%s\"],\"dataQuality\":{\"eventsDropped\":0}}\n",
             (unsigned long long)ev->ts_ns, severity, escaped_message, primary_json,
             (unsigned long long)ev->len, (unsigned long long)ev->addr,
             ev->alloc_size, alloc_stack_json, call_stack_json, escaped_fix);

    dprintf(out_fd, "%s", finding);

    // Also emit v1 schema finding
    char v1_finding[4096];
    snprintf(v1_finding, sizeof(v1_finding),
             "{\"schema_version\":\"1.0\",\"id\":\"F-heap-overflow-%llu\",\"class\":\"heap_overflow\","
             "\"confidence\":\"high\",\"severity\":\"%s\",\"timestamp\":%llu,\"pid\":%u,"
             "\"evidence\":{\"memory\":{\"ptr\":%llu,\"size\":%u,\"alloc_size\":%u,\"operation\":\"memcpy\"},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s},\"alloc_site\":\"%s\"},"
             "\"escalation\":{\"tool\":\"asan\",\"reason\":\"len>alloc_size\",\"estimated_cost\":\"low\",\"cooldown_ms\":10000},"
             "\"related\":[]}",
             (unsigned long long)ev->ts_ns, severity, (unsigned long long)ev->ts_ns, ev->pid,
             (unsigned long long)ev->addr, ev->len, ev->alloc_size,
             alloc_stack_json, call_stack_json, primary ? primary->file : "unknown");

    emit_v1_finding(v1_finding, "/host/build/crashpack");

    const char *top = (primary_call && primary_call->summary[0]) ? primary_call->summary : location_summary;
    log_line("heap overflow: pid=%u len=%u dst_size=%u dst=0x%llx at %s",
             ev->pid, ev->len, ev->alloc_size,
             (unsigned long long)ev->addr, top);
}

static void emit_free_finding(const struct re_sentinel_event *ev, __u8 status,
    struct frame_info *free_frames, int free_count,
    struct frame_info *alloc_frames, int alloc_count)
{
    const struct frame_info *primary_call = select_primary(free_frames, free_count);
    const struct frame_info *primary_alloc = select_primary(alloc_frames, alloc_count);
    const struct frame_info *primary = primary_call ? primary_call : primary_alloc;

    const char *kind = (status == RE_SENTINEL_FREE_DOUBLE) ? "double_free" : "invalid_free";

    char free_stack_json[1536];
    char alloc_stack_json[1536];
    build_stack_json(free_frames, free_count, free_stack_json, sizeof(free_stack_json));
    build_stack_json(alloc_frames, alloc_count, alloc_stack_json, sizeof(alloc_stack_json));

    const char *location_summary = (primary && primary->summary[0]) ? primary->summary : "unknown location";
    char message[512];
    if (status == RE_SENTINEL_FREE_DOUBLE) {
        snprintf(message, sizeof(message),
                 "double free: free(0x%llx) called again at %s",
                 (unsigned long long)ev->addr,
                 location_summary);
    } else {
        snprintf(message, sizeof(message),
                 "invalid free: pointer 0x%llx was never tracked by the allocator (reported at %s)",
                 (unsigned long long)ev->addr,
                 location_summary);
    }

    char escaped_message[512];
    json_escape(message, escaped_message, sizeof(escaped_message));

    char fix_hint[512];
    if (status == RE_SENTINEL_FREE_DOUBLE) {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Guard pointer 0x%llx so it is freed only once (set to NULL after free or remove duplicate free)",
                 (unsigned long long)ev->addr);
    } else {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Only pass pointers returned by malloc/calloc/realloc to free (0x%llx is not tracked)",
                 (unsigned long long)ev->addr);
    }
    char escaped_fix[512];
    json_escape(fix_hint, escaped_fix, sizeof(escaped_fix));

    char primary_uri[PATH_MAX + 8] = "file://unknown";
    int primary_line = 0;
    int primary_col = 0;
    if (primary && primary->has_symbol && primary->file[0]) {
        snprintf(primary_uri, sizeof(primary_uri), "file://%s", primary->file);
        primary_line = primary->line > 0 ? primary->line - 1 : 0;
        primary_col = primary->column > 0 ? primary->column - 1 : 0;
    }

    char primary_json[256];
    snprintf(primary_json, sizeof(primary_json),
             "{\"uri\":\"%s\",\"range\":{\"start\":{\"line\":%d,\"character\":%d},\"end\":{\"line\":%d,\"character\":%d}}}",
             primary_uri, primary_line, primary_col, primary_line, primary_col + 1);

    char finding[4096];
    snprintf(finding, sizeof(finding),
             "RE:FINDING: {\"id\":\"F-%s-%llu\",\"origin\":\"ebpf\",\"kind\":\"%s\","
             "\"severity\":\"error\",\"message\":\"%s\",\"primaryLocation\":%s,"
             "\"evidence\":{\"api\":\"free\",\"memory\":{\"ptr\":\"0x%llx\",\"size\":%u},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s}},\"fixHints\":[\"%s\"],\"dataQuality\":{\"eventsDropped\":0}}\n",
             kind,
             (unsigned long long)ev->ts_ns,
             kind,
             escaped_message,
             primary_json,
             (unsigned long long)ev->addr,
             ev->alloc_size,
             alloc_stack_json,
             free_stack_json,
             escaped_fix);

    dprintf(out_fd, "%s", finding);

    // Also emit v1 schema finding
    char v1_finding[4096];
    const char *v1_class = (status == RE_SENTINEL_FREE_DOUBLE) ? "double_free" : "invalid_free";
    const char *v1_confidence = (status == RE_SENTINEL_FREE_DOUBLE) ? "certain" : "high";
    const char *v1_severity = (status == RE_SENTINEL_FREE_DOUBLE) ? "critical" : "high";
    
    snprintf(v1_finding, sizeof(v1_finding),
             "{\"schema_version\":\"1.0\",\"id\":\"F-%s-%llu\",\"class\":\"%s\","
             "\"confidence\":\"%s\",\"severity\":\"%s\",\"timestamp\":%llu,\"pid\":%u,"
             "\"evidence\":{\"memory\":{\"ptr\":%llu,\"size\":%u,\"alloc_size\":%u,\"operation\":\"free\"},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s},\"alloc_site\":\"%s\"},"
             "\"escalation\":{\"tool\":\"asan\",\"reason\":\"%s_detected\",\"estimated_cost\":\"low\",\"cooldown_ms\":%d},"
             "\"related\":[]}",
             kind, (unsigned long long)ev->ts_ns, v1_class, v1_confidence, v1_severity,
             (unsigned long long)ev->ts_ns, ev->pid,
             (unsigned long long)ev->addr, ev->alloc_size, ev->alloc_size,
             alloc_stack_json, free_stack_json, primary ? primary->file : "unknown",
             v1_class, (status == RE_SENTINEL_FREE_DOUBLE) ? 0 : 5000);

    emit_v1_finding(v1_finding, "/host/build/crashpack");

    const char *top = (primary_call && primary_call->summary[0]) ? primary_call->summary : location_summary;
    log_line("%s: pid=%u ptr=0x%llx size=%u at %s",
             kind,
             ev->pid,
             (unsigned long long)ev->addr,
             ev->alloc_size,
             top);
}

static int on_sentinel_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct re_sentinel_event))
        return 0;

    struct re_sentinel_event ev;
    memcpy(&ev, data, sizeof(ev));

    if (!ensure_pid_allowed(ev.pid))
        return 0;

    if (ev.drop_count && ev.pid) {
        char buf[64];
        snprintf(buf, sizeof(buf), "drop_count=%u", ev.drop_count);
        debug_drop(ev.pid, buf);
    }

    switch (ev.type) {
    case RE_SENTINEL_TYPE_MEMCPY: {
        if (memcpy_finding_emitted)
            return 0;

        if (ev.alloc_size && ev.len <= ev.alloc_size)
            return 0;

        if (already_reported(ev.pid, ev.addr))
            return 0;

        __s32 alloc_sid = -1;
        if (ev.site_id)
            alloc_sid = (__s32)ev.site_id - 1;

        struct frame_info call_frames[MAX_CALL_FRAMES];
        struct frame_info alloc_frames[MAX_CALL_FRAMES];
        int call_count = collect_call_frames(ev.pid, ev.stack_id, call_frames, MAX_CALL_FRAMES);
        int alloc_count = collect_call_frames(ev.pid, alloc_sid, alloc_frames, MAX_CALL_FRAMES);

        mark_reported(ev.pid, ev.addr);
        last_drop_reason[0] = '\0';
        emit_memcpy_finding(&ev, call_frames, call_count, alloc_frames, alloc_count);
        memcpy_finding_emitted = true;
        break;
    }
    case RE_SENTINEL_TYPE_FREE: {
        __u8 status = (ev.errno_code >= 0 && ev.errno_code <= RE_SENTINEL_FREE_INVALID)
                        ? (__u8)ev.errno_code : RE_SENTINEL_FREE_OK;
        if (status == RE_SENTINEL_FREE_OK)
            return 0;

        unsigned bit = (status <= 30) ? (1u << status) : (1u << 31);
        if (free_finding_mask & bit)
            return 0;
        free_finding_mask |= bit;

        __s32 alloc_sid = -1;
        if (ev.site_id)
            alloc_sid = (__s32)ev.site_id - 1;

        struct frame_info free_frames[MAX_CALL_FRAMES];
        struct frame_info alloc_frames[MAX_CALL_FRAMES];
        int free_count = collect_call_frames(ev.pid, ev.stack_id, free_frames, MAX_CALL_FRAMES);
        int alloc_count = collect_call_frames(ev.pid, alloc_sid, alloc_frames, MAX_CALL_FRAMES);

        emit_free_finding(&ev, status, free_frames, free_count, alloc_frames, alloc_count);
        break;
    }
    default:
        break;
    }

    return 0;
}

// Return symbol offset inside ET_DYN (usable for uprobes)
struct sym_entry { char name[64]; size_t offset; char impl[128]; };
struct sym_cache {
    struct sym_entry entries[32];
    int count;
};

static size_t find_elf_symbol_offset(const char *path, const char *name, char *impl_name, size_t impl_sz) {
    if (elf_version(EV_CURRENT) == EV_NONE) return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e){ close(fd); return 0; }

    size_t shnum=0; if (elf_getshdrnum(e, &shnum) != 0){ elf_end(e); close(fd); return 0; }
    size_t off = 0;
    for (int pass=0; pass<2 && !off; ++pass) {
        for (size_t i=0; i<shnum; ++i) {
            Elf_Scn *scn = elf_getscn(e, i); if (!scn) continue;
            GElf_Shdr sh; if (!gelf_getshdr(scn, &sh)) continue;
            if ((pass==0 && sh.sh_type != SHT_DYNSYM) ||
                (pass==1 && sh.sh_type != SHT_SYMTAB)) continue;
            Elf_Data *d = elf_getdata(scn, NULL); if (!d) continue;
            size_t n = sh.sh_size / sh.sh_entsize;
            for (size_t j=0; j<n; ++j) {
                GElf_Sym s; if (!gelf_getsym(d, j, &s)) continue;
                const char *nm = elf_strptr(e, sh.sh_link, s.st_name);
                if (!nm) continue;
                if (strcmp(nm, name)==0 && GELF_ST_TYPE(s.st_info)==STT_FUNC && s.st_value) {
                    off = (size_t)s.st_value;
                    if (impl_name && impl_sz) {
                        strncpy(impl_name, nm, impl_sz - 1);
                        impl_name[impl_sz - 1] = '\0';
                    }
                    break;
                }
            }
            if (off) break;
        }
    }
    elf_end(e); close(fd); return off;
}

static size_t find_symbol_offset_rtld(const char *path, const char *name, char *impl_name, size_t impl_sz) {
    void *handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 0;

    void *addr = dlsym(handle, name);
    if (!addr && strncmp(name, "__GI_", 5) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "__GI_%s", name);
        addr = dlsym(handle, buf);
    }
    if (!addr) {
        dlclose(handle);
        return 0;
    }

    Dl_info info;
    if (dladdr(addr, &info) == 0 || !info.dli_fbase) {
        dlclose(handle);
        return 0;
    }

    size_t off = (size_t)((const char *)addr - (const char *)info.dli_fbase);
    if (impl_name && impl_sz) {
        if (info.dli_sname && info.dli_sname[0]) {
            strncpy(impl_name, info.dli_sname, impl_sz - 1);
            impl_name[impl_sz - 1] = '\0';
        } else {
            snprintf(impl_name, impl_sz, "<anon@0x%zx>", off);
        }
    }
    dlclose(handle);
    return off;
}

static size_t cache_symbol_offset(struct sym_cache *cache, const char *libc_path,
    const char *symbol, char *impl_out, size_t impl_sz)
{
    for (int i = 0; i < cache->count; ++i) {
        if (strcmp(cache->entries[i].name, symbol) == 0) {
            if (impl_out && impl_sz) {
                strncpy(impl_out, cache->entries[i].impl, impl_sz - 1);
                impl_out[impl_sz - 1] = '\0';
            }
            return cache->entries[i].offset;
        }
    }

    char impl_name[128] = {0};
    size_t off = find_elf_symbol_offset(libc_path, symbol, impl_name, sizeof(impl_name));
    if (!off) {
        off = find_symbol_offset_rtld(libc_path, symbol, impl_name, sizeof(impl_name));
    }
    if (!off) return 0;

    if (cache->count < (int)(sizeof(cache->entries) / sizeof(cache->entries[0]))) {
        struct sym_entry *e = &cache->entries[cache->count++];
        strncpy(e->name, symbol, sizeof(e->name) - 1);
        strncpy(e->impl, impl_name, sizeof(e->impl) - 1);
        e->offset = off;
    }
    if (impl_out && impl_sz) {
        strncpy(impl_out, impl_name, impl_sz - 1);
        impl_out[impl_sz - 1] = '\0';
    }
    return off;
}

struct link_vec {
    struct bpf_link *links[32];
    int count;
};

struct reported_event {
    __u32 pid;
    __u64 dst;
};

#define MAX_REPORTED 64
static struct reported_event reported[MAX_REPORTED];
static int reported_count = 0;

struct module_range {
    __u64 start;
    __u64 end;
    char path[PATH_MAX];
};

struct module_cache {
    __u32 pid;
    bool built;
    int count;
    struct module_range ranges[256];
};

static struct module_cache module_caches[MAX_TRACKED_PIDS];

static void debug_drop(__u32 pid, const char *reason)
{
    if (reason && strcmp(reason, last_drop_reason) == 0)
        return;
    if (reason)
        strncpy(last_drop_reason, reason, sizeof(last_drop_reason) - 1);
    else
        last_drop_reason[0] = '\0';
    log_line("drop pid=%u: %s", pid, reason ? reason : "");
}

static int attach_uprobes_for_object(struct bpf_object *obj, const char *libc_path,
    struct sym_cache *cache, struct link_vec *out_links, const char *filter)
{
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (!sec) continue;

        bool retprobe = false;
        const char *sym = NULL;
        if (strncmp(sec, "tracepoint/", 11) == 0) {
            const char *tp = sec + 11;
            const char *slash = strchr(tp, '/');
            if (!slash) {
                log_line("invalid tracepoint section %s", sec);
                return -1;
            }
            char category[64];
            char name[64];
            size_t cat_len = slash - tp;
            if (cat_len >= sizeof(category)) cat_len = sizeof(category) - 1;
            memcpy(category, tp, cat_len);
            category[cat_len] = '\0';
            const char *tp_name = slash + 1;
            size_t name_len = strlen(tp_name);
            if (name_len >= sizeof(name)) name_len = sizeof(name) - 1;
            memcpy(name, tp_name, name_len);
            name[name_len] = '\0';

            struct bpf_link *link = bpf_program__attach_tracepoint(prog, category, name);
            if (!link || libbpf_get_error(link)) {
                long rc = libbpf_get_error(link);
                log_line("attach tracepoint %s/%s failed: %ld", category, name, rc);
                return -1;
            }
            if (out_links && out_links->count < (int)(sizeof(out_links->links)/sizeof(out_links->links[0])))
                out_links->links[out_links->count++] = link;
            log_line("attached tracepoint %s/%s", category, name);
            continue;
        }

        if (strncmp(sec, "uretprobe/", 10) == 0) {
            retprobe = true;
            sym = sec + 10;
        } else if (strncmp(sec, "uprobe/", 7) == 0) {
            sym = sec + 7;
        } else {
            continue;
        }

        if (!sym || !*sym) continue;
        if (filter && strcmp(filter, sym) != 0) continue;

        char impl[128] = {0};
        char sym_buf[128];
        const char *sym_name = sym;
        size_t off = cache_symbol_offset(cache, libc_path, sym_name, impl, sizeof(impl));
        if (!off && sym_name[0] != '_' && sym_name[1] != '_') {
            snprintf(sym_buf, sizeof(sym_buf), "__%s", sym_name);
            off = cache_symbol_offset(cache, libc_path, sym_buf, impl, sizeof(impl));
            if (off)
                sym_name = sym_buf;
        }
        if (!off) {
            log_line("resolve failed for %s in %s", sym, libc_path);
            return -1;
        }

        struct bpf_link *link =
            bpf_program__attach_uprobe(prog, retprobe, -1, libc_path, off);
        if (!link || libbpf_get_error(link)) {
            long rc = libbpf_get_error(link);
            log_line("attach failed for %s (impl %s): %ld", sym_name, impl, rc);
            return -1;
        }

        if (out_links && out_links->count < (int)(sizeof(out_links->links)/sizeof(out_links->links[0]))) {
            out_links->links[out_links->count++] = link;
        }

        log_line("attached %s (impl %s) at 0x%zx%s", sym_name, impl, off,
            retprobe ? " [ret]" : "");
    }
    return 0;
}

static void trim_newline(char *s)
{
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[--n] = '\0'; }
}

static bool path_equals_binary(const char *path)
{
    if (!binary_path) return true;
    if (!path || !*path) return false;
    if (binary_realpath_ok) {
        if (strcmp(path, binary_realpath_buf) == 0) return true;
        char tmp[PATH_MAX];
        if (realpath(path, tmp) && strcmp(tmp, binary_realpath_buf) == 0) return true;
        return false;
    }
    return strcmp(path, binary_path) == 0;
}

static struct pid_entry *get_pid_entry(__u32 pid)
{
    for (int i = 0; i < tracked_pid_count; ++i) {
        if (tracked_pids[i].pid == pid)
            return &tracked_pids[i];
    }
    if (tracked_pid_count >= MAX_TRACKED_PIDS)
        return NULL;
    tracked_pids[tracked_pid_count].pid = pid;
    tracked_pids[tracked_pid_count].allowed = false;
    return &tracked_pids[tracked_pid_count++];
}

static bool ensure_pid_allowed(__u32 pid)
{
    struct pid_entry *entry = get_pid_entry(pid);
    if (!entry) return false;
    if (pid == self_pid) {
        debug_drop(pid, "self pid");
        entry->allowed = false;
        return false;
    }

    if (target_pid && pid != target_pid)
        return false;

    if (binary_path == NULL) {
        entry->allowed = true;
        if (!target_pid) target_pid = pid;
        return true;
    }
    if (entry->allowed)
        return true;

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%u/exe", pid);
    char resolved[PATH_MAX];
    ssize_t n = readlink(link_path, resolved, sizeof(resolved) - 1);
    if (n <= 0) {
        debug_drop(pid, "readlink failed");
        entry->allowed = false;
        return false;
    }
    resolved[n] = '\0';
    if (path_equals_binary(resolved)) {
        entry->allowed = true;
        if (!target_pid) target_pid = pid;
        return true;
    }
    entry->allowed = false;
    debug_drop(pid, resolved);
    return false;
}

static struct module_cache *get_module_cache(__u32 pid)
{
    for (int i = 0; i < MAX_TRACKED_PIDS; ++i) {
        if (module_caches[i].pid == pid)
            return &module_caches[i];
        if (module_caches[i].pid == 0) {
            module_caches[i].pid = pid;
            module_caches[i].built = false;
            module_caches[i].count = 0;
            return &module_caches[i];
        }
    }
    return NULL;
}

static void build_module_cache(struct module_cache *cache)
{
    if (!cache || cache->built) return;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", cache->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        cache->built = true;
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start = 0, end = 0, offset = 0;
        char perms[5] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        char map_path[PATH_MAX] = {0};
        int scanned = sscanf(line, "%llx-%llx %4s %llx %15s %lu %s",
            &start, &end, perms, &offset, dev, &inode, map_path);
        if (scanned < 6) continue;
        if (cache->count >= (int)(sizeof(cache->ranges)/sizeof(cache->ranges[0]))) continue;
        cache->ranges[cache->count].start = start;
        cache->ranges[cache->count].end = end;
        cache->ranges[cache->count].path[0] = '\0';
        if (scanned == 7) {
            strncpy(cache->ranges[cache->count].path, map_path, sizeof(cache->ranges[cache->count].path) - 1);
        }
        cache->count++;
    }
    fclose(fp);
    cache->built = true;
}

static int find_module_for_addr(__u32 pid, __u64 addr, char *path_out, size_t path_sz, __u64 *base_out)
{
    struct module_cache *cache = get_module_cache(pid);
    if (!cache) return 0;
    if (!cache->built) build_module_cache(cache);
    for (int i = 0; i < cache->count; ++i) {
        if (addr >= cache->ranges[i].start && addr < cache->ranges[i].end) {
            if (path_out && path_sz) {
                const char *p = cache->ranges[i].path[0] ? cache->ranges[i].path : "[anon]";
                strncpy(path_out, p, path_sz - 1);
                path_out[path_sz - 1] = '\0';
            }
            if (base_out) *base_out = cache->ranges[i].start;
            return 1;
        }
    }
    return 0;
}

static bool already_reported(__u32 pid, __u64 dst)
{
    for (int i = 0; i < reported_count; ++i) {
        if (reported[i].pid == pid && reported[i].dst == dst)
            return true;
    }
    return false;
}

static void mark_reported(__u32 pid, __u64 dst)
{
    if (reported_count >= MAX_REPORTED) return;
    reported[reported_count].pid = pid;
    reported[reported_count].dst = dst;
    reported_count++;
}

static bool symbolize_address(__u32 pid, __u64 addr, struct frame_info *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    char module[PATH_MAX];
    __u64 base = 0;
    if (!find_module_for_addr(pid, addr, module, sizeof(module), &base)) {
        out->address = addr;
        snprintf(out->summary, sizeof(out->summary), "0x%llx", (unsigned long long)addr);
        return false;
    }

    out->address = addr;
    out->offset = addr - base;
    strncpy(out->module, module, sizeof(out->module) - 1);

    char cmd[PATH_MAX * 2 + 128];
    // Prefer llvm-symbolizer if available (better demangling and accuracy), fallback to addr2line
    // Both tools print two lines for a single address when requested this way:
    //  1) function name
    //  2) file:path:line[:col] or '??:0:0' on failure
    snprintf(
        cmd,
        sizeof(cmd),
        "(command -v llvm-symbolizer >/dev/null 2>&1 && llvm-symbolizer --inlining --demangle --obj=%s 0x%llx) || addr2line -f -C -e %s 0x%llx 2>/dev/null",
        module,
        (unsigned long long)out->offset,
        module,
        (unsigned long long)out->offset
    );
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx", module, (unsigned long long)out->offset);
        return false;
    }

    char func[256] = {0};
    char loc[256] = {0};
    if (!fgets(func, sizeof(func), fp) || !fgets(loc, sizeof(loc), fp)) {
        pclose(fp);
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx", module, (unsigned long long)out->offset);
        return false;
    }
    pclose(fp);

    trim_newline(func);
    trim_newline(loc);

    strncpy(out->function, func, sizeof(out->function) - 1);

    char location_copy[256];
    strncpy(location_copy, loc, sizeof(location_copy) - 1);
    location_copy[sizeof(location_copy) - 1] = '\0';

    int line = -1;
    int column = -1;
    char *last = strrchr(location_copy, ':');
    if (last) {
        column = atoi(last + 1);
        *last = '\0';
        char *prev = strrchr(location_copy, ':');
        if (prev) {
            line = atoi(prev + 1);
            *prev = '\0';
        } else {
            line = column;
            column = -1;
        }
    }
    out->line = (line > 0) ? line : 0;
    out->column = (column > 0) ? column : 0;

    strncpy(out->file, location_copy, sizeof(out->file) - 1);

    if (out->file[0] == '\0' || strcmp(out->file, "??") == 0)
        out->has_symbol = false;
    else
        out->has_symbol = true;

    if (out->has_symbol) {
        snprintf(out->summary, sizeof(out->summary), "%s (%s:%d)",
            out->function[0] ? out->function : "?", out->file, out->line);
    } else {
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx",
            module, (unsigned long long)out->offset);
    }
    return out->has_symbol;
}

static int collect_call_frames(__u32 pid, __s32 stack_id, struct frame_info *frames, int max_frames)
{
    if (!frames || max_frames <= 0) return 0;
    if (stack_id < 0 || ustacks_fd < 0) return 0;

    __u64 raw[PERF_MAX_STACK_DEPTH] = {0};
    if (bpf_map_lookup_elem(ustacks_fd, &stack_id, raw) != 0)
        return 0;

    int count = 0;
    for (int i = 0; i < PERF_MAX_STACK_DEPTH && count < max_frames; ++i) {
        __u64 addr = raw[i];
        if (!addr) break;
        symbolize_address(pid, addr, &frames[count]);
        count++;
    }
    return count;
}

static size_t json_escape(const char *in, char *out, size_t out_sz)
{
    size_t pos = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && pos + 2 < out_sz; ++p) {
        char c = (char)*p;
        if (c == '"' || c == '\\') {
            if (pos + 2 >= out_sz) break;
            out[pos++] = '\\';
            out[pos++] = c;
        } else if (c == '\n') {
            if (pos + 2 >= out_sz) break;
            out[pos++] = '\\';
            out[pos++] = 'n';
        } else if ((unsigned char)c < 0x20) {
            if (pos + 6 >= out_sz) break;
            snprintf(out + pos, out_sz - pos, "\\u%04x", c);
            pos += 6;
        } else {
            out[pos++] = c;
        }
    }
    if (pos < out_sz) out[pos] = '\0';
    else out[out_sz - 1] = '\0';
    return pos;
}

static void usage(const char *argv0){
    fprintf(stderr,
        "usage: %s [--heap <heap_tracker.o>] --obj <copy_checker.o> [--sentinel <sentinel.o>] [--binary <path>] [--libc <libc.so>] [--func memcpy] [--out <path>]\n",
        argv0);
}

int main(int argc, char **argv){
    struct sym_cache cache = {0};
    struct link_vec heap_links = {0};
    struct link_vec copy_links = {0};
    struct link_vec sentinel_links = {0};
    int shared_allocs_fd = -1;
    int shared_ustacks_fd = -1;
    int shared_events_fd = -1;
    int shared_state_fd = -1;
    struct bpf_object *sentinel_obj = NULL;

    for (int i=1;i<argc;i++){
        if (strcmp(argv[i],"--obj")==0 && i+1<argc) obj_path = argv[++i];
        else if (strcmp(argv[i],"--heap")==0 && i+1<argc) heap_path = argv[++i];
        else if (strcmp(argv[i],"--binary")==0 && i+1<argc) binary_path = argv[++i];
        else if (strcmp(argv[i],"--libc")==0 && i+1<argc) libc_path = argv[++i];
        else if (strcmp(argv[i],"--func")==0 && i+1<argc) func_filter = argv[++i];
        else if (strcmp(argv[i],"--sentinel")==0 && i+1<argc) sentinel_path = argv[++i];
        else if (strcmp(argv[i],"--out")==0 && i+1<argc) out_path = argv[++i];
        else if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) { usage(argv[0]); return 1; }
    }
    if (!obj_path){ usage(argv[0]); return 1; }

    self_pid = ( __u32)getpid();

    out_fd = open(out_path, O_WRONLY|O_CLOEXEC);
    if (out_fd < 0) out_fd = STDERR_FILENO;

    if (binary_path) {
        if (realpath(binary_path, binary_realpath_buf)) {
            binary_realpath_ok = true;
        } else {
            log_line("warning: realpath failed for %s", binary_path);
        }
    }

    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY }; setrlimit(RLIMIT_MEMLOCK, &rl);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_vprintf);

    struct bpf_object *heap_obj = NULL;
    if (heap_path) {
        heap_obj = bpf_object__open_file(heap_path, NULL);
        if (libbpf_get_error(heap_obj)) {
            log_line("heap open failed: %ld", libbpf_get_error(heap_obj));
            return 1;
        }
        int err = bpf_object__load(heap_obj);
        if (err) {
            char msg[256];
            libbpf_strerror(err, msg, sizeof(msg));
            log_line("heap load BPF failed: %d (%s)", err, msg);
            return 1;
        }

        if (attach_uprobes_for_object(heap_obj, libc_path, &cache, &heap_links, NULL) != 0) {
            return 1;
        }

        struct bpf_map *allocs_map = bpf_object__find_map_by_name(heap_obj, "allocs");
        if (allocs_map) {
            shared_allocs_fd = bpf_map__fd(allocs_map);
        } else {
            log_line("heap tracker missing 'allocs' map");
        }

        struct bpf_map *heap_stacks = bpf_object__find_map_by_name(heap_obj, "ustacks");
        if (heap_stacks) {
            shared_ustacks_fd = bpf_map__fd(heap_stacks);
        } else {
            log_line("heap tracker missing 'ustacks' map");
        }

        struct bpf_map *events_map = bpf_object__find_map_by_name(heap_obj, "sentinel_events");
        if (events_map) {
            shared_events_fd = bpf_map__fd(events_map);
        } else {
            log_line("heap tracker missing 'sentinel_events' map");
        }

        struct bpf_map *state_map = bpf_object__find_map_by_name(heap_obj, "sentinel_state");
        if (state_map) {
            shared_state_fd = bpf_map__fd(state_map);
        } else {
            log_line("heap tracker missing 'sentinel_state' map");
        }
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) { log_line("load open failed: %ld", libbpf_get_error(obj)); return 1; }
    if (shared_allocs_fd >= 0) {
        struct bpf_map *allocs_map = bpf_object__find_map_by_name(obj, "allocs");
        if (allocs_map) {
            int rc = bpf_map__reuse_fd(allocs_map, shared_allocs_fd);
            if (rc) {
                log_line("reuse allocs map failed: %d", rc);
            } else {
                log_line("reusing shared allocs map");
            }
        } else {
            log_line("copy checker missing 'allocs' map definition");
        }
    }
    if (shared_ustacks_fd >= 0) {
        struct bpf_map *stacks_map = bpf_object__find_map_by_name(obj, "ustacks");
        if (stacks_map) {
            int rc = bpf_map__reuse_fd(stacks_map, shared_ustacks_fd);
            if (rc) {
                log_line("reuse ustacks map failed: %d", rc);
            }
        }
    }
    if (shared_events_fd >= 0) {
        struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "sentinel_events");
        if (events_map) {
            int rc = bpf_map__reuse_fd(events_map, shared_events_fd);
            if (rc)
                log_line("reuse sentinel_events map failed: %d", rc);
        }
    }
    if (shared_state_fd >= 0) {
        struct bpf_map *state_map = bpf_object__find_map_by_name(obj, "sentinel_state");
        if (state_map) {
            int rc = bpf_map__reuse_fd(state_map, shared_state_fd);
            if (rc)
                log_line("reuse sentinel_state map failed: %d", rc);
        }
    }
    int err = bpf_object__load(obj);
    if (err) {
      char msg[256];
      libbpf_strerror(err, msg, sizeof(msg));
      dprintf(out_fd, "RE:AGENT: load BPF failed: %d (%s)\n", err, msg);
      if (err == -4007) {
        dprintf(out_fd,
          "RE:AGENT: hint: CO-RE relocation failed; mismatch in BTF/relocs or an unsupported feature on 5.15 arm64.\n");
      }
      return 1;
    }

    if (attach_uprobes_for_object(obj, libc_path, &cache, &copy_links, func_filter) != 0) {
        return 1;
    }

    if (sentinel_path) {
        sentinel_obj = bpf_object__open_file(sentinel_path, NULL);
        if (libbpf_get_error(sentinel_obj)) {
            log_line("sentinel open failed: %ld", libbpf_get_error(sentinel_obj));
            return 1;
        }
        if (shared_allocs_fd >= 0) {
            struct bpf_map *allocs_map = bpf_object__find_map_by_name(sentinel_obj, "allocs");
            if (allocs_map)
                bpf_map__reuse_fd(allocs_map, shared_allocs_fd);
        }
        if (shared_ustacks_fd >= 0) {
            struct bpf_map *ustacks_map = bpf_object__find_map_by_name(sentinel_obj, "ustacks");
            if (ustacks_map)
                bpf_map__reuse_fd(ustacks_map, shared_ustacks_fd);
        }
        if (shared_events_fd >= 0) {
            struct bpf_map *events_map = bpf_object__find_map_by_name(sentinel_obj, "sentinel_events");
            if (events_map)
                bpf_map__reuse_fd(events_map, shared_events_fd);
        }
        if (shared_state_fd >= 0) {
            struct bpf_map *state_map = bpf_object__find_map_by_name(sentinel_obj, "sentinel_state");
            if (state_map)
                bpf_map__reuse_fd(state_map, shared_state_fd);
        }
        err = bpf_object__load(sentinel_obj);
        if (err) {
            char msg[256];
            libbpf_strerror(err, msg, sizeof(msg));
            log_line("sentinel load BPF failed: %d (%s)", err, msg);
            return 1;
        }
        if (attach_uprobes_for_object(sentinel_obj, libc_path, &cache, &sentinel_links, NULL) != 0) {
            return 1;
        }
    }

    int rb_fd = -1;
    if (shared_events_fd >= 0) {
        rb_fd = shared_events_fd;
    } else {
        struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "sentinel_events");
        if (events_map)
            rb_fd = bpf_map__fd(events_map);
        else if (sentinel_obj) {
            struct bpf_map *extra_events = bpf_object__find_map_by_name(sentinel_obj, "sentinel_events");
            if (extra_events)
                rb_fd = bpf_map__fd(extra_events);
        }
    }

    struct ring_buffer *rb = NULL;
    if (rb_fd >= 0) {
        rb = ring_buffer__new(rb_fd, on_sentinel_event, NULL, NULL);
        if (libbpf_get_error(rb)) rb = NULL;
    } else {
        log_line("no 'sentinel_events' map found");
    }

    if (shared_ustacks_fd >= 0) {
        ustacks_fd = shared_ustacks_fd;
    } else {
        struct bpf_map *ustacks_map = bpf_object__find_map_by_name(obj, "ustacks");
        if (ustacks_map)
            ustacks_fd = bpf_map__fd(ustacks_map);
        else if (sentinel_obj) {
            struct bpf_map *extra_ustacks = bpf_object__find_map_by_name(sentinel_obj, "ustacks");
            if (extra_ustacks)
                ustacks_fd = bpf_map__fd(extra_ustacks);
        }
        if (ustacks_fd < 0)
            log_line("warning: no 'ustacks' map found; stacks unavailable");
    }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    while (!stop) {
        if (rb) ring_buffer__poll(rb, 250);
        else    usleep(200*1000);
    }
    (void)heap_links;
    (void)copy_links;
    (void)sentinel_links;
    return 0;
}
