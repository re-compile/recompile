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

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

// ---- must match copy_checker.bpf.c payload layout ----
struct copy_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 dst;
    __u64 src;
    __u64 len;
    __u64 dst_size;   // 0 if unknown
    __s32 call_sid;
    __u8  api;        // 1=memcpy
    __u8  severity;   // 2=warn, 3=error
    __u16 _pad;
};

static volatile sig_atomic_t stop = 0;
static const char *obj_path = NULL;
static const char *heap_path = NULL;
static const char *libc_path = "/usr/lib/aarch64-linux-gnu/libc.so.6";
static const char *binary_path = NULL;
static char binary_realpath_buf[PATH_MAX];
static bool binary_realpath_ok = false;
static const char *func_filter = NULL;
static const char *out_path = "/dev/virtio-ports/re.findings";
static int out_fd = -1;
static int ustacks_fd = -1;
static __u32 self_pid = 0;
static __u32 target_pid = 0;
static bool finding_emitted = false;

#define MAX_TRACKED_PIDS 32
struct pid_entry { __u32 pid; bool allowed; };
static struct pid_entry tracked_pids[MAX_TRACKED_PIDS];
static int tracked_pid_count = 0;
static char last_drop_reason[128];

struct frame_info {
    char function[128];
    char file[PATH_MAX];
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

static void emit_finding(const struct copy_event *e,
    struct frame_info *call_frames, int call_count)
{
    const char *severity = (e->severity >= 3) ? "error" : "warning";

    const struct frame_info *primary = NULL;
    for (int i = 0; i < call_count; ++i) {
        if (!call_frames[i].has_symbol) continue;
        if (primary == NULL) {
            primary = &call_frames[i];
            continue;
        }
        /* prefer non-system frames */
        bool primary_is_system = primary->file[0] && strstr(primary->file, "/usr/") != NULL;
        bool current_is_system = call_frames[i].file[0] && strstr(call_frames[i].file, "/usr/") != NULL;
        if (primary_is_system && !current_is_system)
            primary = &call_frames[i];
    }
    if (!primary && call_count > 0) primary = &call_frames[0];

    char primary_uri[PATH_MAX + 8] = "file://unknown";
    int primary_line = 0;
    int primary_col = 0;
    if (primary && primary->has_symbol && primary->file[0]) {
        snprintf(primary_uri, sizeof(primary_uri), "file://%s", primary->file);
        primary_line = primary->line > 0 ? primary->line - 1 : 0;
        primary_col = primary->column > 0 ? primary->column - 1 : 0;
    }

    char message[256];
    if (e->dst_size)
        snprintf(message, sizeof(message),
            "memcpy overflow: wrote %llu bytes into allocation of %llu bytes at 0x%llx",
            (unsigned long long)e->len,
            (unsigned long long)e->dst_size,
            (unsigned long long)e->dst);
    else
        snprintf(message, sizeof(message),
            "memcpy overflow suspicion: wrote %llu bytes into allocation without tracked size at 0x%llx",
            (unsigned long long)e->len,
            (unsigned long long)e->dst);

    char call_stack_json[1536];
    size_t call_off = 0;
    call_off += snprintf(call_stack_json + call_off, sizeof(call_stack_json) - call_off, "[");
    for (int i = 0; i < call_count && call_off + 4 < sizeof(call_stack_json); ++i) {
        char escaped[512];
        json_escape(call_frames[i].summary, escaped, sizeof(escaped));
        call_off += snprintf(call_stack_json + call_off, sizeof(call_stack_json) - call_off,
            "%s\"%s\"", (i == 0 ? "" : ","), escaped);
    }
    if (call_off + 2 < sizeof(call_stack_json)) {
        call_stack_json[call_off++] = ']';
        call_stack_json[call_off] = '\0';
    } else {
        snprintf(call_stack_json, sizeof(call_stack_json), "[]");
    }

    char escaped_message[512];
    json_escape(message, escaped_message, sizeof(escaped_message));

    char fix_hint[512];
    if (e->dst_size) {
        snprintf(fix_hint, sizeof(fix_hint),
            "Bound copy to <= %llu bytes or grow the destination buffer to >= %llu bytes",
            (unsigned long long)e->dst_size,
            (unsigned long long)e->len);
    } else {
        snprintf(fix_hint, sizeof(fix_hint),
            "Grow the destination allocation to at least %llu bytes or re-run with heap_tracker active to capture allocation size",
            (unsigned long long)e->len);
    }
    char escaped_fix[512];
    json_escape(fix_hint, escaped_fix, sizeof(escaped_fix));

    char primary_json[256];
    snprintf(primary_json, sizeof(primary_json),
        "{\"uri\":\"%s\",\"range\":{\"start\":{\"line\":%d,\"character\":%d},\"end\":{\"line\":%d,\"character\":%d}}}",
        primary_uri, primary_line, primary_col, primary_line, primary_col + 1);

    char finding[4096];
    snprintf(finding, sizeof(finding),
        "RE:FINDING: {\"id\":\"F-heap-overflow-%llu\",\"origin\":\"ebpf\",\"kind\":\"heap_overflow\","
        "\"severity\":\"%s\",\"message\":\"%s\",\"primaryLocation\":%s,"
        "\"evidence\":{\"api\":\"memcpy\",\"len\":%llu,\"dest_alloc\":{\"ptr\":\"0x%llx\",\"size\":%llu},"
        "\"stacks\":{\"call\":%s}},\"fixHints\":[\"%s\"],\"dataQuality\":{\"eventsDropped\":0}}\n",
        (unsigned long long)e->ts_ns, severity, escaped_message, primary_json,
        (unsigned long long)e->len, (unsigned long long)e->dst,
        (unsigned long long)e->dst_size, call_stack_json, escaped_fix);

    dprintf(out_fd, "%s", finding);

    const char *top = (call_count > 0) ? call_frames[0].summary : "<no stack>";
    log_line("heap overflow: pid=%u len=%llu dst_size=%llu dst=0x%llx top=%s",
        e->pid, (unsigned long long)e->len, (unsigned long long)e->dst_size,
        (unsigned long long)e->dst, top);
}

static int on_event(void *ctx, void *data, size_t len){
    (void)ctx;
    if (len < sizeof(struct copy_event))
        return 0;

    struct copy_event ev;
    memcpy(&ev, data, sizeof(ev));

    if (finding_emitted)
        return 0;

    if (!ensure_pid_allowed(ev.pid))
        return 0;

    if (ev.dst_size && ev.len <= ev.dst_size && ev.severity < 3) {
        debug_drop(ev.pid, "len <= dst_size");
        return 0;
    }

    if (already_reported(ev.pid, ev.dst))
        return 0;

    mark_reported(ev.pid, ev.dst);
    last_drop_reason[0] = '\0';

    struct frame_info call_frames[MAX_CALL_FRAMES];
    int call_count = collect_call_frames(ev.pid, ev.call_sid, call_frames, MAX_CALL_FRAMES);

    emit_finding(&ev, call_frames, call_count);
    finding_emitted = true;
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
        size_t off = cache_symbol_offset(cache, libc_path, sym, impl, sizeof(impl));
        if (!off) {
            log_line("resolve failed for %s in %s", sym, libc_path);
            return -1;
        }

        struct bpf_link *link =
            bpf_program__attach_uprobe(prog, retprobe, -1, libc_path, off);
        if (!link || libbpf_get_error(link)) {
            long rc = libbpf_get_error(link);
            log_line("attach failed for %s (impl %s): %ld", sym, impl, rc);
            return -1;
        }

        if (out_links && out_links->count < (int)(sizeof(out_links->links)/sizeof(out_links->links[0]))) {
            out_links->links[out_links->count++] = link;
        }

        log_line("attached %s (impl %s) at 0x%zx%s", sym, impl, off,
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
        snprintf(out->summary, sizeof(out->summary), "0x%llx", (unsigned long long)addr);
        return false;
    }

    __u64 offset = addr - base;
    char cmd[PATH_MAX * 2 + 64];
    snprintf(cmd, sizeof(cmd), "addr2line -f -C -e %s 0x%llx 2>/dev/null", module, (unsigned long long)offset);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx", module, (unsigned long long)offset);
        return false;
    }

    char func[256] = {0};
    char loc[256] = {0};
    if (!fgets(func, sizeof(func), fp) || !fgets(loc, sizeof(loc), fp)) {
        pclose(fp);
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx", module, (unsigned long long)offset);
        return false;
    }
    pclose(fp);

    trim_newline(func);
    trim_newline(loc);

    strncpy(out->function, func, sizeof(out->function) - 1);

    char location_copy[256];
    strncpy(location_copy, loc, sizeof(location_copy) - 1);
    location_copy[sizeof(location_copy) - 1] = '\0';

    char *col_part = strrchr(location_copy, ':');
    if (col_part) {
        *col_part = '\0';
        out->column = atoi(col_part + 1);
    }
    char *line_part = strrchr(location_copy, ':');
    if (line_part) {
        *line_part = '\0';
        out->line = atoi(line_part + 1);
    }

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
            module, (unsigned long long)offset);
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
        "usage: %s [--heap <heap_tracker.o>] --obj <copy_checker.o> [--binary <path>] [--libc <libc.so>] [--func memcpy] [--out <path>]\n",
        argv0);
}

int main(int argc, char **argv){
    struct sym_cache cache = {0};
    struct link_vec heap_links = {0};
    struct link_vec copy_links = {0};
    int shared_allocs_fd = -1;

    for (int i=1;i<argc;i++){
        if (strcmp(argv[i],"--obj")==0 && i+1<argc) obj_path = argv[++i];
        else if (strcmp(argv[i],"--heap")==0 && i+1<argc) heap_path = argv[++i];
        else if (strcmp(argv[i],"--binary")==0 && i+1<argc) binary_path = argv[++i];
        else if (strcmp(argv[i],"--libc")==0 && i+1<argc) libc_path = argv[++i];
        else if (strcmp(argv[i],"--func")==0 && i+1<argc) func_filter = argv[++i];
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

    struct bpf_map *events = bpf_object__find_map_by_name(obj, "events");
    struct ring_buffer *rb = NULL;
    if (events) {
        int mfd = bpf_map__fd(events);
        rb = ring_buffer__new(mfd, on_event, NULL, NULL);
        if (libbpf_get_error(rb)) rb = NULL;
    } else {
        log_line("no 'events' map found");
    }

    struct bpf_map *ustacks_map = bpf_object__find_map_by_name(obj, "ustacks");
    if (ustacks_map) {
        ustacks_fd = bpf_map__fd(ustacks_map);
    } else {
        log_line("warning: no 'ustacks' map found; stacks unavailable");
    }

    if (attach_uprobes_for_object(obj, libc_path, &cache, &copy_links, func_filter) != 0) {
        return 1;
    }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    while (!stop) {
        if (rb) ring_buffer__poll(rb, 250);
        else    usleep(200*1000);
    }
    return 0;
}
