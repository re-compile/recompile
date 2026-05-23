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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../shared/re_events.h"

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

// Common libc paths for different Linux distributions
static const char *libc_search_paths[] = {
    "/lib/x86_64-linux-gnu/libc.so.6",      // Debian/Ubuntu x86_64
    "/lib64/libc.so.6",                      // RHEL/CentOS/Fedora x86_64
    "/usr/lib/x86_64-linux-gnu/libc.so.6",  // Some Debian variants
    "/usr/lib64/libc.so.6",                  // Some RHEL variants
    "/lib/libc.so.6",                        // Generic
    "/lib/aarch64-linux-gnu/libc.so.6",     // Debian/Ubuntu arm64
    "/usr/lib/aarch64-linux-gnu/libc.so.6", // ARM64 variants
    NULL
};

static const char *libstdcxx_search_paths[] = {
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/usr/lib64/libstdc++.so.6",
    "/lib64/libstdc++.so.6",
    "/usr/lib/aarch64-linux-gnu/libstdc++.so.6",
    "/lib/aarch64-linux-gnu/libstdc++.so.6",
    NULL
};

// Recursive mkdir - creates all parent directories as needed
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

// Detect libc path using ldd on self or by checking common paths
static const char *detect_libc_path(void) {
    // First, check common paths
    for (int i = 0; libc_search_paths[i] != NULL; i++) {
        if (access(libc_search_paths[i], R_OK) == 0) {
            return libc_search_paths[i];
        }
    }

    // Fallback: try to find via /proc/self/maps
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp) {
        static char detected_path[PATH_MAX];
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "libc") && strstr(line, ".so")) {
                // Parse the path from the maps line
                char *path_start = strchr(line, '/');
                if (path_start) {
                    char *path_end = strchr(path_start, '\n');
                    if (path_end) *path_end = '\0';
                    path_end = strchr(path_start, ' ');
                    if (path_end) *path_end = '\0';
                    strncpy(detected_path, path_start, sizeof(detected_path) - 1);
                    detected_path[sizeof(detected_path) - 1] = '\0';
                    fclose(fp);
                    return detected_path;
                }
            }
        }
        fclose(fp);
    }

    return NULL;
}

static const char *detect_libstdcxx_path(void) {
    for (int i = 0; libstdcxx_search_paths[i] != NULL; i++) {
        if (access(libstdcxx_search_paths[i], R_OK) == 0) {
            return libstdcxx_search_paths[i];
        }
    }

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp) {
        static char detected_path[PATH_MAX];
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "libstdc++") && strstr(line, ".so")) {
                char *path_start = strchr(line, '/');
                if (path_start) {
                    char *path_end = strchr(path_start, '\n');
                    if (path_end) *path_end = '\0';
                    path_end = strchr(path_start, ' ');
                    if (path_end) *path_end = '\0';
                    strncpy(detected_path, path_start, sizeof(detected_path) - 1);
                    detected_path[sizeof(detected_path) - 1] = '\0';
                    fclose(fp);
                    return detected_path;
                }
            }
        }
        fclose(fp);
    }

    return NULL;
}

static volatile sig_atomic_t stop = 0;
static const char *obj_path = NULL;
static const char *heap_path = NULL;
static const char *libc_path = NULL;  // Detected at runtime or via --libc
static const char *libstdcxx_path = NULL;
static const char *binary_path = NULL;
static const char *sentinel_path = NULL;
static char binary_realpath_buf[PATH_MAX];
static bool binary_realpath_ok = false;
static dev_t binary_dev = 0;
static ino_t binary_ino = 0;
static bool binary_stat_ok = false;
static pid_t target_pid = -1;
static const char *func_filter = NULL;
static const char *out_path = NULL;  // NULL = stdout, or set via --out
static const char *crashpack_dir = NULL;  // NULL = cwd/crashpack, or set via --crashpack
static int out_fd = -1;
static int ustacks_fd = -1;
static int open_fds_fd = -1;
static __u32 self_pid = 0;
static bool symbolize_debug = false;

enum finding_dedupe_kind {
    FINDING_DEDUPE_HEAP_OVERFLOW = 1,
    FINDING_DEDUPE_DOUBLE_FREE = 2,
    FINDING_DEDUPE_INVALID_FREE = 3,
    FINDING_DEDUPE_ALLOCATOR_MISMATCH = 4,
    FINDING_DEDUPE_FD_DOUBLE_CLOSE = 5,
    FINDING_DEDUPE_FD_INVALID_CLOSE = 6,
    FINDING_DEDUPE_FD_LEAK = 7,
};

struct emitted_finding_key {
    __u16 kind;
    __u8 status;
    __u32 pid;
    __u32 site_id;
    __s32 stack_id;
    __u64 addr;
    __u32 len;
    __u32 alloc_size;
};

#define MAX_EMITTED_FINDINGS 256
static struct emitted_finding_key emitted_findings[MAX_EMITTED_FINDINGS];
static int emitted_finding_count = 0;
static int emitted_finding_next = 0;

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
static bool exe_matches_binary(__u32 pid, const char *proc_exe_path);
static void debug_drop(__u32 pid, const char *reason);
static void debug_symbolize(const char *fmt, ...);
static struct emitted_finding_key finding_key_from_event(
    const struct re_sentinel_event *ev,
    enum finding_dedupe_kind kind,
    __u8 status);
static bool finding_already_emitted(const struct emitted_finding_key *key);
static void mark_finding_emitted(const struct emitted_finding_key *key);
static bool heap_overflow_emitted_for_addr(__u32 pid, __u64 addr);
static bool allocator_mismatch_emitted_for_addr(__u32 pid, __u64 addr);
static int collect_call_frames(__u32 pid, __s32 stack_id, struct frame_info *frames, int max_frames);
static struct module_cache *get_module_cache(__u32 pid);
static void build_module_cache(struct module_cache *cache);

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

static bool frame_has_user_source(const struct frame_info *frame)
{
    if (!frame || !frame->has_symbol || !frame->file[0])
        return false;
    return strstr(frame->file, "/usr/") == NULL;
}

static const struct frame_info *choose_primary_frame(
    const struct frame_info *call_primary,
    const struct frame_info *alloc_primary)
{
    if (frame_has_user_source(call_primary))
        return call_primary;
    if (frame_has_user_source(alloc_primary))
        return alloc_primary;
    if (alloc_primary && alloc_primary->has_symbol)
        return alloc_primary;
    if (call_primary && call_primary->has_symbol)
        return call_primary;
    return call_primary ? call_primary : alloc_primary;
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
static void emit_v1_finding(const char *finding_json, const char *output_dir)
{
    // Create crashpack directory if it doesn't exist
    if (mkdir_p(output_dir, 0755) != 0) {
        log_line("Failed to create directory %s: %s", output_dir, strerror(errno));
    }

    // Write to crashpack/findings.json
    char crashpack_findings_path[PATH_MAX];
    snprintf(crashpack_findings_path, sizeof(crashpack_findings_path), "%s/findings.json", output_dir);

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
    snprintf(last_finding_path, sizeof(last_finding_path), "%s/.re/last_finding.json", output_dir);

    // Create .re directory if it doesn't exist
    char re_dir[PATH_MAX];
    snprintf(re_dir, sizeof(re_dir), "%s/.re", output_dir);
    if (mkdir_p(re_dir, 0755) != 0) {
        log_line("Failed to create directory %s: %s", re_dir, strerror(errno));
    }
    
    int last_fd = open(last_finding_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (last_fd >= 0) {
        dprintf(last_fd, "%s\n", finding_json);
        close(last_fd);
        log_line("V1 finding written to %s", last_finding_path);
    } else {
        log_line("Failed to open %s for writing: %s", last_finding_path, strerror(errno));
    }
}

static const char *fd_status_kind(__u8 status)
{
    switch (status) {
    case RE_SENTINEL_FD_DOUBLE_CLOSE:
        return "double_close";
    case RE_SENTINEL_FD_INVALID_CLOSE:
        return "invalid_close";
    case RE_SENTINEL_FD_LEAK:
        return "fd_leak";
    default:
        return "fd_lifecycle";
    }
}

static enum finding_dedupe_kind fd_dedupe_kind(__u8 status)
{
    switch (status) {
    case RE_SENTINEL_FD_DOUBLE_CLOSE:
        return FINDING_DEDUPE_FD_DOUBLE_CLOSE;
    case RE_SENTINEL_FD_INVALID_CLOSE:
        return FINDING_DEDUPE_FD_INVALID_CLOSE;
    case RE_SENTINEL_FD_LEAK:
        return FINDING_DEDUPE_FD_LEAK;
    default:
        return FINDING_DEDUPE_FD_INVALID_CLOSE;
    }
}

static void emit_fd_finding(const struct re_sentinel_event *ev, __u8 status,
    struct frame_info *action_frames, int action_count,
    struct frame_info *open_frames, int open_count)
{
    const struct frame_info *primary_action = select_primary(action_frames, action_count);
    const struct frame_info *primary_open = select_primary(open_frames, open_count);
    const struct frame_info *primary = choose_primary_frame(primary_action, primary_open);
    const char *kind = fd_status_kind(status);

    char action_stack_json[1536];
    char open_stack_json[1536];
    build_stack_json(action_frames, action_count, action_stack_json, sizeof(action_stack_json));
    build_stack_json(open_frames, open_count, open_stack_json, sizeof(open_stack_json));

    const char *location_summary = (primary && primary->summary[0]) ? primary->summary : "unknown location";
    char message[512];
    if (status == RE_SENTINEL_FD_LEAK) {
        snprintf(message, sizeof(message),
                 "fd leak: descriptor %d was opened but not closed before process exit (opened at %s)",
                 ev->fd,
                 location_summary);
    } else if (status == RE_SENTINEL_FD_DOUBLE_CLOSE) {
        snprintf(message, sizeof(message),
                 "double close: descriptor %d was closed again after it was already closed at %s",
                 ev->fd,
                 location_summary);
    } else {
        snprintf(message, sizeof(message),
                 "invalid close: close(%d) failed for an untracked descriptor at %s",
                 ev->fd,
                 location_summary);
    }

    char escaped_message[512];
    json_escape(message, escaped_message, sizeof(escaped_message));

    char fix_hint[512];
    if (status == RE_SENTINEL_FD_LEAK) {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Close descriptor %d on every successful open/acquire path, including error paths",
                 ev->fd);
    } else if (status == RE_SENTINEL_FD_DOUBLE_CLOSE) {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Ensure descriptor %d has a single owner, set it to -1 after close, or guard duplicate cleanup paths",
                 ev->fd);
    } else {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Only close descriptors returned by open/openat/creat and still owned by this code path");
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
             "\"evidence\":{\"api\":\"fd_lifecycle\",\"resource\":{\"type\":\"fd\",\"fd\":%d,"
             "\"operation\":\"%s\",\"return_value\":%d},"
             "\"stacks\":{\"open\":%s,\"action\":%s}},\"fixHints\":[\"%s\"],"
             "\"dataQuality\":{\"eventsDropped\":0}}\n",
             kind,
             (unsigned long long)ev->ts_ns,
             kind,
             escaped_message,
             primary_json,
             ev->fd,
             kind,
             ev->bytes_ret,
             open_stack_json,
             action_stack_json,
             escaped_fix);

    dprintf(out_fd, "%s", finding);

    char v1_finding[4096];
    snprintf(v1_finding, sizeof(v1_finding),
             "{\"schema_version\":\"1.0\",\"id\":\"F-%s-%llu\",\"class\":\"%s\","
             "\"confidence\":\"high\",\"severity\":\"high\",\"timestamp\":%llu,\"pid\":%u,"
             "\"evidence\":{\"resource\":{\"type\":\"fd\",\"fd\":%d,\"operation\":\"%s\","
             "\"return_value\":%d},\"stacks\":{\"open\":%s,\"action\":%s},"
             "\"alloc_site\":\"%s\"},"
             "\"escalation\":{\"tool\":\"valgrind\",\"reason\":\"%s_detected\","
             "\"estimated_cost\":\"medium\",\"cooldown_ms\":5000},\"related\":[]}",
             kind,
             (unsigned long long)ev->ts_ns,
             kind,
             (unsigned long long)ev->ts_ns,
             ev->pid,
             ev->fd,
             kind,
             ev->bytes_ret,
             open_stack_json,
             action_stack_json,
             primary ? primary->file : "unknown",
             kind);

    emit_v1_finding(v1_finding, crashpack_dir ? crashpack_dir : "crashpack");
    log_line("%s: pid=%u fd=%d at %s", kind, ev->pid, ev->fd, location_summary);
}

static const char *heap_write_api_name(const struct re_sentinel_event *ev)
{
    switch (ev->errno_code) {
    case 1:
        return "memcpy";
    case 2:
        return "memmove";
    case 3:
        return "memset";
    case 4:
        return "strcpy";
    case 5:
        return "strncpy";
    default:
        break;
    }

    switch (ev->type) {
    case RE_SENTINEL_TYPE_MEMMOVE:
        return "memmove";
    case RE_SENTINEL_TYPE_MEMSET:
        return "memset";
    case RE_SENTINEL_TYPE_STRCPY:
        return "strcpy";
    case RE_SENTINEL_TYPE_STRNCPY:
        return "strncpy";
    case RE_SENTINEL_TYPE_MEMCPY:
    default:
        return "memcpy";
    }
}

static const char *alloc_family_name(__u8 family)
{
    switch (family) {
    case RE_SENTINEL_ALLOC_MALLOC:
        return "malloc";
    case RE_SENTINEL_ALLOC_NEW:
        return "new";
    case RE_SENTINEL_ALLOC_NEW_ARRAY:
        return "new[]";
    case RE_SENTINEL_ALLOC_UNKNOWN:
    default:
        return "unknown";
    }
}

static const char *dealloc_family_name(__u8 family)
{
    switch (family) {
    case RE_SENTINEL_DEALLOC_FREE:
        return "free";
    case RE_SENTINEL_DEALLOC_DELETE:
        return "delete";
    case RE_SENTINEL_DEALLOC_DELETE_ARRAY:
        return "delete[]";
    case RE_SENTINEL_DEALLOC_UNKNOWN:
    default:
        return "unknown";
    }
}

static void emit_heap_write_finding(const struct re_sentinel_event *ev,
    struct frame_info *call_frames, int call_count,
    struct frame_info *alloc_frames, int alloc_count)
{
    const struct frame_info *primary_call = select_primary(call_frames, call_count);
    const struct frame_info *primary_alloc = select_primary(alloc_frames, alloc_count);
    const struct frame_info *primary = choose_primary_frame(primary_call, primary_alloc);
    const char *api = heap_write_api_name(ev);

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
                 "%s overflow: wrote %llu bytes into 0x%llx (capacity %u) at %s",
                 api,
                 (unsigned long long)ev->len,
                 (unsigned long long)ev->addr,
                 ev->alloc_size,
                 location_summary);
    } else {
        snprintf(message, sizeof(message),
                 "%s overflow suspicion: wrote %llu bytes into 0x%llx (capacity unknown) at %s",
                 api,
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
             "\"evidence\":{\"api\":\"%s\",\"len\":%llu,\"dest_alloc\":{\"ptr\":\"0x%llx\",\"size\":%u},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s}},\"fixHints\":[\"%s\"],\"dataQuality\":{\"eventsDropped\":0}}\n",
             (unsigned long long)ev->ts_ns, severity, escaped_message, primary_json,
             api,
             (unsigned long long)ev->len, (unsigned long long)ev->addr,
             ev->alloc_size, alloc_stack_json, call_stack_json, escaped_fix);

    dprintf(out_fd, "%s", finding);

    // Also emit v1 schema finding
    char v1_finding[4096];
    snprintf(v1_finding, sizeof(v1_finding),
             "{\"schema_version\":\"1.0\",\"id\":\"F-heap-overflow-%llu\",\"class\":\"heap_overflow\","
             "\"confidence\":\"high\",\"severity\":\"%s\",\"timestamp\":%llu,\"pid\":%u,"
             "\"evidence\":{\"memory\":{\"ptr\":%llu,\"size\":%u,\"alloc_size\":%u,\"operation\":\"%s\"},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s},\"alloc_site\":\"%s\"},"
             "\"escalation\":{\"tool\":\"asan\",\"reason\":\"len>alloc_size\",\"estimated_cost\":\"low\",\"cooldown_ms\":10000},"
             "\"related\":[]}",
             (unsigned long long)ev->ts_ns, severity, (unsigned long long)ev->ts_ns, ev->pid,
             (unsigned long long)ev->addr, ev->len, ev->alloc_size,
             api,
             alloc_stack_json, call_stack_json, primary ? primary->file : "unknown");

    emit_v1_finding(v1_finding, crashpack_dir ? crashpack_dir : "crashpack");

    const char *top = (primary_call && primary_call->summary[0]) ? primary_call->summary : location_summary;
    log_line("heap overflow: api=%s pid=%u len=%u dst_size=%u dst=0x%llx at %s",
             api, ev->pid, ev->len, ev->alloc_size,
             (unsigned long long)ev->addr, top);
}

static void emit_free_finding(const struct re_sentinel_event *ev, __u8 status,
    struct frame_info *free_frames, int free_count,
    struct frame_info *alloc_frames, int alloc_count)
{
    const struct frame_info *primary_call = select_primary(free_frames, free_count);
    const struct frame_info *primary_alloc = select_primary(alloc_frames, alloc_count);
    const struct frame_info *primary = choose_primary_frame(primary_call, primary_alloc);

    const char *kind = "invalid_free";
    if (status == RE_SENTINEL_FREE_DOUBLE)
        kind = "double_free";
    else if (status == RE_SENTINEL_FREE_MISMATCH)
        kind = "allocator_mismatch";
    const char *alloc_family = alloc_family_name((__u8)ev->len);
    const char *dealloc_family = dealloc_family_name((__u8)ev->bytes_ret);

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
    } else if (status == RE_SENTINEL_FREE_MISMATCH) {
        snprintf(message, sizeof(message),
                 "allocator mismatch: pointer 0x%llx allocated by %s was released with %s at %s",
                 (unsigned long long)ev->addr,
                 alloc_family,
                 dealloc_family,
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
    } else if (status == RE_SENTINEL_FREE_MISMATCH) {
        snprintf(fix_hint, sizeof(fix_hint),
                 "Release pointers with the matching allocator family: %s allocations must use the matching deallocator, not %s",
                 alloc_family,
                 dealloc_family);
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
             "\"evidence\":{\"api\":\"%s\",\"memory\":{\"ptr\":\"0x%llx\",\"size\":%u,"
             "\"alloc_family\":\"%s\",\"dealloc_family\":\"%s\"},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s}},\"fixHints\":[\"%s\"],\"dataQuality\":{\"eventsDropped\":0}}\n",
             kind,
             (unsigned long long)ev->ts_ns,
             kind,
             escaped_message,
             primary_json,
             dealloc_family,
             (unsigned long long)ev->addr,
             ev->alloc_size,
             alloc_family,
             dealloc_family,
             alloc_stack_json,
             free_stack_json,
             escaped_fix);

    dprintf(out_fd, "%s", finding);

    // Also emit v1 schema finding
    char v1_finding[4096];
    const char *v1_class = kind;
    const char *v1_confidence = (status == RE_SENTINEL_FREE_DOUBLE) ? "certain" : "high";
    const char *v1_severity = (status == RE_SENTINEL_FREE_DOUBLE) ? "critical" : "high";
    
    snprintf(v1_finding, sizeof(v1_finding),
             "{\"schema_version\":\"1.0\",\"id\":\"F-%s-%llu\",\"class\":\"%s\","
             "\"confidence\":\"%s\",\"severity\":\"%s\",\"timestamp\":%llu,\"pid\":%u,"
             "\"evidence\":{\"memory\":{\"ptr\":%llu,\"size\":%u,\"alloc_size\":%u,\"operation\":\"%s\","
             "\"alloc_family\":\"%s\",\"dealloc_family\":\"%s\"},"
             "\"stacks\":{\"alloc\":%s,\"call\":%s},\"alloc_site\":\"%s\"},"
             "\"escalation\":{\"tool\":\"asan\",\"reason\":\"%s_detected\",\"estimated_cost\":\"low\",\"cooldown_ms\":%d},"
             "\"related\":[]}",
             kind, (unsigned long long)ev->ts_ns, v1_class, v1_confidence, v1_severity,
             (unsigned long long)ev->ts_ns, ev->pid,
             (unsigned long long)ev->addr, ev->alloc_size, ev->alloc_size,
             dealloc_family,
             alloc_family,
             dealloc_family,
             alloc_stack_json, free_stack_json, primary ? primary->file : "unknown",
             v1_class, (status == RE_SENTINEL_FREE_DOUBLE) ? 0 : 5000);

    emit_v1_finding(v1_finding, crashpack_dir ? crashpack_dir : "crashpack");

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
    case RE_SENTINEL_TYPE_MEMCPY:
    case RE_SENTINEL_TYPE_MEMMOVE:
    case RE_SENTINEL_TYPE_MEMSET:
    case RE_SENTINEL_TYPE_STRCPY:
    case RE_SENTINEL_TYPE_STRNCPY: {
        // Treat heap overflow as a tracked-allocation signal only. Unknown
        // destination capacity produces too many libc-internal false positives
        // in the current native pipeline.
        if (ev.alloc_size == 0)
            return 0;

        if (ev.len <= ev.alloc_size)
            return 0;

        struct emitted_finding_key key = finding_key_from_event(
            &ev,
            FINDING_DEDUPE_HEAP_OVERFLOW,
            RE_SENTINEL_FREE_OK);
        if (finding_already_emitted(&key))
            return 0;

        __s32 alloc_sid = -1;
        if (ev.site_id)
            alloc_sid = (__s32)ev.site_id - 1;

        struct frame_info call_frames[MAX_CALL_FRAMES];
        struct frame_info alloc_frames[MAX_CALL_FRAMES];
        int call_count = collect_call_frames(ev.pid, ev.stack_id, call_frames, MAX_CALL_FRAMES);
        int alloc_count = collect_call_frames(ev.pid, alloc_sid, alloc_frames, MAX_CALL_FRAMES);

        mark_finding_emitted(&key);
        last_drop_reason[0] = '\0';
        emit_heap_write_finding(&ev, call_frames, call_count, alloc_frames, alloc_count);
        break;
    }
    case RE_SENTINEL_TYPE_FREE: {
        __u8 status = (ev.errno_code >= 0 && ev.errno_code <= RE_SENTINEL_FREE_MISMATCH)
                        ? (__u8)ev.errno_code : RE_SENTINEL_FREE_OK;
        if (status == RE_SENTINEL_FREE_OK)
            return 0;

        // Once we have already reported a heap overflow on this exact
        // allocation, a later invalid free is usually a secondary symptom of
        // the same corruption rather than an independent root cause.
        if (status == RE_SENTINEL_FREE_INVALID && heap_overflow_emitted_for_addr(ev.pid, ev.addr))
            return 0;
        if (status == RE_SENTINEL_FREE_DOUBLE && allocator_mismatch_emitted_for_addr(ev.pid, ev.addr))
            return 0;
        // libstdc++ delete operators release storage via libc free after the
        // logical delete event. Treat that free as allocator internals, not a
        // user-visible double-free.
        if (status == RE_SENTINEL_FREE_DOUBLE
            && ev.bytes_ret == RE_SENTINEL_DEALLOC_FREE
            && (ev.len == RE_SENTINEL_ALLOC_NEW || ev.len == RE_SENTINEL_ALLOC_NEW_ARRAY))
            return 0;

        enum finding_dedupe_kind kind = FINDING_DEDUPE_INVALID_FREE;
        if (status == RE_SENTINEL_FREE_DOUBLE)
            kind = FINDING_DEDUPE_DOUBLE_FREE;
        else if (status == RE_SENTINEL_FREE_MISMATCH)
            kind = FINDING_DEDUPE_ALLOCATOR_MISMATCH;
        struct emitted_finding_key key = finding_key_from_event(&ev, kind, status);
        if (finding_already_emitted(&key))
            return 0;

        __s32 alloc_sid = -1;
        if (ev.site_id)
            alloc_sid = (__s32)ev.site_id - 1;

        struct frame_info free_frames[MAX_CALL_FRAMES];
        struct frame_info alloc_frames[MAX_CALL_FRAMES];
        int free_count = collect_call_frames(ev.pid, ev.stack_id, free_frames, MAX_CALL_FRAMES);
        int alloc_count = collect_call_frames(ev.pid, alloc_sid, alloc_frames, MAX_CALL_FRAMES);

        mark_finding_emitted(&key);
        emit_free_finding(&ev, status, free_frames, free_count, alloc_frames, alloc_count);
        break;
    }
    case RE_SENTINEL_TYPE_FD_CLOSE: {
        __u8 status = (ev.errno_code >= RE_SENTINEL_FD_DOUBLE_CLOSE
            && ev.errno_code <= RE_SENTINEL_FD_LEAK)
            ? (__u8)ev.errno_code : RE_SENTINEL_FD_OK;
        if (status == RE_SENTINEL_FD_OK)
            return 0;

        struct emitted_finding_key key = finding_key_from_event(&ev, fd_dedupe_kind(status), status);
        if (finding_already_emitted(&key))
            return 0;

        __s32 open_sid = -1;
        if (ev.site_id)
            open_sid = (__s32)ev.site_id - 1;

        struct frame_info action_frames[MAX_CALL_FRAMES];
        struct frame_info open_frames[MAX_CALL_FRAMES];
        int action_count = collect_call_frames(ev.pid, ev.stack_id, action_frames, MAX_CALL_FRAMES);
        int open_count = collect_call_frames(ev.pid, open_sid, open_frames, MAX_CALL_FRAMES);

        mark_finding_emitted(&key);
        emit_fd_finding(&ev, status, action_frames, action_count, open_frames, open_count);
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

static const char *preferred_symbol_aliases(const char *symbol, int idx)
{
    if (strcmp(symbol, "memcpy") == 0) {
        static const char *aliases[] = {
            "memcpy@GLIBC_2.17",
            "memcpy@GLIBC_2.2.5",
            "memcpy",
            "__memcpy",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "memmove") == 0) {
        static const char *aliases[] = {
            "memmove@GLIBC_2.17",
            "memmove@GLIBC_2.2.5",
            "memmove",
            "__memmove",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "memset") == 0) {
        static const char *aliases[] = {
            "memset@GLIBC_2.17",
            "memset@GLIBC_2.2.5",
            "memset",
            "__memset",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "strcpy") == 0) {
        static const char *aliases[] = {
            "strcpy@GLIBC_2.17",
            "strcpy@GLIBC_2.2.5",
            "strcpy",
            "__strcpy",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "strncpy") == 0) {
        static const char *aliases[] = {
            "strncpy@GLIBC_2.17",
            "strncpy@GLIBC_2.2.5",
            "strncpy",
            "__strncpy",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "malloc") == 0) {
        static const char *aliases[] = {
            "malloc",
            "__libc_malloc",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "calloc") == 0) {
        static const char *aliases[] = {
            "calloc",
            "__libc_calloc",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "realloc") == 0) {
        static const char *aliases[] = {
            "realloc",
            "__libc_realloc",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "posix_memalign") == 0) {
        static const char *aliases[] = {
            "posix_memalign",
            "__posix_memalign",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "aligned_alloc") == 0) {
        static const char *aliases[] = {
            "aligned_alloc",
            "__libc_aligned_alloc",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "strdup") == 0) {
        static const char *aliases[] = {
            "strdup",
            "__strdup",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "free") == 0) {
        static const char *aliases[] = {
            "free",
            "__libc_free",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "open") == 0) {
        static const char *aliases[] = {
            "open",
            "__open",
            "__libc_open",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "open64") == 0) {
        static const char *aliases[] = {
            "open64",
            "__open64",
            "__libc_open64",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "openat") == 0) {
        static const char *aliases[] = {
            "openat",
            "__openat",
            "__libc_openat",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "openat64") == 0) {
        static const char *aliases[] = {
            "openat64",
            "__openat64",
            "__libc_openat64",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "creat") == 0) {
        static const char *aliases[] = {
            "creat",
            "__creat",
            "__libc_creat",
            NULL,
        };
        return aliases[idx];
    }

    if (strcmp(symbol, "close") == 0) {
        static const char *aliases[] = {
            "close",
            "__close",
            "__libc_close",
            NULL,
        };
        return aliases[idx];
    }

    if (idx == 0)
        return symbol;
    return NULL;
}

static bool is_cxx_operator_symbol(const char *symbol)
{
    return symbol
        && (strcmp(symbol, "_Znwm") == 0
            || strcmp(symbol, "_Znam") == 0
            || strcmp(symbol, "_ZdlPv") == 0
            || strcmp(symbol, "_ZdlPvm") == 0
            || strcmp(symbol, "_ZdaPv") == 0
            || strcmp(symbol, "_ZdaPvm") == 0);
}

static struct bpf_link *attach_uprobe_by_name(const struct bpf_program *prog, bool retprobe,
    int attach_pid, const char *binary_path, const char *symbol, char *impl_out, size_t impl_sz)
{
    for (int i = 0; ; ++i) {
        const char *candidate = preferred_symbol_aliases(symbol, i);
        if (!candidate)
            break;

        struct bpf_uprobe_opts opts = {};
        opts.sz = sizeof(opts);
        opts.retprobe = retprobe;
        opts.func_name = candidate;

        struct bpf_link *link =
            bpf_program__attach_uprobe_opts(prog, attach_pid, binary_path, 0, &opts);
        if (!link || libbpf_get_error(link))
            continue;

        if (impl_out && impl_sz) {
            strncpy(impl_out, candidate, impl_sz - 1);
            impl_out[impl_sz - 1] = '\0';
        }
        return link;
    }

    if (strcmp(symbol, "memcpy") != 0
        && strcmp(symbol, "memmove") != 0
        && strcmp(symbol, "memset") != 0
        && strcmp(symbol, "strcpy") != 0
        && strcmp(symbol, "strncpy") != 0)
        return NULL;

    // IFUNC-backed libc memory/string routines on aarch64 glibc can fail
    // name-based attachment. Resolve the actual implementation address from
    // the loaded libc and attach by offset as a narrow fallback.
    void *handle = dlopen(binary_path, RTLD_LAZY | RTLD_LOCAL);
    if (!handle)
        return NULL;

    void *addr = dlsym(handle, symbol);
    if (!addr && strncmp(symbol, "__GI_", 5) != 0) {
        char gi_name[128];
        snprintf(gi_name, sizeof(gi_name), "__GI_%s", symbol);
        addr = dlsym(handle, gi_name);
    }
    if (!addr) {
        dlclose(handle);
        return NULL;
    }

    Dl_info info;
    if (dladdr(addr, &info) == 0 || !info.dli_fbase) {
        dlclose(handle);
        return NULL;
    }

    size_t offset = (size_t)((const char *)addr - (const char *)info.dli_fbase);
    struct bpf_link *link = bpf_program__attach_uprobe(prog, retprobe, attach_pid, binary_path, offset);
    if (link && !libbpf_get_error(link) && impl_out && impl_sz) {
        if (info.dli_sname && info.dli_sname[0]) {
            strncpy(impl_out, info.dli_sname, impl_sz - 1);
            impl_out[impl_sz - 1] = '\0';
        } else {
            snprintf(impl_out, impl_sz, "0x%zx", offset);
        }
    } else {
        link = NULL;
    }

    dlclose(handle);
    return link;
}

struct link_vec {
    struct bpf_link *links[32];
    int count;
};

struct module_range {
    __u64 start;
    __u64 end;
    __u64 file_offset;
    char path[PATH_MAX];
};

struct module_cache {
    __u32 pid;
    bool built;
    int count;
    struct module_range ranges[256];
};

static struct module_cache module_caches[MAX_TRACKED_PIDS];

static void snapshot_module_cache(__u32 pid)
{
    struct module_cache *cache = get_module_cache(pid);
    if (!cache)
        return;
    if (!cache->built)
        build_module_cache(cache);
}

static void maybe_snapshot_target_modules(void)
{
    if (target_pid <= 0 || !binary_path)
        return;

    struct module_cache *cache = get_module_cache((__u32)target_pid);
    if (!cache || cache->built)
        return;

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%u/exe", (__u32)target_pid);
    if (exe_matches_binary((__u32)target_pid, link_path)) {
        build_module_cache(cache);
        if (cache->built)
            debug_symbolize("snapshotted modules pid=%u ranges=%d", (__u32)target_pid, cache->count);
    }
}

static bool pid_still_alive(pid_t pid)
{
    if (pid <= 0)
        return false;
    return kill(pid, 0) == 0 || errno == EPERM;
}

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

static void debug_symbolize(const char *fmt, ...)
{
    if (!symbolize_debug)
        return;

    va_list ap;
    va_start(ap, fmt);
    if (out_fd >= 0) {
        dprintf(out_fd, "RE:SYMBOLIZE: ");
        vdprintf(out_fd, fmt, ap);
        dprintf(out_fd, "\n");
    } else {
        fprintf(stderr, "RE:SYMBOLIZE: ");
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    va_end(ap);
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
        bool cxx_operator = is_cxx_operator_symbol(sym);
        const char *attach_path = cxx_operator ? libstdcxx_path : libc_path;
        if (!attach_path && !cxx_operator) {
            log_line("attach path missing for %s", sym);
            return -1;
        }

        if (cxx_operator) {
            bool attached_any = false;

            if (attach_path) {
                char impl[128] = {0};
                struct bpf_link *link =
                    attach_uprobe_by_name(prog, retprobe, -1, attach_path, sym, impl, sizeof(impl));
                if (link && !libbpf_get_error(link)) {
                    if (out_links && out_links->count < (int)(sizeof(out_links->links)/sizeof(out_links->links[0])))
                        out_links->links[out_links->count++] = link;
                    attached_any = true;
                    log_line("attached %s (impl %s)%s [global]", sym, impl[0] ? impl : sym,
                        retprobe ? " [ret]" : "");
                } else {
                    long rc = libbpf_get_error(link);
                    log_line("attach failed for %s in libstdc++: %ld", sym, rc);
                }
            } else {
                log_line("skipping %s libstdc++ attach: libstdc++ not found", sym);
            }

            if (!attached_any) {
                log_line("skipping %s: libstdc++ attachment unavailable", sym);
            }
            continue;
        }

        char impl[128] = {0};
        struct bpf_link *link =
            attach_uprobe_by_name(prog, retprobe, target_pid, attach_path, sym, impl, sizeof(impl));
        if (!link || libbpf_get_error(link)) {
            long rc = libbpf_get_error(link);
            log_line("attach failed for %s%s%s: %ld",
                sym,
                impl[0] ? " via " : "",
                impl[0] ? impl : "",
                rc);
            return -1;
        }

        if (out_links && out_links->count < (int)(sizeof(out_links->links)/sizeof(out_links->links[0]))) {
            out_links->links[out_links->count++] = link;
        }

        log_line("attached %s (impl %s)%s", sym, impl[0] ? impl : sym,
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

static bool exe_matches_binary(__u32 pid, const char *proc_exe_path)
{
    if (!binary_path || !proc_exe_path)
        return false;

    if (binary_stat_ok) {
        struct stat st;
        if (stat(proc_exe_path, &st) == 0) {
            if (st.st_dev == binary_dev && st.st_ino == binary_ino)
                return true;
        }
    }

    char resolved[PATH_MAX];
    ssize_t n = readlink(proc_exe_path, resolved, sizeof(resolved) - 1);
    if (n < 0) {
        debug_drop(pid, "readlink failed (process may have exited)");
        return false;
    }
    if ((size_t)n >= sizeof(resolved) - 1) {
        debug_drop(pid, "readlink truncated");
        return false;
    }
    resolved[n] = '\0';
    return path_equals_binary(resolved);
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

    if (target_pid > 0) {
        if (pid == (__u32)target_pid) {
            entry->allowed = true;
            snapshot_module_cache(pid);
            return true;
        }

        // Docker/native setups can expose a kernel-visible PID in BPF events
        // that differs from the process namespace PID we launched. Treat the
        // configured PID as a fast path, then fall back to binary-path
        // validation before rejecting the event.
        if (binary_path == NULL) {
            entry->allowed = false;
            debug_drop(pid, "pid does not match target");
            return false;
        }
    }

    // No --binary filter: allow all PIDs (except self)
    if (binary_path == NULL) {
        entry->allowed = true;
        return true;
    }

    // Already validated this PID
    if (entry->allowed)
        return true;

    // Try to validate PID against binary path
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%u/exe", pid);
    if (exe_matches_binary(pid, link_path)) {
        entry->allowed = true;
        snapshot_module_cache(pid);
        return true;
    }

    entry->allowed = false;
    debug_drop(pid, "exe does not match target binary");
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
    if (!fp)
        return;

    cache->count = 0;

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
        cache->ranges[cache->count].file_offset = offset;
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
            if (base_out) *base_out = cache->ranges[i].start - cache->ranges[i].file_offset;
            return 1;
        }
    }
    return 0;
}

static struct emitted_finding_key finding_key_from_event(
    const struct re_sentinel_event *ev,
    enum finding_dedupe_kind kind,
    __u8 status)
{
    struct emitted_finding_key key = {
        .kind = (__u16)kind,
        .status = status,
        .pid = ev->pid,
        .site_id = ev->site_id,
        .stack_id = ev->stack_id,
        .addr = ev->addr,
        .len = ev->len,
        .alloc_size = ev->alloc_size,
    };
    return key;
}

static bool finding_keys_equal(const struct emitted_finding_key *a,
    const struct emitted_finding_key *b)
{
    return a->kind == b->kind
        && a->status == b->status
        && a->pid == b->pid
        && a->site_id == b->site_id
        && a->stack_id == b->stack_id
        && a->addr == b->addr
        && a->len == b->len
        && a->alloc_size == b->alloc_size;
}

static bool finding_already_emitted(const struct emitted_finding_key *key)
{
    for (int i = 0; i < emitted_finding_count; ++i) {
        if (finding_keys_equal(&emitted_findings[i], key))
            return true;
    }
    return false;
}

static void mark_finding_emitted(const struct emitted_finding_key *key)
{
    emitted_findings[emitted_finding_next] = *key;
    if (emitted_finding_count < MAX_EMITTED_FINDINGS)
        emitted_finding_count++;
    emitted_finding_next = (emitted_finding_next + 1) % MAX_EMITTED_FINDINGS;
}

static bool heap_overflow_emitted_for_addr(__u32 pid, __u64 addr)
{
    for (int i = 0; i < emitted_finding_count; ++i) {
        if (emitted_findings[i].kind == FINDING_DEDUPE_HEAP_OVERFLOW
            && emitted_findings[i].pid == pid
            && emitted_findings[i].addr == addr)
            return true;
    }
    return false;
}

static bool allocator_mismatch_emitted_for_addr(__u32 pid, __u64 addr)
{
    for (int i = 0; i < emitted_finding_count; ++i) {
        if (emitted_findings[i].kind == FINDING_DEDUPE_ALLOCATOR_MISMATCH
            && emitted_findings[i].pid == pid
            && emitted_findings[i].addr == addr)
            return true;
    }
    return false;
}

static void drain_fd_leaks(void)
{
    if (open_fds_fd < 0)
        return;

    struct re_fd_key prev = {};
    struct re_fd_key key = {};
    void *prev_ptr = NULL;

    while (bpf_map_get_next_key(open_fds_fd, prev_ptr, &key) == 0) {
        prev = key;
        prev_ptr = &prev;

        if (target_pid > 0 && key.pid != (__u32)target_pid)
            continue;
        if (key.fd < 0)
            continue;
        if (!ensure_pid_allowed(key.pid))
            continue;

        struct re_fd_info info = {};
        if (bpf_map_lookup_elem(open_fds_fd, &key, &info) != 0)
            continue;

        struct re_sentinel_event ev = {
            .version = RE_SENTINEL_EVENT_VERSION,
            .type = RE_SENTINEL_TYPE_FD_CLOSE,
            .pid = key.pid,
            .tid = key.pid,
            .site_id = info.open_stack_id >= 0 ? (__u32)(info.open_stack_id + 1) : 0,
            .stack_id = -1,
            .fd = key.fd,
            .bytes_ret = 0,
            .errno_code = RE_SENTINEL_FD_LEAK,
            .seq = 0,
            .ts_ns = info.opened_ts_ns,
            .addr = (__u64)(__u32)key.fd,
        };

        struct emitted_finding_key finding_key =
            finding_key_from_event(&ev, FINDING_DEDUPE_FD_LEAK, RE_SENTINEL_FD_LEAK);
        if (finding_already_emitted(&finding_key))
            continue;

        __s32 open_sid = info.open_stack_id;
        struct frame_info action_frames[MAX_CALL_FRAMES];
        struct frame_info open_frames[MAX_CALL_FRAMES];
        int action_count = 0;
        int open_count = collect_call_frames(key.pid, open_sid, open_frames, MAX_CALL_FRAMES);

        mark_finding_emitted(&finding_key);
        emit_fd_finding(&ev, RE_SENTINEL_FD_LEAK, action_frames, action_count, open_frames, open_count);
    }
}

// Run symbolizer via fork/exec (avoids shell injection)
static FILE *run_symbolizer(const char *module, __u64 offset) {
    int pipefd[2];
    if (pipe(pipefd) == -1)
        return NULL;

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        // Child process
        close(pipefd[0]);  // Close read end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        // Redirect stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        char addr_str[32];
        snprintf(addr_str, sizeof(addr_str), "0x%llx", (unsigned long long)offset);

        // Try llvm-symbolizer first
        execlp("llvm-symbolizer", "llvm-symbolizer",
               "--inlining", "--demangle", "--obj", module, addr_str, NULL);

        // Fallback to addr2line
        execlp("addr2line", "addr2line", "-f", "-C", "-e", module, addr_str, NULL);

        _exit(127);
    }

    // Parent process
    close(pipefd[1]);  // Close write end
    FILE *fp = fdopen(pipefd[0], "r");
    if (!fp) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return NULL;
    }
    return fp;
}

static bool symbolize_address(__u32 pid, __u64 addr, struct frame_info *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    char module[PATH_MAX];
    __u64 base = 0;
    if (!find_module_for_addr(pid, addr, module, sizeof(module), &base)) {
        debug_symbolize("no module pid=%u addr=0x%llx", pid, (unsigned long long)addr);
        out->address = addr;
        snprintf(out->summary, sizeof(out->summary), "0x%llx", (unsigned long long)addr);
        return false;
    }

    out->address = addr;
    out->offset = addr - base;
    strncpy(out->module, module, sizeof(out->module) - 1);

    // Use fork/exec to avoid shell injection with untrusted module paths
    FILE *fp = run_symbolizer(module, out->offset);
    if (!fp) {
        debug_symbolize("spawn failed module=%s offset=0x%llx", module, (unsigned long long)out->offset);
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx", module, (unsigned long long)out->offset);
        return false;
    }

    char func[256] = {0};
    char loc[256] = {0};
    if (!fgets(func, sizeof(func), fp) || !fgets(loc, sizeof(loc), fp)) {
        debug_symbolize("empty output module=%s offset=0x%llx", module, (unsigned long long)out->offset);
        fclose(fp);
        // Reap child process
        while (wait(NULL) > 0);
        snprintf(out->summary, sizeof(out->summary), "%s+0x%llx", module, (unsigned long long)out->offset);
        return false;
    }
    fclose(fp);
    // Reap child process
    while (wait(NULL) > 0);

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

    if (!out->has_symbol) {
        debug_symbolize("unknown symbol module=%s offset=0x%llx func=%s loc=%s",
            module,
            (unsigned long long)out->offset,
            func[0] ? func : "<empty>",
            loc[0] ? loc : "<empty>");
    }

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

static void reset_finding_dedupe_state(void)
{
    memset(emitted_findings, 0, sizeof(emitted_findings));
    emitted_finding_count = 0;
    emitted_finding_next = 0;
}

static int require_dedupe_check(bool condition, const char *message)
{
    if (condition)
        return 0;
    fprintf(stderr, "dedupe self-test failed: %s\n", message);
    return 1;
}

static int run_dedupe_self_test(void)
{
    reset_finding_dedupe_state();

    struct re_sentinel_event overflow = {
        .type = RE_SENTINEL_TYPE_MEMCPY,
        .pid = 42,
        .site_id = 7,
        .stack_id = 11,
        .len = 64,
        .alloc_size = 16,
        .addr = 0x1000,
    };
    struct emitted_finding_key first_overflow = finding_key_from_event(
        &overflow,
        FINDING_DEDUPE_HEAP_OVERFLOW,
        RE_SENTINEL_FREE_OK);

    if (require_dedupe_check(!finding_already_emitted(&first_overflow),
            "new heap overflow key should not be suppressed"))
        return 1;
    mark_finding_emitted(&first_overflow);
    if (require_dedupe_check(finding_already_emitted(&first_overflow),
            "identical heap overflow key should be suppressed"))
        return 1;
    if (require_dedupe_check(heap_overflow_emitted_for_addr(42, 0x1000),
            "heap overflow address should be tracked for secondary suppression"))
        return 1;

    overflow.addr = 0x2000;
    struct emitted_finding_key second_overflow = finding_key_from_event(
        &overflow,
        FINDING_DEDUPE_HEAP_OVERFLOW,
        RE_SENTINEL_FREE_OK);
    if (require_dedupe_check(!finding_already_emitted(&second_overflow),
            "different heap overflow address should remain reportable"))
        return 1;

    struct re_sentinel_event double_free = {
        .type = RE_SENTINEL_TYPE_FREE,
        .pid = 42,
        .site_id = 9,
        .stack_id = 13,
        .addr = 0x3000,
        .errno_code = RE_SENTINEL_FREE_DOUBLE,
    };
    struct emitted_finding_key first_free = finding_key_from_event(
        &double_free,
        FINDING_DEDUPE_DOUBLE_FREE,
        RE_SENTINEL_FREE_DOUBLE);
    mark_finding_emitted(&first_free);
    if (require_dedupe_check(finding_already_emitted(&first_free),
            "identical double free key should be suppressed"))
        return 1;

    double_free.addr = 0x4000;
    struct emitted_finding_key second_free = finding_key_from_event(
        &double_free,
        FINDING_DEDUPE_DOUBLE_FREE,
        RE_SENTINEL_FREE_DOUBLE);
    if (require_dedupe_check(!finding_already_emitted(&second_free),
            "different double free address should remain reportable"))
        return 1;

    fprintf(stderr, "dedupe self-test passed\n");
    return 0;
}

static void usage(const char *argv0){
    fprintf(stderr,
        "usage: %s [--heap <heap_tracker.o>] --obj <copy_checker.o> [--sentinel <sentinel.o>]\n"
        "       [--binary <path>] [--pid <pid>] [--libc <libc.so>] [--func memcpy|memmove|memset|strcpy|strncpy]\n"
        "       [--out <path>] [--crashpack <dir>] [--self-test-dedupe]\n"
        "\n"
        "Options:\n"
        "  --obj <file>       Required: copy_checker BPF object\n"
        "  --heap <file>      Optional: heap_tracker BPF object\n"
        "  --sentinel <file>  Optional: sentinel_extra BPF object\n"
        "  --binary <path>    Filter events to this binary only\n"
        "  --pid <pid>        Attach to one target PID only\n"
        "  --libc <path>      Path to libc.so.6 (auto-detected if not specified)\n"
        "  --func <name>      Filter to specific function (e.g., memcpy, memmove, memset, strcpy, strncpy)\n"
        "  --out <path>       Output file for events (default: stdout)\n"
        "  --crashpack <dir>  Directory for findings (default: ./crashpack)\n"
        "  --self-test-dedupe Run runtime dedupe self-test and exit\n",
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
    bool self_test_dedupe = false;

    for (int i=1;i<argc;i++){
        if (strcmp(argv[i],"--obj")==0 && i+1<argc) obj_path = argv[++i];
        else if (strcmp(argv[i],"--heap")==0 && i+1<argc) heap_path = argv[++i];
        else if (strcmp(argv[i],"--binary")==0 && i+1<argc) binary_path = argv[++i];
        else if (strcmp(argv[i],"--pid")==0 && i+1<argc) target_pid = (pid_t)atoi(argv[++i]);
        else if (strcmp(argv[i],"--libc")==0 && i+1<argc) libc_path = argv[++i];
        else if (strcmp(argv[i],"--func")==0 && i+1<argc) func_filter = argv[++i];
        else if (strcmp(argv[i],"--sentinel")==0 && i+1<argc) sentinel_path = argv[++i];
        else if (strcmp(argv[i],"--out")==0 && i+1<argc) out_path = argv[++i];
        else if (strcmp(argv[i],"--crashpack")==0 && i+1<argc) crashpack_dir = argv[++i];
        else if (!strcmp(argv[i],"--self-test-dedupe")) self_test_dedupe = true;
        else if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) { usage(argv[0]); return 1; }
    }
    if (self_test_dedupe)
        return run_dedupe_self_test();
    if (!obj_path){ usage(argv[0]); return 1; }

    self_pid = (__u32)getpid();
    symbolize_debug = getenv("RE_SYMBOLIZE_DEBUG") != NULL;

    // Setup output: use specified path, or stdout if not specified
    if (out_path) {
        out_fd = open(out_path, O_WRONLY|O_CREAT|O_CLOEXEC, 0644);
        if (out_fd < 0) {
            fprintf(stderr, "Failed to open output file %s: %s\n", out_path, strerror(errno));
            out_fd = STDOUT_FILENO;
        }
    } else {
        out_fd = STDOUT_FILENO;
    }

    // Detect libc path if not specified
    if (!libc_path) {
        libc_path = detect_libc_path();
        if (!libc_path) {
            fprintf(stderr, "Error: Could not detect libc path. Please specify --libc <path>\n");
            return 1;
        }
        log_line("Detected libc at: %s", libc_path);
    }
    libstdcxx_path = detect_libstdcxx_path();
    if (libstdcxx_path) {
        log_line("Detected libstdc++ at: %s", libstdcxx_path);
    } else {
        log_line("libstdc++ not found; C++ allocator probes disabled");
    }

    if (binary_path) {
        if (realpath(binary_path, binary_realpath_buf)) {
            binary_realpath_ok = true;
        } else {
            log_line("warning: realpath failed for %s", binary_path);
        }
        struct stat st;
        if (stat(binary_path, &st) == 0) {
            binary_dev = st.st_dev;
            binary_ino = st.st_ino;
            binary_stat_ok = true;
        } else {
            log_line("warning: stat failed for %s", binary_path);
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

        if (attach_uprobes_for_object(heap_obj, libc_path, &cache, &heap_links, func_filter) != 0) {
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

        struct bpf_map *open_fds_map = bpf_object__find_map_by_name(heap_obj, "open_fds");
        if (open_fds_map) {
            open_fds_fd = bpf_map__fd(open_fds_map);
        } else {
            log_line("heap tracker missing 'open_fds' map");
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
        maybe_snapshot_target_modules();
        if (target_pid > 0) {
            struct module_cache *cache = get_module_cache((__u32)target_pid);
            if (cache && !cache->built && pid_still_alive(target_pid)) {
                usleep(5 * 1000);
                continue;
            }
        }
        if (rb) ring_buffer__poll(rb, 250);
        else    usleep(200*1000);
    }
    if (rb)
        ring_buffer__poll(rb, 0);
    drain_fd_leaks();
    (void)heap_links;
    (void)copy_links;
    (void)sentinel_links;
    return 0;
}
