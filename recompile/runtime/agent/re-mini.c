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

// ---- must match copy_checker.bpf.c payload layout ----
struct copy_event {
    __u64 ts_ns;
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
static const char *func_filter = NULL;
static const char *out_path = "/dev/virtio-ports/re.findings";
static int out_fd = -1;

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

static void emit_finding(const struct copy_event *e) {
    const char *sev = (e->severity >= 3) ? "error" : "warn";
    dprintf(out_fd,
      "RE:FINDING: {\"id\":\"F-memcpy-%llu\",\"origin\":\"ebpf\",\"kind\":\"memcpy_copy\","
      "\"severity\":\"%s\",\"message\":\"memcpy len=%llu dst_size=%llu\","
      "\"evidence\":{\"api\":\"memcpy\",\"len\":%llu,\"dst_size\":%llu,"
      "\"dst\":\"0x%llx\",\"src\":\"0x%llx\"}}\n",
      (unsigned long long)e->ts_ns, sev,
      (unsigned long long)e->len, (unsigned long long)e->dst_size,
      (unsigned long long)e->len, (unsigned long long)e->dst_size,
      (unsigned long long)e->dst, (unsigned long long)e->src);
}

static int on_event(void *ctx, void *data, size_t len){
    (void)ctx;
    if (len >= sizeof(struct copy_event))
        emit_finding((const struct copy_event*)data);
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

static void usage(const char *argv0){
    fprintf(stderr,
        "usage: %s [--heap <heap_tracker.o>] --obj <copy_checker.o> [--libc <libc.so>] [--func memcpy] [--out <path>]\n",
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
        else if (strcmp(argv[i],"--libc")==0 && i+1<argc) libc_path = argv[++i];
        else if (strcmp(argv[i],"--func")==0 && i+1<argc) func_filter = argv[++i];
        else if (strcmp(argv[i],"--out")==0 && i+1<argc) out_path = argv[++i];
        else if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) { usage(argv[0]); return 1; }
    }
    if (!obj_path){ usage(argv[0]); return 1; }

    out_fd = open(out_path, O_WRONLY|O_CLOEXEC);
    if (out_fd < 0) out_fd = STDERR_FILENO;

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
