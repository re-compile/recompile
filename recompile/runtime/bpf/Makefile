# --- runtime/bpf/Makefile ---
#
# Builds BPF objects for re:compile's uprobe-based memory tracking.
# vmlinux.h is auto-generated on first build using bpftool or a minimal fallback.

# Detect the Linux LLVM toolchain used for native BPF builds.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifneq ($(UNAME_S),Linux)
  $(error re:compile BPF builds are Linux-native only; build inside the Linux container or on a Linux host)
endif

CLANG       ?= clang
OBJDUMP     ?= llvm-objdump
# Auto-detect architecture from kernel (critical for Docker on Apple Silicon).
ifeq ($(UNAME_M),aarch64)
  TARGET_ARCH ?= arm64
else ifeq ($(UNAME_M),arm64)
  TARGET_ARCH ?= arm64
else
  TARGET_ARCH ?= x86
endif

BPF_DIR     := $(abspath .)

BPF_INCLUDES := \
  -I$(BPF_DIR) \
  -I$(BPF_DIR)/include \
  -I$(BPF_DIR)/include/uapi \
  -I$(BPF_DIR)/../shared

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -O2 -g \
  -Wall -Wno-unknown-attributes -Wno-unused-value -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types \
  -Wno-gnu-variable-sized-type-not-at-end -Wno-incompatible-pointer-types \
  -Wno-unused-function \
  $(BPF_INCLUDES)

CORE_BPF_SRCS := copy_checker.bpf.c heap_tracker.bpf.c
EXTRA_BPF_SRCS := sentinel_extra.bpf.c
BPF_SRCS := $(CORE_BPF_SRCS) $(EXTRA_BPF_SRCS)
BPF_OBJS := $(BPF_SRCS:.c=.o)
CORE_BPF_OBJS := $(CORE_BPF_SRCS:.c=.o)
EXTRA_BPF_OBJS := $(EXTRA_BPF_SRCS:.c=.o)
SHARED_HEADERS := ../shared/re_events.h
VMLINUX_OUT ?= vmlinux.h

.PHONY: all clean clang-version check-btf vmlinux-regen vmlinux-minimal vmlinux-sync help

all: vmlinux-sync
	@$(MAKE) --no-print-directory $(CORE_BPF_OBJS)
	@if grep -q "Minimal vmlinux.h" vmlinux.h; then \
	  echo "Skipping sentinel_extra.bpf.o (minimal vmlinux.h does not include tracepoint types)"; \
	else \
	  $(MAKE) --no-print-directory $(EXTRA_BPF_OBJS); \
	fi

%.bpf.o: %.bpf.c vmlinux.h $(SHARED_HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Refresh vmlinux.h from the current kernel when possible. This avoids silently
# reusing a stale header generated on a different architecture.
vmlinux-sync:
	@tmp_file=$$(mktemp "$(BPF_DIR)/vmlinux.h.XXXXXX"); \
	if [ -f /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null 2>&1 && \
	   bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$$tmp_file" 2>/dev/null && \
	   grep -q "struct pt_regs" "$$tmp_file"; then \
	  echo "Syncing vmlinux.h from kernel BTF..."; \
	else \
	  echo "bpftool or BTF not available, generating minimal vmlinux.h for uprobes..."; \
	  $(MAKE) --no-print-directory vmlinux-minimal VMLINUX_OUT="$$tmp_file"; \
	fi; \
	if [ ! -f vmlinux.h ] || ! cmp -s "$$tmp_file" vmlinux.h; then \
	  mv "$$tmp_file" vmlinux.h; \
	  echo "vmlinux.h updated"; \
	else \
	  rm -f "$$tmp_file"; \
	  echo "vmlinux.h already current"; \
	fi

vmlinux.h: vmlinux-sync
	@true

# Generate minimal vmlinux.h (sufficient for uprobe-based BPF programs)
vmlinux-minimal:
	@echo '/* Minimal vmlinux.h for uprobe-based BPF programs */' > $(VMLINUX_OUT)
	@echo '#ifndef __RE_MINIMAL_VMLINUX_H__' >> $(VMLINUX_OUT)
	@echo '#define __RE_MINIMAL_VMLINUX_H__' >> $(VMLINUX_OUT)
	@echo '' >> $(VMLINUX_OUT)
	@echo 'typedef unsigned char __u8;' >> $(VMLINUX_OUT)
	@echo 'typedef short unsigned int __u16;' >> $(VMLINUX_OUT)
	@echo 'typedef unsigned int __u32;' >> $(VMLINUX_OUT)
	@echo 'typedef unsigned long long __u64;' >> $(VMLINUX_OUT)
	@echo 'typedef signed char __s8;' >> $(VMLINUX_OUT)
	@echo 'typedef short int __s16;' >> $(VMLINUX_OUT)
	@echo 'typedef int __s32;' >> $(VMLINUX_OUT)
	@echo 'typedef long long __s64;' >> $(VMLINUX_OUT)
	@echo 'typedef __u16 __be16; typedef __u32 __be32; typedef __u64 __be64;' >> $(VMLINUX_OUT)
	@echo 'typedef __u16 __le16; typedef __u32 __le32; typedef __u64 __le64;' >> $(VMLINUX_OUT)
	@echo 'typedef __u32 __wsum;' >> $(VMLINUX_OUT)
	@echo 'typedef __u8 u8; typedef __u16 u16; typedef __u32 u32; typedef __u64 u64;' >> $(VMLINUX_OUT)
	@echo 'typedef __s8 s8; typedef __s16 s16; typedef __s32 s32; typedef __s64 s64;' >> $(VMLINUX_OUT)
	@echo 'typedef _Bool bool;' >> $(VMLINUX_OUT)
	@echo '#define true 1' >> $(VMLINUX_OUT)
	@echo '#define false 0' >> $(VMLINUX_OUT)
	@echo '#define BPF_MAP_TYPE_HASH 1' >> $(VMLINUX_OUT)
	@echo '#define BPF_MAP_TYPE_PERCPU_ARRAY 6' >> $(VMLINUX_OUT)
	@echo '#define BPF_MAP_TYPE_STACK_TRACE 7' >> $(VMLINUX_OUT)
	@echo '#define BPF_MAP_TYPE_LRU_HASH 9' >> $(VMLINUX_OUT)
	@echo '#define BPF_MAP_TYPE_RINGBUF 27' >> $(VMLINUX_OUT)
	@echo '#define BPF_ANY 0' >> $(VMLINUX_OUT)
	@echo '#define BPF_NOEXIST 1' >> $(VMLINUX_OUT)
	@echo '#define BPF_F_USER_STACK (1ULL << 8)' >> $(VMLINUX_OUT)
	@echo '' >> $(VMLINUX_OUT)
	@echo '#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)' >> $(VMLINUX_OUT)
	@echo 'struct pt_regs { unsigned long r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax,rip,cs,eflags,rsp,ss; };' >> $(VMLINUX_OUT)
	@echo '#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)' >> $(VMLINUX_OUT)
	@echo 'struct user_pt_regs { __u64 regs[31]; __u64 sp; __u64 pc; __u64 pstate; };' >> $(VMLINUX_OUT)
	@echo 'struct pt_regs { struct user_pt_regs user_regs; __u64 orig_x0; };' >> $(VMLINUX_OUT)
	@echo '#endif' >> $(VMLINUX_OUT)
	@echo '' >> $(VMLINUX_OUT)
	@echo '#endif /* __RE_MINIMAL_VMLINUX_H__ */' >> $(VMLINUX_OUT)

# Regenerate vmlinux.h from system BTF (requires bpftool + BTF-enabled kernel)
vmlinux-regen:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
	  echo "Error: /sys/kernel/btf/vmlinux not found (kernel may not have BTF enabled)"; \
	  exit 1; \
	fi
	@if ! command -v bpftool >/dev/null 2>&1; then \
	  echo "Error: bpftool not found"; \
	  echo "Install: apt-get install linux-tools-generic (Ubuntu) or dnf install bpftool (Fedora)"; \
	  exit 1; \
	fi
	@echo "Generating vmlinux.h from kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo "Done."

clean:
	rm -f $(BPF_OBJS)

clean-all: clean
	rm -f vmlinux.h

clang-version:
	@$(CLANG) --version | head -1

check-btf:
	@test -s $(BPF_DIR)/vmlinux.h && echo "✓ vmlinux.h present" || echo "✗ vmlinux.h missing (run make)"
	@if [ -f copy_checker.bpf.o ]; then \
	  $(OBJDUMP) -h copy_checker.bpf.o | grep -q ' BTF' && echo "✓ BTF sections present" || echo "✗ no BTF sections"; \
	else echo "… build objects first"; fi

help:
	@echo "BPF Makefile targets:"
	@echo "  all            - Build BPF objects (auto-generates vmlinux.h if needed)"
	@echo "  clean          - Remove built objects"
	@echo "  clean-all      - Remove objects and vmlinux.h"
	@echo "  vmlinux-regen  - Force regenerate vmlinux.h from kernel BTF"
	@echo "  vmlinux-minimal- Generate minimal vmlinux.h (uprobe-only)"
	@echo "  check-btf      - Verify vmlinux.h and BTF sections"
	@echo ""
	@echo "vmlinux.h is auto-generated on first build. For full kernel tracing,"
	@echo "use 'make vmlinux-regen' on a BTF-enabled system."
# --- end ---
