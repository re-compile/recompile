# --- runtime/bpf/Makefile ---
#
# Builds BPF objects for re:compile's uprobe-based memory tracking.
# vmlinux.h is auto-generated on first build using bpftool or a minimal fallback.

# Detect LLVM toolchain (prefer system clang on Linux, Homebrew on macOS)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LLVM_PREFIX ?= /opt/homebrew/opt/llvm
  CLANG       ?= $(LLVM_PREFIX)/bin/clang
  OBJDUMP     ?= $(LLVM_PREFIX)/bin/llvm-objdump
  TARGET_ARCH ?= arm64
else
  CLANG       ?= clang
  OBJDUMP     ?= llvm-objdump
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

BPF_SRCS := copy_checker.bpf.c heap_tracker.bpf.c sentinel_extra.bpf.c
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all clean clang-version check-btf vmlinux-regen vmlinux-minimal help

all: $(BPF_OBJS)

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Auto-generate vmlinux.h if it doesn't exist
# Tries bpftool first, falls back to minimal inline header for uprobe-only programs
vmlinux.h:
	@echo "Generating vmlinux.h..."
	@if [ -f /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null 2>&1; then \
	  echo "Using bpftool to generate from kernel BTF..."; \
	  bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
	  echo "bpftool or BTF not available, generating minimal vmlinux.h for uprobes..."; \
	  $(MAKE) vmlinux-minimal; \
	fi
	@echo "vmlinux.h generated successfully"

# Generate minimal vmlinux.h (sufficient for uprobe-based BPF programs)
vmlinux-minimal:
	@echo '/* Minimal vmlinux.h for uprobe-based BPF programs */' > vmlinux.h
	@echo '#ifndef __VMLINUX_H__' >> vmlinux.h
	@echo '#define __VMLINUX_H__' >> vmlinux.h
	@echo '' >> vmlinux.h
	@echo '#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)' >> vmlinux.h
	@echo '' >> vmlinux.h
	@echo 'typedef unsigned char __u8;' >> vmlinux.h
	@echo 'typedef short unsigned int __u16;' >> vmlinux.h
	@echo 'typedef unsigned int __u32;' >> vmlinux.h
	@echo 'typedef unsigned long long __u64;' >> vmlinux.h
	@echo 'typedef signed char __s8;' >> vmlinux.h
	@echo 'typedef short int __s16;' >> vmlinux.h
	@echo 'typedef int __s32;' >> vmlinux.h
	@echo 'typedef long long __s64;' >> vmlinux.h
	@echo 'typedef __u8 u8; typedef __u16 u16; typedef __u32 u32; typedef __u64 u64;' >> vmlinux.h
	@echo 'typedef __s8 s8; typedef __s16 s16; typedef __s32 s32; typedef __s64 s64;' >> vmlinux.h
	@echo 'typedef _Bool bool;' >> vmlinux.h
	@echo '#define true 1' >> vmlinux.h
	@echo '#define false 0' >> vmlinux.h
	@echo '' >> vmlinux.h
	@echo '#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)' >> vmlinux.h
	@echo 'struct pt_regs { unsigned long r15,r14,r13,r12,bp,bx,r11,r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss; };' >> vmlinux.h
	@echo '#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)' >> vmlinux.h
	@echo 'struct pt_regs { __u64 regs[31]; __u64 sp; __u64 pc; __u64 pstate; };' >> vmlinux.h
	@echo '#endif' >> vmlinux.h
	@echo '' >> vmlinux.h
	@echo '#pragma clang attribute pop' >> vmlinux.h
	@echo '#endif /* __VMLINUX_H__ */' >> vmlinux.h

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
