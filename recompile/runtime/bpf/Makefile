# --- runtime/bpf/Makefile (drop-in) ---
LLVM_PREFIX ?= /opt/homebrew/opt/llvm
CLANG       ?= $(LLVM_PREFIX)/bin/clang
OBJDUMP     ?= $(LLVM_PREFIX)/bin/llvm-objdump

# Where this Makefile lives
BPF_DIR     := $(abspath .)

# Headers we vendor/local-generate:
#   include/            <- your downloaded libbpf headers live here
#   include/uapi        <- (optional) put any UAPI shims here
#   vmlinux.h           <- generated inside this dir
#   ../shared           <- your re_events.h etc.
BPF_INCLUDES := \
  -I$(BPF_DIR) \
  -I$(BPF_DIR)/include \
  -I$(BPF_DIR)/include/uapi \
  -I$(BPF_DIR)/../shared

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_arm64 -O2 -g \
  -Wall -Wno-unknown-attributes -Wno-unused-value -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types \
  -Wno-gnu-variable-sized-type-not-at-end -Wno-incompatible-pointer-types \
  -Wno-unused-function \
  $(BPF_INCLUDES)

BPF_SRCS := copy_checker.bpf.c heap_tracker.bpf.c sentinel_extra.bpf.c
BPF_OBJS := $(BPF_SRCS:.c=.o)

.PHONY: all clean clang-version check-btf
all: $(BPF_OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_OBJS)

clang-version:
	@$(CLANG) --version | head -1

check-btf:
	@test -s $(BPF_DIR)/vmlinux.h && echo "✓ vmlinux.h present" || (echo "✗ vmlinux.h missing" && exit 1)
	@if [ -f copy_checker.bpf.o ]; then \
	  $(OBJDUMP) -h copy_checker.bpf.o | grep -q ' BTF' && echo "✓ BTF sections present in copy_checker.bpf.o" || echo "✗ no BTF sections yet"; \
	else echo "… build objects first"; fi
# --- end ---
