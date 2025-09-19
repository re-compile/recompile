BPF_CLANG ?= clang

UNAME_M := $(shell uname -m)
ifeq ($(BPF_ARCH),)
  ifeq ($(UNAME_M),x86_64)
    BPF_ARCH := x86
  else ifeq ($(UNAME_M),arm64)
    BPF_ARCH := arm64
  else ifeq ($(UNAME_M),aarch64)
    BPF_ARCH := arm64
  else
    BPF_ARCH := x86
  endif
endif

BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH)

SRCS := heap_tracker.bpf.c copy_checker.bpf.c
OBJS := $(SRCS:.c=.o)

ifeq ($(wildcard vmlinux.h),)
all:
	@echo "Skipping BPF build: missing runtime/bpf/vmlinux.h (run 'make vm' to generate from microVM kernel BTF)"
	@true
else
all: $(OBJS)
endif

%.o: %.c ../shared/re_events.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)


