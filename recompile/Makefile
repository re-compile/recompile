.PHONY: all bpf passes agent toolchain examples

all: examples

examples:
	./scripts/build-examples.sh

passes:
	cmake -S llvm-passes -B build/passes && cmake --build build/passes

bpf:
	$(MAKE) -C runtime/bpf all

agent:
	cargo build -p agent

toolchain:

