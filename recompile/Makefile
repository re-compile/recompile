.PHONY: all vm bpf passes agent toolchain examples

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
	cargo build -p recc -p rerun -p vm-launcher -p agent

vm:
	./scripts/build-vm.sh

seed:
	./scripts/make-seed.sh


