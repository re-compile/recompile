.PHONY: all bpf passes agent agent-test toolchain examples user-samples project-fixtures external-smoke escalation-smoke asan-smoke lsan-smoke ubsan-smoke summarize-smoke replay-smoke observe-smoke project-smoke observe-hit-rate recc-smoke hit-rate phase1 rc phase2 phase4

all: examples

examples:
	./scripts/build-examples.sh

user-samples:
	./scripts/build-user-samples.sh

project-fixtures:
	./scripts/build-project-fixtures.sh

external-smoke:
	./scripts/validate-user-samples.sh

escalation-smoke:
	./scripts/validate-escalation.sh

asan-smoke:
	./scripts/validate-asan.sh

lsan-smoke:
	./scripts/validate-lsan.sh

ubsan-smoke:
	./scripts/validate-ubsan.sh

summarize-smoke:
	./scripts/validate-summarize.sh

replay-smoke:
	./scripts/validate-replay.sh

observe-smoke:
	./scripts/validate-observe.sh

project-smoke:
	./scripts/validate-project-fixtures.sh

observe-hit-rate:
	./scripts/validate-observe-hit-rate.sh

recc-smoke:
	./scripts/validate-recc.sh

hit-rate:
	./scripts/validate-hit-rate.sh

phase1:
	./scripts/validate-phase1.sh

rc:
	./scripts/validate-rc.sh

phase2:
	$(MAKE) agent-test
	./scripts/validate-rc.sh
	./scripts/validate-escalation.sh
	./scripts/validate-asan.sh
	./scripts/validate-lsan.sh
	./scripts/validate-ubsan.sh
	./scripts/validate-summarize.sh
	./scripts/validate-replay.sh

phase4:
	$(MAKE) phase2
	./scripts/validate-observe.sh
	./scripts/validate-project-fixtures.sh
	./scripts/validate-observe-hit-rate.sh
	./scripts/validate-hit-rate.sh
	./scripts/validate-recc.sh

passes:
	cmake -S llvm-passes -B build/passes && cmake --build build/passes

bpf:
	$(MAKE) -C runtime/bpf all

agent:
	$(MAKE) -C runtime/bpf all
	cd runtime/agent && clang -O2 -g -Wall -I../bpf -I../shared -o re-mini re-mini.c -lelf -lz -lbpf -ldl

agent-test: agent
	runtime/agent/re-mini --self-test-dedupe

toolchain:
	cargo build -p rerun -p re-rules -p re-crashpack -p re-escalate -p recc
