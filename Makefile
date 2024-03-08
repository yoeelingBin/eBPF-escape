CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror -I /usr/include/aarch64-linux-gnu -v $(CFLAGS)

# build full sshd_backdoor cli tool.
build: mod_tidy generate
	go build -o sshd_backdoor cmd/main.go

help:
	$(info |=======================================================================================================)
	$(info |usage:)
	$(info |	build:  build full sshd_backdoor cli tool. But full sshd_backdoor is just supoorted the demo only)
	$(info |	generate: Generate the ebpf prog in kernel with clang.)
	$(info |			  if you need you can set the CFLAGS to append)
	$(info |	test_ebpf: if you editing the ebpf-c c files and header files)
	$(info |			   to test the ebpf can be compiled and pass ebpf verifier when load)
	$(info |	tool_unload: bpftool unload progs.)
	$(info |	tool_load: bpftool load  progs.)
	$(info |)

# Generate the ebpf prog in kernel with clang
generate: mod_tidy
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./pkg/generate...

# try go mod tidy
mod_tidy: 
	go mod tidy

# read tracing pipe debug printk
tool_read_printk:
	cat  /sys/kernel/debug/tracing/trace_pipe

# bpftool load progs.
tool_load:
	bpftool prog loadall ./pkg/generate/bpf_bpfel.o /sys/fs/bpf
	echo load Complete But need attach.

# bpftool unload progs.
tool_unload:
	rm /sys/fs/bpf/*

# test ebpf prog in passing verifier.
test_ebpf: generate
test_ebpf: tool_load
test_ebpf: tool_unload