#!/bin/bash

HOST_FILE="/home/ebpf/eBPF-escape/sshd_backdoor"
CONTAINER_FILE="/tmp/sshd_backdoor"

docker run -it \
    --security-opt apparmor:unconfined \
    --cap-add SYS_ADMIN \
    -v $HOST_FILE:$CONTAINER_FILE \
    -v /sys/kernel/debug:/sys/kernel/debug \
    ubuntu:latest \
    /bin/bash
