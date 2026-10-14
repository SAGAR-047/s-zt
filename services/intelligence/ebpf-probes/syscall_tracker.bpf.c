// +build ignore
/*
 * SentinelCloud-Advanced: eBPF System Call Tracker
 * --------------------------------------------------
 * Low-level C eBPF probe using kprobes / tracepoints to intercept
 * container system calls (sys_execve, sys_connect, sys_rename, sys_openat).
 *
 * Emits structured event records to an eBPF Ring Buffer consumed by the Go Agent.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN  256

// Structured event emitted to ringbuffer
struct syscall_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 syscall_id; // 1: execve, 2: connect, 3: rename, 4: openat
    u32 port;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX_LEN];
    char target[PATH_MAX_LEN];
};

// Ring buffer map definition
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Filter map for monitored namespaces/cgroups
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);
} cgroup_filter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_execve(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = (u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->syscall_id = 1; // sys_execve
    event->port = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename_ptr);
    event->target[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_connect(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct sockaddr_in user_addr;
    const void *addr_ptr = (const void *)ctx->args[1];
    if (!addr_ptr)
        return 0;

    bpf_probe_read_user(&user_addr, sizeof(user_addr), addr_ptr);

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = (u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->syscall_id = 2; // sys_connect
    event->port = __builtin_bswap16(user_addr.sin_port);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    event->target[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_sys_rename(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    struct syscall_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = (u32)id;
    event->uid = bpf_get_current_uid_gid();
    event->syscall_id = 3; // sys_rename
    event->port = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    const char *oldname_ptr = (const char *)ctx->args[0];
    const char *newname_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), oldname_ptr);
    bpf_probe_read_user_str(&event->target, sizeof(event->target), newname_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
