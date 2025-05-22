#ifndef __SEND_EVENT_H__
#define __SEND_EVENT_H__

#define TASK_COMM_LEN 32

struct event
{
    u32 pid;
    u8 comm[TASK_COMM_LEN];
};

const struct event *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int send_event(u32 pid, u8 *comm)
{
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return -1;

    event->pid = pid;
    if (bpf_probe_read_kernel(event->comm, TASK_COMM_LEN, comm) == 0)
    {
        bpf_ringbuf_submit(event, 0);
        return 0;
    }
    bpf_ringbuf_discard(event, 0);
    return -1;
}

#endif