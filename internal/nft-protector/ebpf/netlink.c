// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

#include <linux/netfilter/nf_tables.h>

#include "netlink.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/netlink_send")
int BPF_PROG(lsm_netlink_send, struct sock *sk, struct sk_buff *skb)
{
    if (BPF_CORE_READ(sk, sk_protocol) != NETLINK_NETFILTER)
        return 0;

    return nl_handle_msg(skb);
}

SEC("kprobe/nfnetlink_rcv")
int BPF_PROG(kprobe_nfnetlink_rcv, struct sk_buff *skb)
{
    return nl_handle_msg(skb);
}
