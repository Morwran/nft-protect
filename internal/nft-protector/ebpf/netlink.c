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
int kprobe_nfnetlink_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    nl_handle_msg(skb);
    return 0;
}
