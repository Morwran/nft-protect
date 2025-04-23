// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>

// #include <linux/netlink.h>
#include <linux/netfilter/nf_tables.h>
// #include <linux/netfilter/nfnetlink.h>

#include "lsm_netlink.h"
#include "send_event.h"

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/netlink_send")
int BPF_PROG(block_tbl, struct sock *sk, struct sk_buff *skb)
{
    void *data = (void *)BPF_CORE_READ(skb, data);
    void *data_end = data + BPF_CORE_READ(skb, len);

    if (BPF_CORE_READ(sk, sk_protocol) != NETLINK_NETFILTER)
        return 0;

    for (int i = 0; i < MAX_MSGS; i++)
    {
        struct nlmsghdr *nlh = data;
        if ((void *)nlh + sizeof(*nlh) > data_end)
            break;

        u32 nlh_len = BPF_CORE_READ(nlh, nlmsg_len);
        if (nlh_len == 0 || (void *)nlh + nlh_len > data_end)
            break;

        u16 ntype = BPF_CORE_READ(nlh, nlmsg_type);
        u8 subsys = NFNL_SUBSYS_ID(ntype);
        u8 mtype = NFNL_MSG_TYPE(ntype);

        if (subsys != NFNL_SUBSYS_NFTABLES)
        {
            data += NLMSG_ALIGN(nlh_len);
            continue;
        }
        switch (mtype)
        {
        case NFT_MSG_NEWTABLE:
        case NFT_MSG_DELTABLE:
        case NFT_MSG_NEWRULE:
        case NFT_MSG_DELRULE:
        case NFT_MSG_NEWCHAIN:
        case NFT_MSG_DELCHAIN:
        case NFT_MSG_NEWSET:
        case NFT_MSG_DELSET:
        {
            void *attr_buf;
            u32 attr_len;

            attr_buf = (void *)nlh + sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg);
            attr_len = nlh_len - sizeof(struct nlmsghdr) - sizeof(struct nfgenmsg);
            u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
            if (attr_has_protected_tbl(attr_buf, attr_len) &&
                curr_pid != get_allowed_pid())
            {
                u8 comm[TASK_COMM_LEN];
                if (bpf_get_current_comm(&comm, TASK_COMM_LEN) == 0)
                {
                    send_event(curr_pid, comm);
                }
                return -EPERM;
            }

            break;
        }
        default:
            break;
        }

        data += NLMSG_ALIGN(nlh_len);
    }

    return 0;
}