#ifndef __NETLINK_H__
#define __NETLINK_H__

#include "input_params.h"
#include "send_event.h"

#define NETLINK_NETFILTER 12 /* netfilter subsystem */

#define NFNL_SUBSYS_NFTABLES 10

#define NFNL_SUBSYS_ID(x) ((x & 0xff00) >> 8)
#define NFNL_MSG_TYPE(x) (x & 0x00ff)

#define NLA_F_NESTED (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))

#define MAX_ATTRS 32
#define MAX_MSGS 16

#define ATTR_IS_TABLE_NAME(t)   \
    ((t) == NFTA_TABLE_NAME ||  \
     (t) == NFTA_CHAIN_TABLE || \
     (t) == NFTA_RULE_TABLE ||  \
     (t) == NFTA_SET_TABLE)

struct nfgenmsg
{
    __u8 nfgen_family; /* AF_xxx */
    __u8 version;      /* nfnetlink version */
    __be16 res_id;     /* resource id */
};

static __always_inline bool nl_attr_has_protected_tbl(void *attr_buf, u32 len)
{
    for (int n = 0; n < MAX_ATTRS && len >= sizeof(struct nlattr); n++)
    {
        struct nlattr *nla = attr_buf;
        u32 nla_len = BPF_CORE_READ(nla, nla_len);
        if (nla_len < sizeof(*nla) || nla_len > len)
        {
            return false;
        }

        if (ATTR_IS_TABLE_NAME(BPF_CORE_READ(nla, nla_type) & NLA_TYPE_MASK))
        {
            char tbl_name[MAX_TBL_NAME];

            if (bpf_probe_read_kernel(tbl_name, sizeof(tbl_name), (void *)nla + sizeof(*nla)) != 0)
            {
                return false;
            }

            char protected_tbl_name[MAX_TBL_NAME];
            if (!GET_PROTECTED_TBL_NAME(protected_tbl_name))
            {
                return false;
            }
            u32 len = GET_NAME_LEN(protected_tbl_name);
            if (len == 0 || nla_len - sizeof(*nla) < len)
            {
                return false;
            }
            if (NAME_CMP(tbl_name, protected_tbl_name, len))
            {
                return true;
            }
            return false;
        }

        u32 step = (nla_len + 3) & ~3;
        attr_buf += step;
        len -= step;
    }
    return false;
}

static __always_inline int nl_handle_msg(struct sk_buff *skb)
{
    void *data = (void *)BPF_CORE_READ(skb, data);
    void *data_end = data + BPF_CORE_READ(skb, len);

    for (int i = 0; i < MAX_MSGS; i++)
    {
        struct nlmsghdr *nlh = data;
        if ((void *)nlh + sizeof(*nlh) > data_end)
        {
            break;
        }

        u32 nlh_len = BPF_CORE_READ(nlh, nlmsg_len);
        if (nlh_len == 0 || (void *)nlh + nlh_len > data_end)
        {
            break;
        }

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
            if (nl_attr_has_protected_tbl(attr_buf, attr_len) &&
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

#endif