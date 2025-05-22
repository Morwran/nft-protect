#ifndef __INPUT_PARAMS_H__
#define __INPUT_PARAMS_H__

#define MAX_TBL_NAME 64

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} allowed_pid_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8[MAX_TBL_NAME]);
} protected_tbl_name_map SEC(".maps");

static __always_inline u32 get_allowed_pid()
{
    u32 key = 0;
    u32 *val = bpf_map_lookup_elem(&allowed_pid_map, &key);
    if (!val)
    {
        return 0;
    }
    return *val;
}

#define GET_PROTECTED_TBL_NAME(tbl_name)                              \
    ({                                                                \
        u32 key = 0;                                                  \
        u8 *res = NULL;                                               \
        u8 *val = bpf_map_lookup_elem(&protected_tbl_name_map, &key); \
        if (val)                                                      \
        {                                                             \
            res = __builtin_memcpy(tbl_name, val, MAX_TBL_NAME);      \
        }                                                             \
        res;                                                          \
    })

#define GET_NAME_LEN(tbl_name)                                  \
    ({                                                          \
        u32 len = 0;                                            \
        while (tbl_name[len] != '\0' && len < MAX_TBL_NAME - 1) \
        {                                                       \
            len++;                                              \
        }                                                       \
        len;                                                    \
    })

#define NAME_CMP(src1, src2, len)                                 \
    ({                                                            \
        u32 i = 0;                                                \
        while (i < len && i < MAX_TBL_NAME && src1[i] == src2[i]) \
        {                                                         \
            i++;                                                  \
        }                                                         \
        i == len;                                                 \
    })

#endif