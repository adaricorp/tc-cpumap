#pragma once

#include "bpf.h"

volatile const u16 CT_ZONE_ID = 0;
volatile const u32 BPF_CT_OPTS_SIZE = NF_BPF_CT_OPTS_SZ;

struct bpf_ct_opts___local {
  s32 netns_id;
  s32 error;
  u8 l4proto;
  u8 dir;
  u16 ct_zone_id;
  u8 ct_zone_dir;
  u8 reserved[3];
};

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx,
                                         struct bpf_sock_tuple *bpf_tuple,
                                         __u32 len_tuple,
                                         struct bpf_ct_opts *opts,
                                         __u32 len_opts) __ksym;

extern struct nf_conn *
bpf_skb_ct_lookup(struct __sk_buff *skb_ctx, struct bpf_sock_tuple *bpf_tuple,
                  u32 len_tuple, struct bpf_ct_opts *opts, u32 len_opts) __ksym;

extern void bpf_ct_release(struct nf_conn *ct) __ksym;
