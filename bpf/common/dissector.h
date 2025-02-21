#pragma once

#include "bpf.h"
#include "debug.h"
#include "if_ether.h"
#include "ip_hash.h"
#include "math.h"
#include "nf_conntrack_bpf.h"
#include "skb_safety.h"
#include "tcp_opts.h"

// Union that contains either a pointer to an IPv4 header or an IPv6
// header. NULL if not present.
// Note that you also need to keep track of the header type, since
// accessing it directly without checking is undefined behavior.
union iph_ptr {
  // IPv4 Header
  struct iphdr *iph;
  // IPv6 Header
  struct ipv6hdr *ip6h;
};

// Structure holding packet dissection information
struct dissector_t {
  // Pointer to the XDP context, or NULL if running under TC
  struct xdp_md *ctx;
  // Pointer to the SKB context, or NULL if running under XDP
  struct __sk_buff *skb;
  // Start of data
  void *start;
  // Pointer to the end of data
  void *end;
  // Total packet length (end - start)
  __u32 skb_len;
  // Pointer to the Ethernet header once found (NULL until then)
  struct ethhdr *ethernet_header;
  // Ethernet packet type once found (0 until then)
  __u16 eth_type;
  // Start of Layer-3 data if found (0 until then)
  __u32 l3offset;
  // IPv4/6 header once found
  union iph_ptr ip_header;
  // Source IP address, encoded by `ip_hash.h`
  struct in6_addr src_ip;
  // Destination IP address, encoded by `ip_hash.h`
  struct in6_addr dst_ip;
  // Current VLAN tag. If there are multiple tags, it will be
  // the INNER tag.
  __be16 current_vlan;
  // IP protocol from __UAPI_DEF_IN_IPPROTO
  __u8 ip_protocol;
  __u16 src_port;
  __u16 dst_port;
  __u8 tcp_flags;
  __u16 window;
  __u32 tsval;
  __u32 tsecr;
  // NAT
  bool nat;
  struct in6_addr nat_ip;
  struct in6_addr nat_orig_ip;
};

// Representation of the PPPoE protocol header.
struct pppoe_proto {
  __u8 pppoe_version_type;
  __u8 ppoe_code;
  __be16 session_id;
  __be16 pppoe_length;
  __be16 proto;
};

#define PPPOE_SES_HLEN 8
#define PPP_IP 0x21
#define PPP_IPV6 0x57

#define MPLS_LS_LABEL_MASK 0xFFFFF000
#define MPLS_LS_LABEL_SHIFT 12
#define MPLS_LS_TC_MASK 0x00000E00
#define MPLS_LS_TC_SHIFT 9
#define MPLS_LS_S_MASK 0x00000100
#define MPLS_LS_S_SHIFT 8
#define MPLS_LS_TTL_MASK 0x000000FF
#define MPLS_LS_TTL_SHIFT 0

// Constructor for a dissector
// Connects XDP/TC SKB structure to a dissector structure.
// Arguments:
// * dissector - pointer to a local dissector object to be initialized
//
// Returns TRUE if all is good, FALSE if the process cannot be completed
static __always_inline bool dissector_new(struct dissector_t *dissector) {
  dissector->ethernet_header = (struct ethhdr *)NULL;
  dissector->l3offset = 0;
  dissector->skb_len = dissector->end - dissector->start;
  dissector->current_vlan = 0;
  dissector->ip_protocol = 0;
  dissector->src_port = 0;
  dissector->dst_port = 0;
  dissector->nat = false;

  // Check that there's room for an ethernet header
  if SKB_OVERFLOW (dissector->start, dissector->end, ethhdr) {
    return false;
  }
  dissector->ethernet_header = (struct ethhdr *)dissector->start;

  return true;
}

static __always_inline bool xdp_dissector_new(struct xdp_md *ctx,
                                              struct dissector_t *dissector) {
  dissector->skb = NULL;
  dissector->ctx = ctx;
  dissector->start = (void *)(long)ctx->data;
  dissector->end = (void *)(long)ctx->data_end;

  return dissector_new(dissector);
}

static __always_inline bool tc_dissector_new(struct __sk_buff *skb,
                                             struct dissector_t *dissector) {
  dissector->ctx = NULL;
  dissector->skb = skb;
  dissector->start = (void *)(long)skb->data;
  dissector->end = (void *)(long)skb->data_end;

  return dissector_new(dissector);
}

// Helper function - is an eth_type an IPv4 or v6 type?
static __always_inline bool is_ip(__u16 eth_type) {
  return eth_type == ETH_P_IP || eth_type == ETH_P_IPV6;
}

// Locates the layer-3 offset, if present. Fast returns for various
// common non-IP types. Will perform VLAN redirection if requested.
static __always_inline bool
dissector_find_l3_offset(struct dissector_t *dissector) {
  if (dissector->ethernet_header == NULL) {
    log_debug("Ethernet header is NULL, still called offset check.\n");
    return false;
  }
  __u32 offset = sizeof(struct ethhdr);
  __u16 eth_type = bpf_ntohs(dissector->ethernet_header->h_proto);

  // Fast return for unwrapped IP
  if (eth_type == ETH_P_IP || eth_type == ETH_P_IPV6) {
    dissector->eth_type = eth_type;
    dissector->l3offset = offset;
    return true;
  }

  // Fast return for ARP or non-802.3 ether types
  if (eth_type == ETH_P_ARP || eth_type < ETH_P_802_3_MIN) {
    return false;
  }

  // Walk the headers until we find IP
  __u8 i = 0;
  while (i < 10 && !is_ip(eth_type)) {
    switch (eth_type) {
    // Read inside VLAN headers
    case ETH_P_8021AD:
    case ETH_P_8021Q: {
      if SKB_OVERFLOW_OFFSET (dissector->start, dissector->end, offset,
                              vlan_hdr) {
        return false;
      }
      struct vlan_hdr *vlan = (struct vlan_hdr *)(dissector->start + offset);
      dissector->current_vlan = vlan->h_vlan_TCI;
      eth_type = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
      offset += sizeof(struct vlan_hdr);
    } break;

    // Handle PPPoE
    case ETH_P_PPP_SES: {
      if SKB_OVERFLOW_OFFSET (dissector->start, dissector->end, offset,
                              pppoe_proto) {
        return false;
      }
      struct pppoe_proto *pppoe =
          (struct pppoe_proto *)(dissector->start + offset);
      __u16 proto = bpf_ntohs(pppoe->proto);
      switch (proto) {
      case PPP_IP:
        eth_type = ETH_P_IP;
        break;
      case PPP_IPV6:
        eth_type = ETH_P_IPV6;
        break;
      default:
        return false;
      }
      offset += PPPOE_SES_HLEN;
    } break;

    // We found something we don't know how to handle - bail out
    default:
      return false;
    }
    ++i;
  }

  dissector->l3offset = offset;
  dissector->eth_type = eth_type;
  return true;
}

static __always_inline void resolve_nat(struct dissector_t *dissector) {
  if (dissector->eth_type != ETH_P_IP) {
    return;
  }

  if (dissector->ip_protocol != IPPROTO_TCP &&
      dissector->ip_protocol != IPPROTO_UDP) {
    return;
  }

  struct bpf_sock_tuple lookup_tuple = {
      .ipv4 = {
          .saddr = dissector->ip_header.iph->saddr,
          .daddr = dissector->ip_header.iph->daddr,
          .sport = dissector->src_port,
          .dport = dissector->dst_port,
      }};
  struct bpf_ct_opts___local ct_lookup_opts = {
      .netns_id = BPF_F_CURRENT_NETNS,
      .l4proto = dissector->ip_protocol,
  };

  if (BPF_CT_OPTS_SIZE >= 16) {
    ct_lookup_opts.ct_zone_id = CT_ZONE_ID;
  }

  if (dissector->ctx) {
    // Do conntrack lookup from XDP
    struct nf_conn *ct = bpf_xdp_ct_lookup(
        dissector->ctx, &lookup_tuple, sizeof(lookup_tuple.ipv4),
        &ct_lookup_opts, MIN(BPF_CT_OPTS_SIZE, sizeof(ct_lookup_opts)));
    if (ct) {
      if (ct->status & IPS_SRC_NAT) {
        dissector->nat = true;
        encode_ipv4(ct->tuplehash[0].tuple.src.u3.ip, &dissector->nat_orig_ip);
        encode_ipv4(ct->tuplehash[1].tuple.dst.u3.ip, &dissector->nat_ip);
      }
      bpf_ct_release(ct);
    }
  } else if (dissector->skb) {
    // Do conntrack lookup from TC
    struct nf_conn *ct = bpf_skb_ct_lookup(
        dissector->skb, &lookup_tuple, sizeof(lookup_tuple.ipv4),
        &ct_lookup_opts, MIN(BPF_CT_OPTS_SIZE, sizeof(ct_lookup_opts)));
    if (ct) {
      if (ct->status & IPS_SRC_NAT) {
        dissector->nat = true;
        encode_ipv4(ct->tuplehash[0].tuple.src.u3.ip, &dissector->nat_orig_ip);
        encode_ipv4(ct->tuplehash[1].tuple.dst.u3.ip, &dissector->nat_ip);
      }
      bpf_ct_release(ct);
    }
  }
}

static __always_inline struct tcphdr *
get_tcp_header(struct dissector_t *dissector) {
  if (dissector->eth_type == ETH_P_IP) {
    return (struct tcphdr *)((char *)dissector->ip_header.iph +
                             (dissector->ip_header.iph->ihl * 4));
  } else if (dissector->eth_type == ETH_P_IPV6) {
    return (struct tcphdr *)(dissector->ip_header.ip6h + 1);
  }
  return NULL;
}

static __always_inline struct udphdr *
get_udp_header(struct dissector_t *dissector) {
  if (dissector->eth_type == ETH_P_IP) {
    return (struct udphdr *)((char *)dissector->ip_header.iph +
                             (dissector->ip_header.iph->ihl * 4));
  } else if (dissector->eth_type == ETH_P_IPV6) {
    return (struct udphdr *)(dissector->ip_header.ip6h + 1);
  }
  return NULL;
}

static __always_inline struct icmphdr *
get_icmp_header(struct dissector_t *dissector) {
  if (dissector->eth_type == ETH_P_IP) {
    return (struct icmphdr *)((char *)dissector->ip_header.iph +
                              (dissector->ip_header.iph->ihl * 4));
  } else if (dissector->eth_type == ETH_P_IPV6) {
    return (struct icmphdr *)(dissector->ip_header.ip6h + 1);
  }
  return NULL;
}

static __always_inline void snoop(struct dissector_t *dissector) {
  switch (dissector->ip_protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *hdr = get_tcp_header(dissector);
    if (hdr != NULL) {
      if ((void *)(hdr + 1) > dissector->end) {
        return;
      }
      dissector->src_port = hdr->source;
      dissector->dst_port = hdr->dest;
      __u8 flags = 0;
      if (hdr->fin)
        flags |= 1;
      if (hdr->syn)
        flags |= 2;
      if (hdr->rst)
        flags |= 4;
      if (hdr->psh)
        flags |= 8;
      if (hdr->ack)
        flags |= 16;
      if (hdr->urg)
        flags |= 32;
      if (hdr->ece)
        flags |= 64;
      if (hdr->cwr)
        flags |= 128;

      dissector->tcp_flags = flags;
      dissector->window = hdr->window;

      parse_tcp_ts(hdr, dissector->end, &dissector->tsval, &dissector->tsecr);

      resolve_nat(dissector);
    }
  } break;
  case IPPROTO_UDP: {
    struct udphdr *hdr = get_udp_header(dissector);
    if (hdr != NULL) {
      if ((void *)(hdr + 1) > dissector->end) {
        log_debug("UDP header past end\n");
        return;
      }
      dissector->src_port = hdr->source;
      dissector->dst_port = hdr->dest;

      resolve_nat(dissector);
    }
  } break;
  case IPPROTO_ICMP: {
    struct icmphdr *hdr = get_icmp_header(dissector);
    if (hdr != NULL) {
      if ((void *)hdr + sizeof(struct icmphdr) > dissector->end) {
        log_debug("ICMP header past end\n");
        return;
      }
      dissector->ip_protocol = 1;
      dissector->src_port = bpf_ntohs(hdr->type);
      dissector->dst_port = bpf_ntohs(hdr->code);
    }
  } break;
  }
}

// Searches for an IP header.
static __always_inline bool
dissector_find_ip_header(struct dissector_t *dissector) {
  switch (dissector->eth_type) {
  case ETH_P_IP: {
    if (dissector->start + dissector->l3offset + sizeof(struct iphdr) >
        dissector->end) {
      return false;
    }
    dissector->ip_header.iph = dissector->start + dissector->l3offset;
    if ((void *)(dissector->ip_header.iph + 1) > dissector->end) {
      return false;
    }
    encode_ipv4(dissector->ip_header.iph->saddr, &dissector->src_ip);
    encode_ipv4(dissector->ip_header.iph->daddr, &dissector->dst_ip);
    dissector->ip_protocol = dissector->ip_header.iph->protocol;
    snoop(dissector);
    return true;
  } break;
  case ETH_P_IPV6: {
    if (dissector->start + dissector->l3offset + sizeof(struct ipv6hdr) >
        dissector->end) {
      return false;
    }
    dissector->ip_header.ip6h = dissector->start + dissector->l3offset;
    if ((void *)(dissector->ip_header.iph + 1) > dissector->end)
      return false;
    encode_ipv6(&dissector->ip_header.ip6h->saddr, &dissector->src_ip);
    encode_ipv6(&dissector->ip_header.ip6h->daddr, &dissector->dst_ip);
    dissector->ip_protocol = dissector->ip_header.ip6h->nexthdr;
    snoop(dissector);
    return true;
  } break;
  default:
    return false;
  }
}
