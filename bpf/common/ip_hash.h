#pragma once

#include "bpf.h"

// Provides hashing services for merging IPv4 and IPv6 addresses into
// the same memory format.

// Encodes an IPv4 address into an IPv6 address. All 0xFF except for the
// last 32-bits.
static __always_inline void encode_ipv4(__be32 addr,
                                        struct in6_addr *out_address) {
  __builtin_memset(&out_address->in6_u.u6_addr8, 0, 16);
  out_address->in6_u.u6_addr32[2] = bpf_htonl(0xffff);
  out_address->in6_u.u6_addr32[3] = addr;
}

// Encodes an IPv6 address into an IPv6 address. Unsurprisingly, that's
// just a memcpy operation.
static __always_inline void encode_ipv6(struct in6_addr *ipv6_address,
                                        struct in6_addr *out_address) {
  __builtin_memcpy(&out_address->in6_u.u6_addr8, &ipv6_address->in6_u.u6_addr8,
                   16);
}

// Macro to check if IPv6 address has an IPv4 address encoded inside of it
#define IN6_IS_ADDR_V4MAPPED(a)                                                \
  ((((const uint32_t *)(a))[0] == 0) && (((const uint32_t *)(a))[1] == 0) &&   \
   (((const uint32_t *)(a))[2] == bpf_htonl(0xffff)))
