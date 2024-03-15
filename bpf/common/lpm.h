#pragma once

#include "bpf.h"
#include "dissector.h"
#include "maps.h"

// Performs an LPM lookup for an `ip_hash.h` encoded address
static __always_inline struct ip_hash_info *lookup_ip(
    // Interface direction. 1 = Internet, 2 = LAN
    int direction,
    // Pointer to the "lookup key", which should contain the IP address
    // to search for. Prefix length will be set for you.
    struct ip_hash_key *lookup_key,
    // Pointer to the traffic dissector.
    struct dissector_t *dissector) {
  lookup_key->prefixlen = 128;

  if (dissector->nat) {
    lookup_key->address = dissector->nat_src_ip;
  } else {
    lookup_key->address = (direction == DIRECTION_INTERNET) ? dissector->dst_ip
                                                            : dissector->src_ip;
  }

  struct ip_hash_info *ip_info =
      bpf_map_lookup_elem(&map_ip_to_cpu_and_tc, lookup_key);

  return ip_info;
}
