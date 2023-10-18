#pragma once

#include "bpf.h"
#include "constants.h"

// Data structure used for map_ip_hash
struct ip_hash_info {
  __u32 cpu;
  __u32 tc_handle; // TC handle MAJOR:MINOR combined in __u32
};

// Key type used for map_ip_hash trie
struct ip_hash_key {
  __u32 prefixlen;         // Length of the prefix to match
  struct in6_addr address; // An IPv6 address. IPv4 uses the last 32 bits.
};

// Data structure used for map_txq_config.
// This is used to apply the queue_mapping in the TC part.
struct txq_config {
  /* lookup key: __u32 cpu; */
  __u16 queue_mapping;
  __u16 tc_major;
};

// Map describing IP to CPU/TC mappings
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, IP_HASH_ENTRIES_MAX);
  __type(key, struct ip_hash_key);
  __type(value, struct ip_hash_info);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ip_to_cpu_and_tc SEC(".maps");

// Map describing interface direction (internet/client) for each ifindex
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_IFINDEX);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_ifindex_direction SEC(".maps");

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
  __uint(type, BPF_MAP_TYPE_CPUMAP);
  __uint(max_entries, MAX_CPUS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} cpu_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_CPUS);
  __type(key, __u32);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} cpus_available SEC(".maps");

// Map used to store queue mappings
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_CPUS);
  __type(key, __u32);
  __type(value, struct txq_config);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_txq_config SEC(".maps");
