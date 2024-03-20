#pragma once

#include "bpf.h"
#include "constants.h"
#include "debug.h"

enum traffic_map {
  TRAFFIC_MAP_LOCAL = 0,
  TRAFFIC_MAP_REMOTE = 1,
};

// Counter for each host
struct host_counter {
  __u64 rx_bytes;
  __u64 tx_bytes;
  __u64 rx_packets;
  __u64 tx_packets;
  __u32 tc_handle;
  __u64 last_seen;
};

// Pinned map storing counters per host on local LAN.
// its an LRU structure: if it runs out of space,
// the least recently seen host will be removed.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __type(key, struct in6_addr);
  __type(value, struct host_counter);
  __uint(max_entries, MAX_TRACKED_IPS);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_traffic_local SEC(".maps");

// Pinned map storing counters per server on remote WAN.
// its an LRU structure: if it runs out of space,
// the least recently seen server will be removed.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __type(key, struct in6_addr);
  __type(value, struct host_counter);
  __uint(max_entries, MAX_TRACKED_IPS);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_traffic_remote SEC(".maps");

static __always_inline void track_traffic(enum traffic_map map, int direction,
                                          struct in6_addr *key, __u32 size,
                                          __u32 tc_handle) {
  void *map_fd =
      (map == TRAFFIC_MAP_LOCAL) ? &map_traffic_local : &map_traffic_remote;

  // Count the bits. It's per-CPU, so we can't be interrupted - no sync required
  struct host_counter *counter =
      (struct host_counter *)bpf_map_lookup_elem(map_fd, key);
  if (counter) {
    counter->last_seen = bpf_ktime_get_boot_ns();
    counter->tc_handle = tc_handle;
    if (direction == DIRECTION_INTERNET) {
      // Receive
      counter->rx_packets += 1;
      counter->rx_bytes += size;
    } else {
      // Transmit
      counter->tx_packets += 1;
      counter->tx_bytes += size;
    }
  } else {
    struct host_counter new_host = {0};
    new_host.tc_handle = tc_handle;
    new_host.last_seen = bpf_ktime_get_boot_ns();
    if (direction == DIRECTION_INTERNET) {
      new_host.rx_packets = 1;
      new_host.rx_bytes = size;
      new_host.tx_bytes = 0;
      new_host.tx_packets = 0;
    } else {
      new_host.tx_packets = 1;
      new_host.tx_bytes = size;
      new_host.rx_bytes = 0;
      new_host.rx_packets = 0;
    }
    if (bpf_map_update_elem(map_fd, key, &new_host, BPF_NOEXIST) != 0) {
      if (IN6_IS_ADDR_V4MAPPED(&key)) {
        log_debug("Failed to insert flow for IPv4 %pI4",
                  &key->in6_u.u6_addr32[3]);
      } else {
        log_debug("Failed to insert flow for IPv6 %pI6", &key);
      }
    }
  }
}
