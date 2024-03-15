/* SPDX-License-Identifier: GPL-2.0 */

// Based on:
//   * https://github.com/xdp-project/xdp-cpumap-tc/
//   * https://github.com/LibreQoE/LibreQoS/tree/main/src/rust/lqos_sys/src/bpf

/* clang-format off */
//go:build ignore
/* clang-format on */

#include "common/bpf.h"
#include "common/constants.h"
#include "common/debug.h"
#include "common/direction.h"
#include "common/dissector.h"
#include "common/lpm.h"
#include "common/maps.h"
#include "common/pkt_cls.h"
#include "common/pkt_sched.h"
#include "common/throughput.h"

char _license[] SEC("license") = "GPL";

/* Theory of operation:
1. (Packet arrives at interface)
2. XDP (ingress) starts
  * Lookup interface direction
  * Dissect the packet to find L3 offset (resolving any NATs)
  * Perform LPM lookup to determine CPU destination
  * Track traffic totals
  * Perform CPU redirection
3. TC (egress) starts
  * Lookup interface direction
  * Lookup CPU/TX queue mapping
  * Dissect the packet to find L3 offset (resolving any NATs)
  * LPM lookup to find TC handle
  * Update packet to set appropriate TC handle.
*/

// XDP-Ingress Entry Point
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  if (DEBUG) {
    log_header = "<tc-cpumap> XDP-Ingress:";
    pkt_id = bpf_get_prandom_u32();
  }

  __u32 ifindex = ctx->ingress_ifindex;

  log_debug("New packet on ifindex %u.", ifindex);

  /* Internet or Client interface? */
  __u32 *direction_lookup =
      bpf_map_lookup_elem(&map_ifindex_direction, &ifindex);
  if (!direction_lookup) {
    log_debug("ifindex %u is missing from ifindex direction map.", ifindex);
    return XDP_PASS;
  }
  __u32 direction = *direction_lookup;
  if (direction != DIRECTION_INTERNET && direction != DIRECTION_CLIENT) {
    log_debug("Interface direction for ifindex %u unspecified, ignoring "
              "traffic on "
              "this interface.",
              ifindex);
    return XDP_PASS;
  }

  if (direction == DIRECTION_INTERNET) {
    log_debug("Interface direction for ifindex %u is INTERNET.", ifindex);
  } else if (direction == DIRECTION_CLIENT) {
    log_debug("Interface direction for ifindex %u is CLIENT.", ifindex);
  }

  struct dissector_t dissector = {0};

  if (!xdp_dissector_new(ctx, &dissector)) {
    log_debug("Failed to initialise new dissector for packet.");
    return XDP_PASS;
  }
  if (!dissector_find_l3_offset(&dissector)) {
    log_debug("Failed to find L3 offset for packet.");
    return XDP_PASS;
  }
  if (!dissector_find_ip_header(&dissector)) {
    log_debug("Failed to find IP header for packet.");
    return XDP_PASS;
  }

  if (IN6_IS_ADDR_V4MAPPED(&dissector.src_ip)) {
    log_debug(
        "L3 flow ip protocol %u src %pI4:%u dst %pI4:%u", dissector.ip_protocol,
        &dissector.src_ip.in6_u.u6_addr32[3], bpf_ntohs(dissector.src_port),
        &dissector.dst_ip.in6_u.u6_addr32[3], bpf_ntohs(dissector.dst_port));
    if (dissector.nat) {
      log_debug("NAT flow, original IP %pI4",
                &dissector.nat_src_ip.in6_u.u6_addr32[3]);
    }
  } else {
    log_debug("L3 flow ip protocol %u src %pI6:%u dst %pI6:%u",
              dissector.ip_protocol, &dissector.src_ip,
              bpf_ntohs(dissector.src_port), &dissector.dst_ip,
              bpf_ntohs(dissector.dst_port));
  }

  struct ip_hash_key lookup_key;
  struct ip_hash_info *ip_info = lookup_ip(direction, &lookup_key, &dissector);

  // Find the desired TC handle and CPU target
  __u32 tc_handle = 0;
  __u32 cpu = 0;
  if (ip_info) {
    tc_handle = ip_info->tc_handle;
    cpu = ip_info->cpu;

    __u16 tc_major = TC_H_MAJ(tc_handle) >> 16;
    __u16 tc_minor = TC_H_MIN(tc_handle);
    if (IN6_IS_ADDR_V4MAPPED(&lookup_key.address)) {
      log_debug("IPv4 %pI4 is mapped to TC handle 0x%x:0x%x and CPU %u.",
                &lookup_key.address.in6_u.u6_addr32[3], tc_major, tc_minor,
                cpu);
    } else {
      log_debug("IPv6 %pI6 is mapped to TC handle 0x%x:0x%x and CPU %u.",
                &lookup_key.address, tc_major, tc_minor, cpu);
    }
  } else {
    if (IN6_IS_ADDR_V4MAPPED(&lookup_key.address)) {
      log_debug("IPv4 %pI4 is not mapped to a TC handle and CPU.",
                &lookup_key.address.in6_u.u6_addr32[3]);
    } else {
      log_debug("IPv6 %pI6 is not mapped to a TC handle and CPU.",
                &lookup_key.address);
    }
  }

  // Update the local traffic tracking buffers
  track_traffic(TRAFFIC_MAP_LOCAL, direction, &lookup_key.address,
                ctx->data_end - ctx->data, // end - data = length
                tc_handle);

  struct in6_addr remote_address =
      (direction == DIRECTION_INTERNET) ? dissector.src_ip : dissector.dst_ip;

  // Update the remote traffic tracking buffers
  track_traffic(TRAFFIC_MAP_REMOTE, reverse_direction(direction),
                &remote_address,
                ctx->data_end - ctx->data, // end - data = length
                0);

  if (tc_handle != 0) {
    // Handle CPU redirection if there is one specified
    __u32 *cpu_lookup;
    cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu);
    if (!cpu_lookup) {
      log_debug("CPU %u is missing from available CPU map.", cpu);
      return XDP_PASS;
    }
    if (*cpu_lookup != CPU_AVAILABLE) {
      log_debug("CPU %u is not available for redirection.", cpu);
      return XDP_PASS;
    }

    long redirect_result = bpf_redirect_map(&cpu_map, cpu, 0);

    if (redirect_result == XDP_REDIRECT) {
      log_debug("Redirecting packet to CPU %u.", cpu);
      return redirect_result;
    } else {
      log_debug("Error redirecting packet, got retval %u.", redirect_result);
    }
  }

  log_debug("No action taken for packet.");

  return XDP_PASS;
}

// TC-Egress Entry Point
SEC("tc")
int tc_prog(struct __sk_buff *skb) {
  if (DEBUG) {
    log_header = "<tc-cpumap> TC-Egress:  ";
    pkt_id = bpf_get_prandom_u32();
  }

  __u32 ifindex = skb->ifindex;

  log_debug("New packet on ifindex %u.", ifindex);

  /* Internet or Client interface? */
  __u32 *direction_lookup =
      bpf_map_lookup_elem(&map_ifindex_direction, &ifindex);
  if (!direction_lookup) {
    log_debug("ifindex %u is missing from ifindex direction map.", ifindex);
    return TC_ACT_OK;
  }
  __u32 direction = *direction_lookup;
  if (direction != DIRECTION_INTERNET && direction != DIRECTION_CLIENT) {
    log_debug("Interface direction for ifindex %u unspecified, ignoring "
              "traffic on this interface.",
              ifindex);
    return TC_ACT_OK;
  }

  if (direction == DIRECTION_INTERNET) {
    log_debug("Interface direction for ifindex %u is INTERNET.", ifindex);
  } else if (direction == DIRECTION_CLIENT) {
    log_debug("Interface direction for ifindex %u is CLIENT.", ifindex);
  }

  __u32 cpu = bpf_get_smp_processor_id();

  // Lookup the queue
  struct txq_config *txq_cfg;
  txq_cfg = bpf_map_lookup_elem(&map_txq_config, &cpu);
  if (!txq_cfg) {
    log_debug("CPU %u is missing from TX queue map", cpu, skb->queue_mapping);
    return TC_ACT_SHOT;
  }
  if (txq_cfg->queue_mapping != 0) {
    log_debug("CPU %u is mapped to TX queue %u", cpu, txq_cfg->queue_mapping);
    skb->queue_mapping = txq_cfg->queue_mapping;
  } else {
    log_debug(
        "CPU %u has no TX queues mapped, will use TX queue %d from packet", cpu,
        skb->queue_mapping);
  }

  struct dissector_t dissector = {0};

  if (!tc_dissector_new(skb, &dissector)) {
    log_debug("Failed to initialise new dissector for packet.");
    return TC_ACT_OK;
  }
  if (!dissector_find_l3_offset(&dissector)) {
    log_debug("Failed to find L3 offset for packet.");
    return TC_ACT_OK;
  }
  if (!dissector_find_ip_header(&dissector)) {
    log_debug("Failed to find IP header for packet.");
    return TC_ACT_OK;
  }

  if (IN6_IS_ADDR_V4MAPPED(&dissector.src_ip)) {
    log_debug(
        "L3 flow ip protocol %u src %pI4:%u dst %pI4:%u", dissector.ip_protocol,
        &dissector.src_ip.in6_u.u6_addr32[3], bpf_ntohs(dissector.src_port),
        &dissector.dst_ip.in6_u.u6_addr32[3], bpf_ntohs(dissector.dst_port));
    if (dissector.nat) {
      log_debug("NAT flow, original IP %pI4",
                &dissector.nat_src_ip.in6_u.u6_addr32[3]);
    }
  } else {
    log_debug("L3 flow ip protocol %u src %pI6:%u dst %pI6:%u",
              dissector.ip_protocol, &dissector.src_ip,
              bpf_ntohs(dissector.src_port), &dissector.dst_ip,
              bpf_ntohs(dissector.dst_port));
  }

  struct ip_hash_key lookup_key;
  struct ip_hash_info *ip_info = lookup_ip(direction, &lookup_key, &dissector);

  if (ip_info) {
    if (ip_info->cpu != cpu) {
      if (IN6_IS_ADDR_V4MAPPED(&lookup_key.address)) {
        log_debug(
            "IPv4 %pI4 has arrived on CPU %u when we expected it on CPU %u.",
            &lookup_key.address.in6_u.u6_addr32[3], cpu, ip_info->cpu);
      } else {
        log_debug(
            "IPv6 %pI6 has arrived on CPU %u when we expected it on CPU %u.",
            &lookup_key.address, cpu, ip_info->cpu);
      }
    }

    if (ip_info->tc_handle != 0) {
      __u16 ip_tc_major = TC_H_MAJ(ip_info->tc_handle) >> 16;
      __u16 ip_tc_minor = TC_H_MIN(ip_info->tc_handle);
      if (ip_tc_major != txq_cfg->tc_major) {
        if (IN6_IS_ADDR_V4MAPPED(&lookup_key.address)) {
          log_debug("IPv4 %pI4 is mapped to TC major 0x%x but CPU %u is "
                    "mapped to TC major 0x%x.",
                    &lookup_key.address.in6_u.u6_addr32[3], ip_tc_major, cpu,
                    txq_cfg->tc_major, cpu);
        } else {
          log_debug("IPv6 %pI6 is mapped to TC major 0x%x but CPU %u is "
                    "mapped to TC major 0x%x.",
                    &lookup_key.address, ip_tc_major, cpu, txq_cfg->tc_major);
        }
      } else {
        if (IN6_IS_ADDR_V4MAPPED(&lookup_key.address)) {
          log_debug("IPv4 %pI4 setting TC handle to 0x%x:0x%x.",
                    &lookup_key.address.in6_u.u6_addr32[3], ip_tc_major,
                    ip_tc_minor);
        } else {
          log_debug("IPv6 %pI6 setting TC handle to 0x%x:0x%x.",
                    &lookup_key.address, ip_tc_major, ip_tc_minor);
        }
        skb->priority = ip_info->tc_handle;
      }
    } else {
      if (IN6_IS_ADDR_V4MAPPED(&lookup_key.address)) {
        log_debug("IPv4 %pI4 is not mapped to a TC handle.",
                  &lookup_key.address.in6_u.u6_addr32[3]);
      } else {
        log_debug("IPv6 %pI6 is not mapped to a TC handle.",
                  &lookup_key.address);
      }
    }
  }

  return TC_ACT_OK;
}
