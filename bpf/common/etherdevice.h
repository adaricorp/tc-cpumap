#pragma once

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static inline u64 ether_addr_to_u64(const u8 *addr) {
  u64 u = 0;
  int i;

  for (i = 0; i < ETH_ALEN; i++)
    u = u << 8 | addr[i];

  return u;
}
