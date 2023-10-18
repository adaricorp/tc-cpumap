#pragma once

/* Interface (ifindex) direction type */
#define DIRECTION_NONE 0 /* Not configured */
#define DIRECTION_INTERNET 1
#define DIRECTION_CLIENT 2

/* This ifindex limit is an artifical limit that can easily be bumped.
 * The reason for this is allowing to use a faster BPF_MAP_TYPE_ARRAY
 * in fast-path lookups.
 */
#define MAX_IFINDEX 256

// Maximum number of client IPs we are tracking
#define MAX_TRACKED_IPS 64000

// Maximum number of TC class mappings to support
#define IP_HASH_ENTRIES_MAX 64000

// Maximum number of supported CPUs
#define MAX_CPUS 1024

// Maximum number of TCP flows to track at once
#define MAX_FLOWS IP_HASH_ENTRIES_MAX * 2

// Maximum number of packet pairs to track per flow.
#define MAX_PACKETS MAX_FLOWS

#define CPU_AVAILABLE 0xffffffff
#define CPU_NOT_AVAILABLE 0
