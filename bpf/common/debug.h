#pragma once

#include "bpf.h"

volatile const bool DEBUG = false;

char *log_header = "";
__u32 pkt_id = 0;

#define log_debug(fmt, args...)                                                \
  ({                                                                           \
    if (DEBUG) {                                                               \
      char ___msg[128] = {};                                                   \
      BPF_SNPRINTF(___msg, sizeof(___msg), fmt, args);                         \
      bpf_printk("%s [%x] %s", log_header, pkt_id, ___msg);                    \
    }                                                                          \
  })
