#pragma once

#include "bpf.h"
#include "constants.h"

static __always_inline int reverse_direction(int direction) {
  if (direction == DIRECTION_INTERNET)
    return DIRECTION_CLIENT;
  else if (direction == DIRECTION_CLIENT)
    return DIRECTION_INTERNET;

  return DIRECTION_NONE;
}
