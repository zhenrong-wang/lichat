#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace lichat
{
  using byte_t = uint8_t;
  using byte_span_t = std::span<byte_t>;
  using const_byte_span_t = std::span<const byte_t>;
}