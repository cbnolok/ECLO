#pragma once

#include <cinttypes>
#include <algorithm>
#include <fstream>
#include <limits>
#include <vector>


using byte = uint8_t;

bool find_bytes(size_t* position, std::fstream& fs, const size_t file_size, const byte* bytes, const size_t bytes_size);


template<typename T>
inline auto signed_to_unsigned_floor(T number) noexcept {
  static_assert(std::is_signed_v<T>, "not signed value");
  return static_cast<std::make_unsigned_t<T>>(std::max(number, static_cast<T>(0)));
}

template<typename T>
inline auto unsigned_to_signed_ceil(T number) noexcept {
  static_assert(std::is_unsigned_v<T>, "not unsigned value");
  return static_cast<std::make_signed_t<T>>(std::min(number, static_cast<T>(std::numeric_limits<T>::max())));
}