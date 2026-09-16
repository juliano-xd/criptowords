#pragma once
#include <cstdint>
#include <cstddef>

namespace crypto {

class RIPEMD160 {
  public:
    RIPEMD160();
    void reset();
    void update(const void* data, size_t len);
    void finalize(uint8_t out[20]);
    static void hash(const void* data, size_t len, uint8_t out[20]);

  private:
    uint32_t h_[5];
    uint8_t buf_[64];
    size_t buf_len_;
    uint64_t total_len_;

    void process_block(const uint8_t block[64]);
};

} // namespace crypto
