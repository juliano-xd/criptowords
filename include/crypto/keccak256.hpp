#pragma once
#include <cstdint>
#include <cstddef>
#include <algorithm>

namespace crypto {

class Keccak256 {
  public:
    Keccak256();
    void reset();
    void update(const void* data, size_t len);
    void finalize(uint8_t out[32]);
    static void hash(const void* data, size_t len, uint8_t out[32]);

  private:
    uint64_t A_[25];
    uint8_t buf_[136];
    size_t buf_len_;

    static void keccakf1600(uint64_t A[25]);
    static inline uint64_t le64dec(const void* buf);
    static inline void le64enc(void* buf, uint64_t v);
    static inline uint64_t rotl64(uint64_t x, int n);
};

} // namespace crypto
