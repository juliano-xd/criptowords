#pragma once
#include <cstdint>
#include <cstddef>
#include "sha512.hpp"

namespace crypto {

class HMAC_SHA512 {
  public:
    void init(const uint8_t* key, size_t key_len);
    void update(const uint8_t* data, size_t len);
    void finalize(uint8_t* out);
    void reset_inner();

  public:
    SHA512 inner_;
    SHA512 outer_base_;
    SHA512 inner_base_;
};

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len);

} // namespace crypto
