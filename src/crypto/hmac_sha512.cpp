#include "../../include/crypto/hmac_sha512.hpp"
#include "../../include/math/UInt.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace crypto {

void pbkdf2_hmac_sha512(const char* password, size_t password_len,
                        const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len) {
    static constexpr size_t HASH_LEN = 64;

    if (salt_len > 252) salt_len = 252;
    const size_t u1_msg_len = salt_len + 4;

    uint8_t salt_and_be4[256];
    if (salt_len != 0) std::memcpy(salt_and_be4, salt, salt_len);
    salt_and_be4[salt_len + 0] = 0;
    salt_and_be4[salt_len + 1] = 0;
    salt_and_be4[salt_len + 2] = 0;
    salt_and_be4[salt_len + 3] = 1;

    alignas(64) std::array<uint8_t, HASH_LEN> U;
    alignas(64) std::array<uint8_t, HASH_LEN> T;

    HMAC_SHA512 h1;
    h1.preset(password, password_len, u1_msg_len);
    h1.complete(salt_and_be4, u1_msg_len, U);
    T = U;

    if (iterations > 1) {
        HMAC_SHA512 h_iter;
        h_iter.preset(password, password_len, HASH_LEN);

        auto* t_words = reinterpret_cast<uint64_t*>(T.data());
        const auto* u_words = reinterpret_cast<const uint64_t*>(U.data());

        for (int i = 1; i < iterations; ++i) {
            h_iter.complete(U.data(), HASH_LEN, U);
            for (int j = 0; j < 8; ++j) {
                t_words[j] ^= u_words[j];
            }
        }
    }

    std::memcpy(out, T.data(), std::min<size_t>(HASH_LEN, out_len));
}

} // namespace crypto
