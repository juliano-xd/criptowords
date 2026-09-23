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

        UInt<8> T_u;
        std::memcpy(T_u.bits.data(), T.data(), 64);
        T_u.set_mode(Backend::SIMD);

        for (int i = 1; i < iterations; ++i) {
            h_iter.complete(U.data(), HASH_LEN, U);
            UInt<8> U_u;
            std::memcpy(U_u.bits.data(), U.data(), 64);
            T_u ^= U_u;
        }
        std::memcpy(T.data(), T_u.bits.data(), 64);
    }

    std::memcpy(out, T.data(), std::min<size_t>(HASH_LEN, out_len));
}

} // namespace crypto
