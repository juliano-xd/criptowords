#include "../../include/crypto/hmac_sha512.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include "../../include/crypto/pbkdf2_simd.hpp"

namespace crypto {

// PBKDF2-HMAC-SHA512 com out_len variável (suporta blocos múltiplos via
// contador BE de 32 bits no final do salt). Reorganizado para evitar
// alocação por bloco.
void pbkdf2_hmac_sha512(const char* password, size_t password_len,
                        const uint8_t* salt, size_t salt_len, int iterations,
                        uint8_t* out, size_t out_len) {
    static constexpr size_t HASH_LEN = 64;

    if (out_len == 0) return;
    if (salt_len > 252) salt_len = 252;

    const size_t u1_msg_len = salt_len + 4;

    alignas(64) uint8_t salt_and_be4[256];
    if (salt_len != 0) std::memcpy(salt_and_be4, salt, salt_len);

    size_t out_done = 0;
    uint32_t block_index = 1;

    while (out_done < out_len) {
        // Bloco BE32(block_index) concatenado ao salt.
        salt_and_be4[salt_len + 0] = static_cast<uint8_t>(block_index >> 24);
        salt_and_be4[salt_len + 1] = static_cast<uint8_t>(block_index >> 16);
        salt_and_be4[salt_len + 2] = static_cast<uint8_t>(block_index >> 8);
        salt_and_be4[salt_len + 3] = static_cast<uint8_t>(block_index);

        alignas(64) std::array<uint8_t, HASH_LEN> U;
        HMAC_SHA512 h1;
        h1.preset(password, password_len, u1_msg_len);
        h1.complete(salt_and_be4, u1_msg_len, U);

        alignas(64) uint64_t T_words[8];

        if (iterations <= 1) {
            for (int i = 0; i < 8; ++i)
                T_words[i] = pbkdf2_simd_detail::load_be64(U.data() + i * 8);
        } else {
            const uint64_t* in_iv  = h1.inner_state();
            const uint64_t* out_iv = h1.outer_state();

            alignas(64) uint64_t U_words[8];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                uint64_t v = pbkdf2_simd_detail::load_be64(U.data() + i * 8);
                T_words[i] = v;
                U_words[i] = v;
            }

            alignas(64) uint64_t W[16];
            for (int it = 1; it < iterations; ++it) {
#pragma GCC unroll 8
                for (int i = 0; i < 8; ++i) W[i] = U_words[i];
                SHA512::compress_padded_block64(in_iv, W, U_words);

#pragma GCC unroll 8
                for (int i = 0; i < 8; ++i) W[i] = U_words[i];
                SHA512::compress_padded_block64(out_iv, W, U_words);

#pragma GCC unroll 8
                for (int i = 0; i < 8; ++i) T_words[i] ^= U_words[i];
            }
        }

        const size_t to_copy = std::min(HASH_LEN, out_len - out_done);
        alignas(64) uint8_t T_out[HASH_LEN];
        for (int i = 0; i < 8; ++i) {
            const uint64_t b = pbkdf2_simd_detail::bswap64(T_words[i]);
            std::memcpy(T_out + i * 8, &b, 8);
        }
        std::memcpy(out + out_done, T_out, to_copy);
        out_done += to_copy;
        ++block_index;
    }
}

}  // namespace crypto
