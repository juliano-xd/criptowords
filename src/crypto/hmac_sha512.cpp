#include "../../include/crypto/hmac_sha512.hpp"

#include <immintrin.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include "../../include/crypto/pbkdf2_simd.hpp"

namespace crypto {

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len, int iterations,
                        uint8_t* out, size_t out_len) {
    static constexpr size_t HASH_LEN = 64;

    if (salt_len > 252)
        salt_len = 252;
    const size_t u1_msg_len = salt_len + 4;

    uint8_t salt_and_be4[256];
    if (salt_len != 0)
        std::memcpy(salt_and_be4, salt, salt_len);
    salt_and_be4[salt_len + 0] = 0;
    salt_and_be4[salt_len + 1] = 0;
    salt_and_be4[salt_len + 2] = 0;
    salt_and_be4[salt_len + 3] = 1;

    alignas(64) std::array<uint8_t, HASH_LEN> U;

    HMAC_SHA512 h1;
    h1.preset(password, password_len, u1_msg_len);
    h1.complete(salt_and_be4, u1_msg_len, U);

    if (iterations <= 1) {
        std::memcpy(out, U.data(), std::min<size_t>(HASH_LEN, out_len));
        return;
    }

    const uint64_t* in_iv = h1.inner_state();
    const uint64_t* out_iv = h1.outer_state();

    alignas(64) uint64_t T_words[8];
    alignas(64) uint64_t U_words[8];
#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        uint64_t v = pbkdf2_simd_detail::load_be64(U.data() + i * 8);
        T_words[i] = v;
        U_words[i] = v;
    }

#if defined(__AVX2__)
    __m256i t0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(T_words));
    __m256i t1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(T_words + 4));
#endif

    alignas(64) uint64_t W[16];
    for (int it = 1; it < iterations; ++it) {
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            W[i] = U_words[i];
        SHA512::compress_padded_block64(in_iv, W, U_words);

#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            W[i] = U_words[i];
        SHA512::compress_padded_block64(out_iv, W, U_words);

#if defined(__AVX2__)
        __m256i u0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(U_words));
        __m256i u1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(U_words + 4));
        t0 = _mm256_xor_si256(t0, u0);
        t1 = _mm256_xor_si256(t1, u1);
#else
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            T_words[i] ^= U_words[i];
#endif
    }

#if defined(__AVX2__)
    _mm256_store_si256(reinterpret_cast<__m256i*>(T_words), t0);
    _mm256_store_si256(reinterpret_cast<__m256i*>(T_words + 4), t1);
#endif

    alignas(64) uint8_t T_out[HASH_LEN];
    for (int i = 0; i < 8; ++i) {
        uint64_t b = pbkdf2_simd_detail::bswap64(T_words[i]);
        std::memcpy(T_out + i * 8, &b, 8);
    }
    std::memcpy(out, T_out, std::min<size_t>(HASH_LEN, out_len));
}

}  // namespace crypto
