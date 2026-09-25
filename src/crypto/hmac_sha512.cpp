#include "../../include/crypto/hmac_sha512.hpp"
#include "../../include/crypto/pbkdf2_simd.hpp"
#include "../../include/math/UInt.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace crypto {

[[gnu::always_inline]]
static inline void sha512_padded_block64_scalar(const uint64_t iv[8], uint64_t W[16], uint64_t out[8]) {
    constexpr uint64_t K_FUSED_8  = 0xd807aa98a3030242ULL + 0x8000000000000000ULL;
    constexpr uint64_t K_FUSED_15 = 0xc19bf174cf692694ULL + 0x0000000000000600ULL;
    constexpr uint64_t C_S1_W15   = 0x00c0000000003018ULL;
    constexpr uint64_t C_S0_W8    = 0x4180000000000000ULL;
    constexpr uint64_t C_S0_W15   = 0x000000000000030aULL;
    constexpr uint64_t C_W8       = 0x8000000000000000ULL;
    constexpr uint64_t C_W15      = 0x0000000000000600ULL;

    #define ROR64(x, n) std::rotr(x, n)
    #define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
    #define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
    #define S0_64(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
    #define S1_64(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
    #define s0_64(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
    #define s1_64(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

    uint64_t a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];

    #define STEP_SCALAR(k_term, w_val) do { \
        uint64_t T1 = (h) + (k_term) + (w_val) + S1_64(e) + CH64(e, f, g); \
        uint64_t T2 = S0_64(a) + MAJ64(a, b, c); \
        h = g; g = f; f = e; \
        e = d + T1; \
        d = c; c = b; b = a; \
        a = T1 + T2; \
    } while(0)

    #define STEP_FUSED_SCALAR(k_fused) do { \
        uint64_t T1 = (h) + (k_fused) + S1_64(e) + CH64(e, f, g); \
        uint64_t T2 = S0_64(a) + MAJ64(a, b, c); \
        h = g; g = f; f = e; \
        e = d + T1; \
        d = c; c = b; b = a; \
        a = T1 + T2; \
    } while(0)

    const auto* k_tbl = pbkdf2_simd_detail::K512;

    STEP_SCALAR(k_tbl[0], W[0]);  W[0] += s0_64(W[1]);
    STEP_SCALAR(k_tbl[1], W[1]);  W[1] += s0_64(W[2]) + C_S1_W15;
    STEP_SCALAR(k_tbl[2], W[2]);  W[2] += s0_64(W[3]) + s1_64(W[0]);
    STEP_SCALAR(k_tbl[3], W[3]);  W[3] += s0_64(W[4]) + s1_64(W[1]);
    STEP_SCALAR(k_tbl[4], W[4]);  W[4] += s0_64(W[5]) + s1_64(W[2]);
    STEP_SCALAR(k_tbl[5], W[5]);  W[5] += s0_64(W[6]) + s1_64(W[3]);
    STEP_SCALAR(k_tbl[6], W[6]);  W[6] += s0_64(W[7]) + C_W15 + s1_64(W[4]);
    STEP_SCALAR(k_tbl[7], W[7]);  W[7] += C_S0_W8 + W[0] + s1_64(W[5]);

    STEP_FUSED_SCALAR(K_FUSED_8);  W[8]  = C_W8 + W[1] + s1_64(W[6]);
    STEP_FUSED_SCALAR(k_tbl[9]);   W[9]  = W[2] + s1_64(W[7]);
    STEP_FUSED_SCALAR(k_tbl[10]);  W[10] = W[3] + s1_64(W[8]);
    STEP_FUSED_SCALAR(k_tbl[11]);  W[11] = W[4] + s1_64(W[9]);
    STEP_FUSED_SCALAR(k_tbl[12]);  W[12] = W[5] + s1_64(W[10]);
    STEP_FUSED_SCALAR(k_tbl[13]);  W[13] = W[6] + s1_64(W[11]);
    STEP_FUSED_SCALAR(k_tbl[14]);  W[14] = C_S0_W15 + W[7] + s1_64(W[12]);
    STEP_FUSED_SCALAR(K_FUSED_15); W[15] = C_W15 + s0_64(W[0]) + W[8] + s1_64(W[13]);

    #undef STEP_SCALAR
    #undef STEP_FUSED_SCALAR

    #pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            uint64_t T1 = h + k_tbl[r*16+i] + W[i] + S1_64(e) + CH64(e, f, g);
            uint64_t T2 = S0_64(a) + MAJ64(a, b, c);
            h = g; g = f; f = e;
            e = d + T1;
            d = c; c = b; b = a;
            a = T1 + T2;
            if (r < 4) {
                W[i] += s0_64(W[(i+1)&15]) + W[(i+9)&15] + s1_64(W[(i+14)&15]);
            }
        }
    }

    out[0] = iv[0] + a; out[1] = iv[1] + b;
    out[2] = iv[2] + c; out[3] = iv[3] + d;
    out[4] = iv[4] + e; out[5] = iv[5] + f;
    out[6] = iv[6] + g; out[7] = iv[7] + h;

    #undef ROR64
    #undef CH64
    #undef MAJ64
    #undef S0_64
    #undef S1_64
    #undef s0_64
    #undef s1_64
}

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

    HMAC_SHA512 h1;
    h1.preset(password, password_len, u1_msg_len);
    h1.complete(salt_and_be4, u1_msg_len, U);

    if (iterations <= 1) {
        std::memcpy(out, U.data(), std::min<size_t>(HASH_LEN, out_len));
        return;
    }

    HMAC_SHA512 h_iter;
    h_iter.preset(password, password_len, HASH_LEN);
    const uint64_t* in_iv = h_iter.inner_state();
    const uint64_t* out_iv = h_iter.outer_state();

    uint64_t T_words[8];
    uint64_t U_words[8];
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        uint64_t v = pbkdf2_simd_detail::load_be64(U.data() + i * 8);
        T_words[i] = v;
        U_words[i] = v;
    }

    uint64_t W[16];
    for (int it = 1; it < iterations; ++it) {
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) W[i] = U_words[i];
        sha512_padded_block64_scalar(in_iv, W, U_words);

        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) W[i] = U_words[i];
        sha512_padded_block64_scalar(out_iv, W, U_words);

#if defined(__AVX2__)
        __m256i t0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(T_words));
        __m256i t1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(T_words + 4));
        __m256i u0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(U_words));
        __m256i u1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(U_words + 4));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(T_words), _mm256_xor_si256(t0, u0));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(T_words + 4), _mm256_xor_si256(t1, u1));
#else
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) T_words[i] ^= U_words[i];
#endif
    }

    alignas(64) uint8_t T_out[HASH_LEN];
    for (int i = 0; i < 8; ++i) {
        uint64_t b = pbkdf2_simd_detail::bswap64(T_words[i]);
        std::memcpy(T_out + i * 8, &b, 8);
    }
    std::memcpy(out, T_out, std::min<size_t>(HASH_LEN, out_len));
}

} // namespace crypto
