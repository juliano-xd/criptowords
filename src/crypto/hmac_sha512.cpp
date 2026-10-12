#include "../../include/crypto/hmac_sha512.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include "../../include/crypto/pbkdf2_simd.hpp"

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
#include <arm_neon.h>

#if defined(__clang__)
__attribute__((target("sha3")))
#else
__attribute__((target("arch=armv8.2-a+sha3")))
#endif
static void pbkdf2_hmac_sha512_arm64_fused(
    const uint64_t* in_iv, const uint64_t* out_iv,
    uint64_t* U_words, uint64_t* T_words, int iterations) noexcept {

    // Tabela K em cache L1 para os ciclos (100% nativa)
    static constexpr uint64_t K_512[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    // Fixar variáveis nas ALUs NEON
    uint64x2_t u0 = vld1q_u64(U_words + 0);
    uint64x2_t u1 = vld1q_u64(U_words + 2);
    uint64x2_t u2 = vld1q_u64(U_words + 4);
    uint64x2_t u3 = vld1q_u64(U_words + 6);

    uint64x2_t T0 = u0; uint64x2_t T1 = u1; uint64x2_t T2 = u2; uint64x2_t T3 = u3;

    uint64x2_t in_iv0 = vld1q_u64(in_iv + 0); uint64x2_t in_iv1 = vld1q_u64(in_iv + 2);
    uint64x2_t in_iv2 = vld1q_u64(in_iv + 4); uint64x2_t in_iv3 = vld1q_u64(in_iv + 6);

    uint64x2_t out_iv0 = vld1q_u64(out_iv + 0); uint64x2_t out_iv1 = vld1q_u64(out_iv + 2);
    uint64x2_t out_iv2 = vld1q_u64(out_iv + 4); uint64x2_t out_iv3 = vld1q_u64(out_iv + 6);

    alignas(16) uint64_t buf4_in[2] = {0x8000000000000000ULL, 0};
    uint64x2_t pad4 = vld1q_u64(buf4_in);
    alignas(16) uint64_t buf7_in[2] = {0, 1536ULL};
    uint64x2_t pad7_in = vld1q_u64(buf7_in);

    #define SHA512_ROUND_ARM(wa, k_idx) \
        do { \
            uint64x2_t kw = vaddq_u64(wa, vld1q_u64(K_512 + k_idx)); \
            uint64x2_t v = vaddq_u64(vextq_u64(kw, kw, 1), q3); \
            v = vsha512hq_u64(v, vextq_u64(q2, q3, 1), vextq_u64(q1, q2, 1)); \
            uint64x2_t next_q3 = vsha512h2q_u64(v, q1, q0); \
            q1 = vaddq_u64(q1, v); \
            q0 = q1; q1 = q2; q2 = q3; q3 = next_q3; \
        } while (0)

    #define SHA512_SU_ARM(wa, wb, wc, wd, we) \
        do { wa = vsha512su1q_u64(vsha512su0q_u64(wa, wb), wc, vextq_u64(wd, we, 1)); } while (0)

    for (int it = 1; it < iterations; ++it) {
        // --- HASH INTERNO ---
        uint64x2_t w0 = u0; uint64x2_t w1 = u1; uint64x2_t w2 = u2; uint64x2_t w3 = u3;
        uint64x2_t w4 = pad4; uint64x2_t w5 = vdupq_n_u64(0); uint64x2_t w6 = vdupq_n_u64(0); uint64x2_t w7 = pad7_in;
        uint64x2_t q0 = in_iv0; uint64x2_t q1 = in_iv1; uint64x2_t q2 = in_iv2; uint64x2_t q3 = in_iv3;

        SHA512_ROUND_ARM(w0, 0);  SHA512_ROUND_ARM(w1, 2);
        SHA512_ROUND_ARM(w2, 4);  SHA512_ROUND_ARM(w3, 6);
        SHA512_ROUND_ARM(w4, 8);  SHA512_ROUND_ARM(w5, 10);
        SHA512_ROUND_ARM(w6, 12); SHA512_ROUND_ARM(w7, 14);

        for (unsigned t = 16; t < 80; t += 16) {
            SHA512_SU_ARM(w0, w1, w7, w4, w5); SHA512_ROUND_ARM(w0, t + 0);
            SHA512_SU_ARM(w1, w2, w0, w5, w6); SHA512_ROUND_ARM(w1, t + 2);
            SHA512_SU_ARM(w2, w3, w1, w6, w7); SHA512_ROUND_ARM(w2, t + 4);
            SHA512_SU_ARM(w3, w4, w2, w7, w0); SHA512_ROUND_ARM(w3, t + 6);
            SHA512_SU_ARM(w4, w5, w3, w0, w1); SHA512_ROUND_ARM(w4, t + 8);
            SHA512_SU_ARM(w5, w6, w4, w1, w2); SHA512_ROUND_ARM(w5, t + 10);
            SHA512_SU_ARM(w6, w7, w5, w2, w3); SHA512_ROUND_ARM(w6, t + 12);
            SHA512_SU_ARM(w7, w0, w6, w3, w4); SHA512_ROUND_ARM(w7, t + 14);
        }

        u0 = vaddq_u64(q0, in_iv0); u1 = vaddq_u64(q1, in_iv1);
        u2 = vaddq_u64(q2, in_iv2); u3 = vaddq_u64(q3, in_iv3);

        // --- HASH EXTERNO ---
        w0 = u0; w1 = u1; w2 = u2; w3 = u3;
        w4 = pad4; w5 = vdupq_n_u64(0); w6 = vdupq_n_u64(0); w7 = pad7_in;
        q0 = out_iv0; q1 = out_iv1; q2 = out_iv2; q3 = out_iv3;

        SHA512_ROUND_ARM(w0, 0);  SHA512_ROUND_ARM(w1, 2);
        SHA512_ROUND_ARM(w2, 4);  SHA512_ROUND_ARM(w3, 6);
        SHA512_ROUND_ARM(w4, 8);  SHA512_ROUND_ARM(w5, 10);
        SHA512_ROUND_ARM(w6, 12); SHA512_ROUND_ARM(w7, 14);

        for (unsigned t = 16; t < 80; t += 16) {
            SHA512_SU_ARM(w0, w1, w7, w4, w5); SHA512_ROUND_ARM(w0, t + 0);
            SHA512_SU_ARM(w1, w2, w0, w5, w6); SHA512_ROUND_ARM(w1, t + 2);
            SHA512_SU_ARM(w2, w3, w1, w6, w7); SHA512_ROUND_ARM(w2, t + 4);
            SHA512_SU_ARM(w3, w4, w2, w7, w0); SHA512_ROUND_ARM(w3, t + 6);
            SHA512_SU_ARM(w4, w5, w3, w0, w1); SHA512_ROUND_ARM(w4, t + 8);
            SHA512_SU_ARM(w5, w6, w4, w1, w2); SHA512_ROUND_ARM(w5, t + 10);
            SHA512_SU_ARM(w6, w7, w5, w2, w3); SHA512_ROUND_ARM(w6, t + 12);
            SHA512_SU_ARM(w7, w0, w6, w3, w4); SHA512_ROUND_ARM(w7, t + 14);
        }

        u0 = vaddq_u64(q0, out_iv0); u1 = vaddq_u64(q1, out_iv1);
        u2 = vaddq_u64(q2, out_iv2); u3 = vaddq_u64(q3, out_iv3);

        T0 = veorq_u64(T0, u0); T1 = veorq_u64(T1, u1);
        T2 = veorq_u64(T2, u2); T3 = veorq_u64(T3, u3);
    }

    #undef SHA512_ROUND_ARM
    #undef SHA512_SU_ARM

    vst1q_u64(T_words + 0, T0); vst1q_u64(T_words + 2, T1);
    vst1q_u64(T_words + 4, T2); vst1q_u64(T_words + 6, T3);
}
#endif

namespace crypto {

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

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
            if (SHA512::has_native_sha512()) {
                pbkdf2_hmac_sha512_arm64_fused(in_iv, out_iv, U_words, T_words, iterations);
            } else {
#endif
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
#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
            }
#endif
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
