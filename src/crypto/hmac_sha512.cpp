#include "../../include/crypto/hmac_sha512.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include "../../include/crypto/pbkdf2_simd.hpp"

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || \
    (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
#include <arm_neon.h>

#if defined(__clang__)
__attribute__((target("sha3")))
#else
__attribute__((target("arch=armv8.2-a+sha3")))
#endif
static void pbkdf2_hmac_sha512_arm64_fused(
    const std::uint64_t* in_iv,
    const std::uint64_t* out_iv,
    std::uint64_t* U_words,
    std::uint64_t* T_words,
    int iterations) noexcept {
    using pbkdf2_simd_detail::K512;

    uint64x2_t u0 = vld1q_u64(U_words + 0);
    uint64x2_t u1 = vld1q_u64(U_words + 2);
    uint64x2_t u2 = vld1q_u64(U_words + 4);
    uint64x2_t u3 = vld1q_u64(U_words + 6);

    uint64x2_t T0 = u0, T1 = u1, T2 = u2, T3 = u3;

    const uint64x2_t in_iv0 = vld1q_u64(in_iv + 0);
    const uint64x2_t in_iv1 = vld1q_u64(in_iv + 2);
    const uint64x2_t in_iv2 = vld1q_u64(in_iv + 4);
    const uint64x2_t in_iv3 = vld1q_u64(in_iv + 6);

    const uint64x2_t out_iv0 = vld1q_u64(out_iv + 0);
    const uint64x2_t out_iv1 = vld1q_u64(out_iv + 2);
    const uint64x2_t out_iv2 = vld1q_u64(out_iv + 4);
    const uint64x2_t out_iv3 = vld1q_u64(out_iv + 6);

    alignas(16) constexpr std::uint64_t pad4_words[2] = {0x8000000000000000ULL, 0};
    alignas(16) constexpr std::uint64_t pad7_words[2] = {0, 1536ULL};
    const uint64x2_t pad4 = vld1q_u64(pad4_words);
    const uint64x2_t pad7 = vld1q_u64(pad7_words);
    const uint64x2_t zero = vdupq_n_u64(0);

#define SHA512_ROUND_ARM(wa, k_idx)                                                                  \
    do {                                                                                             \
        const uint64x2_t kw = vaddq_u64((wa), vld1q_u64(K512 + (k_idx)));                            \
        uint64x2_t v = vaddq_u64(vextq_u64(kw, kw, 1), q3);                                          \
        v = vsha512hq_u64(v, vextq_u64(q2, q3, 1), vextq_u64(q1, q2, 1));                             \
        const uint64x2_t next_q3 = vsha512h2q_u64(v, q1, q0);                                        \
        q1 = vaddq_u64(q1, v);                                                                       \
        q0 = q1;                                                                                     \
        q1 = q2;                                                                                     \
        q2 = q3;                                                                                     \
        q3 = next_q3;                                                                                \
    } while (false)

#define SHA512_SU_ARM(wa, wb, wc, wd, we)                                                            \
    do {                                                                                             \
        (wa) = vsha512su1q_u64(vsha512su0q_u64((wa), (wb)), (wc), vextq_u64((wd), (we), 1));          \
    } while (false)

    for (int it = 1; it < iterations; ++it) {
        // HMAC inner: SHA512(ipad_state, U_previous[64]).
        uint64x2_t w0 = u0, w1 = u1, w2 = u2, w3 = u3;
        uint64x2_t w4 = pad4, w5 = zero, w6 = zero, w7 = pad7;
        uint64x2_t q0 = in_iv0, q1 = in_iv1, q2 = in_iv2, q3 = in_iv3;

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

        u0 = vaddq_u64(q0, in_iv0);
        u1 = vaddq_u64(q1, in_iv1);
        u2 = vaddq_u64(q2, in_iv2);
        u3 = vaddq_u64(q3, in_iv3);

        // HMAC outer: SHA512(opad_state, inner_digest[64]).
        w0 = u0; w1 = u1; w2 = u2; w3 = u3;
        w4 = pad4; w5 = zero; w6 = zero; w7 = pad7;
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

        u0 = vaddq_u64(q0, out_iv0);
        u1 = vaddq_u64(q1, out_iv1);
        u2 = vaddq_u64(q2, out_iv2);
        u3 = vaddq_u64(q3, out_iv3);

        T0 = veorq_u64(T0, u0);
        T1 = veorq_u64(T1, u1);
        T2 = veorq_u64(T2, u2);
        T3 = veorq_u64(T3, u3);
    }

#undef SHA512_ROUND_ARM
#undef SHA512_SU_ARM

    vst1q_u64(T_words + 0, T0);
    vst1q_u64(T_words + 2, T1);
    vst1q_u64(T_words + 4, T2);
    vst1q_u64(T_words + 6, T3);
}
#endif

namespace crypto {

void pbkdf2_hmac_sha512(const char* password, std::size_t password_len,
                        const std::uint8_t* salt, std::size_t salt_len, int iterations,
                        std::uint8_t* out, std::size_t out_len) {
    using pbkdf2_simd_detail::bswap64;
    using pbkdf2_simd_detail::load_be64;
    constexpr std::size_t HASH_LEN = SHA512::digest_size;

    if (out_len == 0)
        return;
    if (iterations <= 0 || out == nullptr || (password_len != 0 && password == nullptr) ||
        (salt_len != 0 && salt == nullptr) || salt_len > std::numeric_limits<std::size_t>::max() - 4)
        return;

    // Mantém o caminho comum sem heap; salts longos usam fallback dinâmico em vez de truncamento.
    alignas(64) std::array<std::uint8_t, 256> local_salt_and_be4{};
    std::vector<std::uint8_t> dynamic_salt_and_be4;
    std::uint8_t* salt_and_be4 = local_salt_and_be4.data();
    if (salt_len > local_salt_and_be4.size() - 4) {
        dynamic_salt_and_be4.resize(salt_len + 4);
        salt_and_be4 = dynamic_salt_and_be4.data();
    }
    if (salt_len != 0)
        std::memcpy(salt_and_be4, salt, salt_len);

    const std::size_t u1_msg_len = salt_len + 4;
    std::size_t out_done = 0;
    std::uint32_t block_index = 1;

    while (out_done < out_len) {
        salt_and_be4[salt_len + 0] = static_cast<std::uint8_t>(block_index >> 24);
        salt_and_be4[salt_len + 1] = static_cast<std::uint8_t>(block_index >> 16);
        salt_and_be4[salt_len + 2] = static_cast<std::uint8_t>(block_index >> 8);
        salt_and_be4[salt_len + 3] = static_cast<std::uint8_t>(block_index);

        alignas(64) std::array<std::uint8_t, HASH_LEN> U{};
        HMAC_SHA512 h1;
        h1.preset(password, password_len, u1_msg_len);
        h1.complete(salt_and_be4, u1_msg_len, U);

        alignas(64) std::array<std::uint64_t, 8> T_words{};
        if (iterations == 1) {
            for (std::size_t i = 0; i < T_words.size(); ++i)
                T_words[i] = load_be64(U.data() + i * sizeof(std::uint64_t));
        } else {
            const std::uint64_t* const in_iv = h1.inner_state();
            const std::uint64_t* const out_iv = h1.outer_state();

            alignas(64) std::array<std::uint64_t, 8> U_words{};
            for (std::size_t i = 0; i < U_words.size(); ++i) {
                U_words[i] = load_be64(U.data() + i * sizeof(std::uint64_t));
                T_words[i] = U_words[i];
            }

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || \
    (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
            if (SHA512::has_native_sha512()) {
                pbkdf2_hmac_sha512_arm64_fused(in_iv, out_iv, U_words.data(), T_words.data(), iterations);
            } else
#endif
            {
                alignas(64) std::array<std::uint64_t, 16> W{};
                for (int it = 1; it < iterations; ++it) {
                    std::copy_n(U_words.data(), U_words.size(), W.data());
                    SHA512::compress_padded_block64(in_iv, W.data(), U_words.data());

                    std::copy_n(U_words.data(), U_words.size(), W.data());
                    SHA512::compress_padded_block64(out_iv, W.data(), U_words.data());

                    for (std::size_t i = 0; i < T_words.size(); ++i)
                        T_words[i] ^= U_words[i];
                }
            }
        }

        const std::size_t to_copy = std::min(HASH_LEN, out_len - out_done);
        alignas(64) std::array<std::uint8_t, HASH_LEN> T_out{};
        for (std::size_t i = 0; i < T_words.size(); ++i) {
            const std::uint64_t be = bswap64(T_words[i]);
            std::memcpy(T_out.data() + i * sizeof(be), &be, sizeof(be));
        }
        std::memcpy(out + out_done, T_out.data(), to_copy);
        out_done += to_copy;

        if (out_done == out_len)
            break;
        if (block_index == std::numeric_limits<std::uint32_t>::max())
            return;
        ++block_index;
    }
}

}  // namespace crypto
