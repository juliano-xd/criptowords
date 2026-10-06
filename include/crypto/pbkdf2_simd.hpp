#pragma once

#include <bit>
#include <cstdint>
#include <cstring>

#include "../simd/cpu_features.hpp"
#include "sha512.hpp"

// Parte comum (arch-independent)
namespace pbkdf2_simd_detail {

alignas(64) inline constexpr uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

inline constexpr uint64_t IV[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                                   0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                                   0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

[[gnu::always_inline]] inline uint64_t bswap64(uint64_t x) noexcept {
    if constexpr (std::endian::native == std::endian::little)
        return __builtin_bswap64(x);
    else
        return x;
}

[[gnu::always_inline]] inline uint64_t load_be64(const uint8_t* p) noexcept {
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    if constexpr (std::endian::native == std::endian::little)
        v = __builtin_bswap64(v);
    return v;
}

template <size_t LANES>
inline void prepare_pads(const void* const* passes, const size_t* lens, uint64_t W_ipad[16][LANES],
                         uint64_t W_opad[16][LANES]) noexcept {
    constexpr uint64_t IPAD_MASK = 0x3636363636363636ULL;
    constexpr uint64_t OPAD_MASK = 0x5c5c5c5c5c5c5c5cULL;

    for (size_t l = 0; l < LANES; ++l) {
        const size_t len = lens[l];
        if (__builtin_expect(len > 128, 0)) {
            alignas(16) uint8_t K[128] = {};
            crypto::SHA512::hash(passes[l], len, K);
            for (int w = 0; w < 16; ++w) {
                uint64_t v;
                std::memcpy(&v, K + w * 8, 8);
                if constexpr (std::endian::native == std::endian::little)
                    v = __builtin_bswap64(v);
                W_ipad[w][l] = v ^ IPAD_MASK;
                W_opad[w][l] = v ^ OPAD_MASK;
            }
        } else {
            const auto* p = static_cast<const uint8_t*>(passes[l]);
            const size_t full_words = len / 8;
            for (size_t w = 0; w < full_words; ++w) {
                uint64_t v;
                std::memcpy(&v, p + w * 8, 8);
                if constexpr (std::endian::native == std::endian::little)
                    v = __builtin_bswap64(v);
                W_ipad[w][l] = v ^ IPAD_MASK;
                W_opad[w][l] = v ^ OPAD_MASK;
            }
            size_t w = full_words;
            const size_t rem = len % 8;
            if (rem > 0) {
                uint64_t v = 0;
                std::memcpy(&v, p + w * 8, rem);
                if constexpr (std::endian::native == std::endian::little)
                    v = __builtin_bswap64(v);
                W_ipad[w][l] = v ^ IPAD_MASK;
                W_opad[w][l] = v ^ OPAD_MASK;
                ++w;
            }
            for (; w < 16; ++w) {
                W_ipad[w][l] = IPAD_MASK;
                W_opad[w][l] = OPAD_MASK;
            }
        }
    }
}

inline bool prepare_salt_W(const uint8_t* salt, size_t salt_len, uint64_t W[16]) noexcept {
    if (salt_len > 107) {
        for (int i = 0; i < 16; ++i) W[i] = 0;
        return false;
    }
    alignas(16) uint8_t buf[128] = {};
    if (salt_len) std::memcpy(buf, salt, salt_len);
    buf[salt_len + 3] = 1;
    buf[salt_len + 4] = 0x80;
    const size_t words_needed = (salt_len + 5 + 7) / 8;
    for (size_t i = 0; i < words_needed; ++i) W[i] = load_be64(buf + i * 8);
    for (size_t i = words_needed; i < 15; ++i) W[i] = 0;
    W[15] = static_cast<uint64_t>(128 + salt_len + 4) * 8;
    return true;
}

inline void precompute_kw_salt_from_W(const uint64_t salt_W[16], uint64_t kw_salt[80]) noexcept {
    uint64_t W[80];
    for (int i = 0; i < 16; ++i) W[i] = salt_W[i];
    for (int i = 16; i < 80; ++i) {
        const uint64_t s0 = std::rotr(W[i - 15], 1) ^ std::rotr(W[i - 15], 8) ^ (W[i - 15] >> 7);
        const uint64_t s1 = std::rotr(W[i - 2], 19) ^ std::rotr(W[i - 2], 61) ^ (W[i - 2] >> 6);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    for (int i = 0; i < 80; ++i) kw_salt[i] = K512[i] + W[i];
}

}  // namespace pbkdf2_simd_detail

// Backends x86 (SSE4.1 / AVX2 / AVX-512)
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#include <immintrin.h>

// SSE 4.1 — 4-way (2 grupos de 2 lanes, sem interleaving)
namespace pbkdf2_simd_detail {

struct DoubleWord {
    alignas(16) uint64_t v[2];
    constexpr DoubleWord(uint64_t x) : v{x, x} {}
    [[gnu::target("sse4.1")]]
    inline __m128i vec() const noexcept {
        __m128i r;
        std::memcpy(&r, v, sizeof(r));
        return r;
    }
    [[gnu::target("sse4.1")]]
    inline operator __m128i() const noexcept { return vec(); }
};

struct K512_SSE_Table {
    alignas(16) uint64_t data[80][2];
    constexpr K512_SSE_Table() : data{} {
        for (int i = 0; i < 80; ++i) {
            uint64_t v = K512[i];
            data[i][0] = v;
            data[i][1] = v;
        }
    }
};
inline constexpr K512_SSE_Table g_k512_sse_table{};

struct IV_SSE_Table {
    alignas(16) uint64_t data[8][2];
    constexpr IV_SSE_Table() : data{} {
        for (int i = 0; i < 8; ++i) {
            uint64_t v = IV[i];
            data[i][0] = v;
            data[i][1] = v;
        }
    }
};
inline constexpr IV_SSE_Table g_iv_sse_table{};

inline constexpr DoubleWord C_S1_W15_SSE{0x00c0000000003018ULL};
inline constexpr DoubleWord C_S0_W8_SSE{0x4180000000000000ULL};
inline constexpr DoubleWord C_S0_W15_SSE{0x000000000000030aULL};
inline constexpr DoubleWord C_W8_SSE{0x8000000000000000ULL};
inline constexpr DoubleWord C_W15_SSE{0x0000000000000600ULL};
inline constexpr DoubleWord K_FUSED_8_SSE{0xd807aa98a3030242ULL + 0x8000000000000000ULL};
inline constexpr DoubleWord K_FUSED_15_SSE{0xc19bf174cf692694ULL + 0x0000000000000600ULL};

}  // namespace pbkdf2_simd_detail

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline const __m128i* get_k512_sse() noexcept {
    return reinterpret_cast<const __m128i*>(pbkdf2_simd_detail::g_k512_sse_table.data);
}
[[gnu::target("sse4.1"), gnu::always_inline]]
static inline const __m128i* get_iv_sse() noexcept {
    return reinterpret_cast<const __m128i*>(pbkdf2_simd_detail::g_iv_sse_table.data);
}

alignas(16) static constexpr uint8_t SHUF_ROR8_SSE[16] = {1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8};

#define ROR128_64(x, n) _mm_xor_si128(_mm_srli_epi64(x, n), _mm_slli_epi64(x, 64 - (n)))
#define CH_SSE(x, y, z) _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z)))
#define MAJ_SSE(x, y, z) _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)))
#define S0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 28), ROR128_64(x, 34)), ROR128_64(x, 39))
#define S1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 14), ROR128_64(x, 18)), ROR128_64(x, 41))
#define s0_SSE(x)                                                                                                      \
    _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 1), _mm_shuffle_epi8(x, _mm_load_si128((const __m128i*)SHUF_ROR8_SSE))),  \
                  _mm_srli_epi64(x, 7))
#define s1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 19), ROR128_64(x, 61)), _mm_srli_epi64(x, 6))

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_block64_sse(const __m128i iv[8], __m128i W[16], __m128i out[8]) {
    __m128i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    const __m128i* k_tbl = get_k512_sse();
#pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m128i kw = _mm_add_epi64(k_tbl[r * 16 + i], W[i]);
            __m128i h_kw = _mm_add_epi64(h, kw);
            __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));
            __m128i T1 = _mm_add_epi64(h_kw, e_terms);
            __m128i T2 = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));
            h = g; g = f; f = e; e = _mm_add_epi64(d, T1);
            d = c; c = b; b = a; a = _mm_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm_add_epi64(_mm_add_epi64(W[i], W[(i + 9) & 15]),
                                     _mm_add_epi64(s0_SSE(W[(i + 1) & 15]), s1_SSE(W[(i + 14) & 15])));
            }
        }
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_padded_block64_sse(const __m128i iv[8], __m128i W[16], __m128i out[8]) {
    const __m128i C_S1_W15 = pbkdf2_simd_detail::C_S1_W15_SSE.vec();
    const __m128i C_S0_W8 = pbkdf2_simd_detail::C_S0_W8_SSE.vec();
    const __m128i C_S0_W15 = pbkdf2_simd_detail::C_S0_W15_SSE.vec();
    const __m128i C_W8 = pbkdf2_simd_detail::C_W8_SSE.vec();
    const __m128i C_W15 = pbkdf2_simd_detail::C_W15_SSE.vec();
    const __m128i K_FUSED_8 = pbkdf2_simd_detail::K_FUSED_8_SSE.vec();
    const __m128i K_FUSED_15 = pbkdf2_simd_detail::K_FUSED_15_SSE.vec();

    __m128i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    const __m128i* k_tbl = get_k512_sse();

#define STEP_SSE(k_term, w_val)                                                                                        \
    do {                                                                                                               \
        __m128i kw = _mm_add_epi64((k_term), (w_val));                                                                 \
        __m128i h_kw = _mm_add_epi64(h, kw);                                                                           \
        __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));                                                   \
        __m128i T1 = _mm_add_epi64(h_kw, e_terms);                                                                     \
        __m128i T2 = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));                                                       \
        h = g; g = f; f = e; e = _mm_add_epi64(d, T1);                                                                 \
        d = c; c = b; b = a; a = _mm_add_epi64(T1, T2);                                                                \
    } while (0)
#define STEP_FUSED_SSE(k_fused)                                                                                        \
    do {                                                                                                               \
        __m128i h_kw = _mm_add_epi64(h, (k_fused));                                                                    \
        __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));                                                   \
        __m128i T1 = _mm_add_epi64(h_kw, e_terms);                                                                     \
        __m128i T2 = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));                                                       \
        h = g; g = f; f = e; e = _mm_add_epi64(d, T1);                                                                 \
        d = c; c = b; b = a; a = _mm_add_epi64(T1, T2);                                                                \
    } while (0)

    STEP_SSE(k_tbl[0], W[0]); W[0] = _mm_add_epi64(W[0], s0_SSE(W[1]));
    STEP_SSE(k_tbl[1], W[1]); W[1] = _mm_add_epi64(W[1], _mm_add_epi64(s0_SSE(W[2]), C_S1_W15));
    STEP_SSE(k_tbl[2], W[2]); W[2] = _mm_add_epi64(W[2], _mm_add_epi64(s0_SSE(W[3]), s1_SSE(W[0])));
    STEP_SSE(k_tbl[3], W[3]); W[3] = _mm_add_epi64(W[3], _mm_add_epi64(s0_SSE(W[4]), s1_SSE(W[1])));
    STEP_SSE(k_tbl[4], W[4]); W[4] = _mm_add_epi64(W[4], _mm_add_epi64(s0_SSE(W[5]), s1_SSE(W[2])));
    STEP_SSE(k_tbl[5], W[5]); W[5] = _mm_add_epi64(W[5], _mm_add_epi64(s0_SSE(W[6]), s1_SSE(W[3])));
    STEP_SSE(k_tbl[6], W[6]); W[6] = _mm_add_epi64(W[6], _mm_add_epi64(_mm_add_epi64(s0_SSE(W[7]), C_W15), s1_SSE(W[4])));
    STEP_SSE(k_tbl[7], W[7]); W[7] = _mm_add_epi64(W[7], _mm_add_epi64(_mm_add_epi64(C_S0_W8, W[0]), s1_SSE(W[5])));

    STEP_FUSED_SSE(K_FUSED_8); W[8] = _mm_add_epi64(C_W8, _mm_add_epi64(W[1], s1_SSE(W[6])));
    STEP_FUSED_SSE(k_tbl[9]); W[9] = _mm_add_epi64(W[2], s1_SSE(W[7]));
    STEP_FUSED_SSE(k_tbl[10]); W[10] = _mm_add_epi64(W[3], s1_SSE(W[8]));
    STEP_FUSED_SSE(k_tbl[11]); W[11] = _mm_add_epi64(W[4], s1_SSE(W[9]));
    STEP_FUSED_SSE(k_tbl[12]); W[12] = _mm_add_epi64(W[5], s1_SSE(W[10]));
    STEP_FUSED_SSE(k_tbl[13]); W[13] = _mm_add_epi64(W[6], s1_SSE(W[11]));
    STEP_FUSED_SSE(k_tbl[14]); W[14] = _mm_add_epi64(C_S0_W15, _mm_add_epi64(W[7], s1_SSE(W[12])));
    STEP_FUSED_SSE(K_FUSED_15); W[15] = _mm_add_epi64(_mm_add_epi64(C_W15, s0_SSE(W[0])), _mm_add_epi64(W[8], s1_SSE(W[13])));

#undef STEP_SSE
#undef STEP_FUSED_SSE

#pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m128i kw = _mm_add_epi64(k_tbl[r * 16 + i], W[i]);
            __m128i h_kw = _mm_add_epi64(h, kw);
            __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));
            __m128i T1 = _mm_add_epi64(h_kw, e_terms);
            __m128i T2 = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));
            h = g; g = f; f = e; e = _mm_add_epi64(d, T1);
            d = c; c = b; b = a; a = _mm_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm_add_epi64(_mm_add_epi64(W[i], W[(i + 9) & 15]),
                                     _mm_add_epi64(s0_SSE(W[(i + 1) & 15]), s1_SSE(W[(i + 14) & 15])));
            }
        }
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void pbkdf2_2lane_fused_stream(const __m128i ipad_iv[8], const __m128i opad_iv[8],
                                             const __m128i initial_digest[8], __m128i T[8], uint32_t iterations) {
    __m128i W[16];
#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    uint32_t it = 1;
    for (; it + 4 <= iterations; it += 4) {
#pragma GCC unroll 4
        for (int j = 0; j < 4; ++j) {
            sha512_padded_block64_sse(ipad_iv, W, W);
            sha512_padded_block64_sse(opad_iv, W, W);
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) T[i] = _mm_xor_si128(T[i], W[i]);
        }
    }
    for (; it < iterations; ++it) {
        sha512_padded_block64_sse(ipad_iv, W, W);
        sha512_padded_block64_sse(opad_iv, W, W);
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) T[i] = _mm_xor_si128(T[i], W[i]);
    }
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_salt_fastforward_sse(const __m128i iv[8], const __m128i kw_salt_vec[80], __m128i out[8]) {
    __m128i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    for (int i = 0; i < 80; ++i) {
        __m128i kw = kw_salt_vec[i];
        __m128i h_kw = _mm_add_epi64(h, kw);
        __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));
        __m128i T1 = _mm_add_epi64(h_kw, e_terms);
        __m128i T2 = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));
        h = g; g = f; f = e; e = _mm_add_epi64(d, T1);
        d = c; c = b; b = a; a = _mm_add_epi64(T1, T2);
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_salt_fastforward_sse(const __m128i iv[8], const uint64_t kw_salt[80], __m128i out[8]) {
    alignas(16) __m128i kw_vec[80];
    for (int i = 0; i < 80; ++i) kw_vec[i] = _mm_set1_epi64x((long long)kw_salt[i]);
    sha512_salt_fastforward_sse(iv, kw_vec, out);
}

[[gnu::target("sse4.1")]]
inline void pbkdf2_hmac_sha512_4way_sse(const char* p1, size_t l1, const char* p2, size_t l2, const char* p3, size_t l3,
                                        const char* p4, size_t l4, const uint8_t* salt, size_t salt_len,
                                        uint32_t iterations, uint8_t out1[64], uint8_t out2[64], uint8_t out3[64],
                                        uint8_t out4[64], const uint64_t* precomputed_salt_blk64 = nullptr,
                                        const uint64_t* precomputed_kw_salt = nullptr,
                                        const void* precomputed_kw_salt_vec = nullptr) {
    using namespace pbkdf2_simd_detail;
    const void* passes[4] = {p1, p2, p3, p4};
    const size_t lens[4] = {l1, l2, l3, l4};
    alignas(16) uint64_t ipad_all[16][4], opad_all[16][4];
    prepare_pads<4>(passes, lens, ipad_all, opad_all);

    __m128i ipad_iv_lo[8], ipad_iv_hi[8], opad_iv_lo[8], opad_iv_hi[8], W[16];
    for (int i = 0; i < 16; ++i) W[i] = _mm_load_si128((const __m128i*)&ipad_all[i][0]);
    sha512_block64_sse(get_iv_sse(), W, ipad_iv_lo);
    for (int i = 0; i < 16; ++i) W[i] = _mm_load_si128((const __m128i*)&ipad_all[i][2]);
    sha512_block64_sse(get_iv_sse(), W, ipad_iv_hi);
    for (int i = 0; i < 16; ++i) W[i] = _mm_load_si128((const __m128i*)&opad_all[i][0]);
    sha512_block64_sse(get_iv_sse(), W, opad_iv_lo);
    for (int i = 0; i < 16; ++i) W[i] = _mm_load_si128((const __m128i*)&opad_all[i][2]);
    sha512_block64_sse(get_iv_sse(), W, opad_iv_hi);

    __m128i s_lo[8], s_hi[8];
    if (precomputed_kw_salt_vec) {
        const auto* kw_vec = static_cast<const __m128i*>(precomputed_kw_salt_vec);
        sha512_salt_fastforward_sse(ipad_iv_lo, kw_vec, s_lo);
        sha512_salt_fastforward_sse(ipad_iv_hi, kw_vec, s_hi);
    } else if (precomputed_kw_salt) {
        sha512_salt_fastforward_sse(ipad_iv_lo, precomputed_kw_salt, s_lo);
        sha512_salt_fastforward_sse(ipad_iv_hi, precomputed_kw_salt, s_hi);
    } else {
        uint64_t salt_W[16];
        if (precomputed_salt_blk64) for (int i = 0; i < 16; ++i) salt_W[i] = precomputed_salt_blk64[i];
        else (void)prepare_salt_W(salt, salt_len, salt_W);
        __m128i Wsalt[16];
        for (int i = 0; i < 16; ++i) Wsalt[i] = _mm_set1_epi64x((long long)salt_W[i]);
        for (int i = 0; i < 16; ++i) W[i] = Wsalt[i];
        sha512_block64_sse(ipad_iv_lo, W, s_lo);
        for (int i = 0; i < 16; ++i) W[i] = Wsalt[i];
        sha512_block64_sse(ipad_iv_hi, W, s_hi);
    }

    __m128i T_lo[8], T_hi[8];
    for (int i = 0; i < 8; ++i) W[i] = s_lo[i];
    sha512_padded_block64_sse(opad_iv_lo, W, T_lo);
    for (int i = 0; i < 8; ++i) W[i] = s_hi[i];
    sha512_padded_block64_sse(opad_iv_hi, W, T_hi);

    pbkdf2_2lane_fused_stream(ipad_iv_lo, opad_iv_lo, T_lo, T_lo, iterations);
    pbkdf2_2lane_fused_stream(ipad_iv_hi, opad_iv_hi, T_hi, T_hi, iterations);

    uint8_t* outs[4] = {out1, out2, out3, out4};
    // OTM-24: byte-swap vetorizado. vpshufb (SSSE3, incluso em SSE4.1)
    // aplica a permutação {7,6,5,4,3,2,1,0, 15,...,8} a cada lane de 128
    // bits, invertendo 2 × u64 por instrução em vez de 2 × bswap escalares.
    const __m128i bswap_mask = _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0,
                                             15, 14, 13, 12, 11, 10, 9, 8);
    for (int i = 0; i < 8; ++i) {
        alignas(16) uint64_t lo[2], hi[2];
        _mm_store_si128((__m128i*)lo, _mm_shuffle_epi8(T_lo[i], bswap_mask));
        _mm_store_si128((__m128i*)hi, _mm_shuffle_epi8(T_hi[i], bswap_mask));
        for (int l = 0; l < 2; ++l) {
            std::memcpy(outs[l] + i * 8, &lo[l], 8);
            std::memcpy(outs[2 + l] + i * 8, &hi[l], 8);
        }
    }
}

#undef ROR128_64
#undef CH_SSE
#undef MAJ_SSE
#undef S0_SSE
#undef S1_SSE
#undef s0_SSE
#undef s1_SSE

// AVX2 + AVX-512
namespace pbkdf2_simd_detail {

struct QuadWord {
    alignas(32) uint64_t v[4];
    constexpr QuadWord(uint64_t x) : v{x, x, x, x} {}
    [[gnu::target("avx2")]] inline __m256i vec() const noexcept { __m256i r; std::memcpy(&r, v, sizeof(r)); return r; }
    [[gnu::target("avx2")]] inline operator __m256i() const noexcept { return vec(); }
};

struct OctWord {
    alignas(64) uint64_t v[8];
    constexpr OctWord(uint64_t x) : v{x, x, x, x, x, x, x, x} {}
    [[gnu::target("avx512f,avx512vl")]] inline __m512i vec() const noexcept { __m512i r; std::memcpy(&r, v, sizeof(r)); return r; }
};

struct K512_AVX2_Table {
    alignas(32) uint64_t data[80][4];
    constexpr K512_AVX2_Table() : data{} {
        for (int i = 0; i < 80; ++i) { uint64_t v = K512[i]; for (int j = 0; j < 4; ++j) data[i][j] = v; }
    }
};
inline constexpr K512_AVX2_Table g_k512_avx2_table{};

struct IV_AVX2_Table {
    alignas(32) uint64_t data[8][4];
    constexpr IV_AVX2_Table() : data{} {
        for (int i = 0; i < 8; ++i) { uint64_t v = IV[i]; for (int j = 0; j < 4; ++j) data[i][j] = v; }
    }
};
inline constexpr IV_AVX2_Table g_iv_avx2_table{};

struct K512_AVX512_Table {
    alignas(64) uint64_t data[80][8];
    constexpr K512_AVX512_Table() : data{} {
        for (int i = 0; i < 80; ++i) { uint64_t v = K512[i]; for (int j = 0; j < 8; ++j) data[i][j] = v; }
    }
};
inline constexpr K512_AVX512_Table g_k512_avx512_table{};

struct IV_AVX512_Table {
    alignas(64) uint64_t data[8][8];
    constexpr IV_AVX512_Table() : data{} {
        for (int i = 0; i < 8; ++i) { uint64_t v = IV[i]; for (int j = 0; j < 8; ++j) data[i][j] = v; }
    }
};
inline constexpr IV_AVX512_Table g_iv_avx512_table{};

inline constexpr QuadWord C_S1_W15_AVX2{0x00c0000000003018ULL};
inline constexpr QuadWord C_S0_W8_AVX2{0x4180000000000000ULL};
inline constexpr QuadWord C_S0_W15_AVX2{0x000000000000030aULL};
inline constexpr QuadWord C_W8_AVX2{0x8000000000000000ULL};
inline constexpr QuadWord C_W15_AVX2{0x0000000000000600ULL};
inline constexpr QuadWord K_FUSED_8_AVX2{0xd807aa98a3030242ULL + 0x8000000000000000ULL};
inline constexpr QuadWord K_FUSED_15_AVX2{0xc19bf174cf692694ULL + 0x0000000000000600ULL};

inline constexpr OctWord C_S1_W15_AVX512{0x00c0000000003018ULL};
inline constexpr OctWord C_S0_W8_AVX512{0x4180000000000000ULL};
inline constexpr OctWord C_S0_W15_AVX512{0x000000000000030aULL};
inline constexpr OctWord C_W8_AVX512{0x8000000000000000ULL};
inline constexpr OctWord C_W15_AVX512{0x0000000000000600ULL};
inline constexpr OctWord K_FUSED_8_AVX512{0xd807aa98a3030242ULL + 0x8000000000000000ULL};
inline constexpr OctWord K_FUSED_15_AVX512{0xc19bf174cf692694ULL + 0x0000000000000600ULL};

inline void precompute_kw_salt_tables(const uint64_t kw_salt[80], uint64_t* sse_tbl, uint64_t* avx2_tbl,
                                      uint64_t* avx512_tbl) noexcept {
    for (int i = 0; i < 80; ++i) {
        uint64_t v = kw_salt[i];
        if (sse_tbl) { sse_tbl[i*2] = v; sse_tbl[i*2 + 1] = v; }
        if (avx2_tbl) { for (int j = 0; j < 4; ++j) avx2_tbl[i*4 + j] = v; }
        if (avx512_tbl) { for (int j = 0; j < 8; ++j) avx512_tbl[i*8 + j] = v; }
    }
}

}  // namespace pbkdf2_simd_detail

[[gnu::target("avx2"), gnu::always_inline]] static inline const __m256i* get_k512_avx2() noexcept {
    return reinterpret_cast<const __m256i*>(pbkdf2_simd_detail::g_k512_avx2_table.data);
}
[[gnu::target("avx2"), gnu::always_inline]] static inline const __m256i* get_iv_avx2() noexcept {
    return reinterpret_cast<const __m256i*>(pbkdf2_simd_detail::g_iv_avx2_table.data);
}
[[gnu::target("avx512f,avx512vl"), gnu::always_inline]] static inline const __m512i* get_k512_avx512() noexcept {
    return reinterpret_cast<const __m512i*>(pbkdf2_simd_detail::g_k512_avx512_table.data);
}
[[gnu::target("avx512f,avx512vl"), gnu::always_inline]] static inline const __m512i* get_iv_avx512() noexcept {
    return reinterpret_cast<const __m512i*>(pbkdf2_simd_detail::g_iv_avx512_table.data);
}

alignas(32) static constexpr uint8_t SHUF_ROR8_AVX2[32] = {1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8,
                                                           1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8};

// ---------------------------------------------------------------------------
// AVX2
// ---------------------------------------------------------------------------
#define ROR256_64(x, n) _mm256_or_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))
#define CH_AVX2(x, y, z) _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
#define MAJ_AVX2(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)))
#define S0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 28), ROR256_64(x, 34)), ROR256_64(x, 39))
#define S1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 14), ROR256_64(x, 18)), ROR256_64(x, 41))
#define s0_AVX2(x)                                                                                                     \
    _mm256_xor_si256(                                                                                                  \
        _mm256_xor_si256(ROR256_64(x, 1), _mm256_shuffle_epi8(x, _mm256_load_si256((const __m256i*)SHUF_ROR8_AVX2))),  \
        _mm256_srli_epi64(x, 7))
#define s1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 19), ROR256_64(x, 61)), _mm256_srli_epi64(x, 6))

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_block64_avx2(const __m256i iv[8], __m256i W[16], __m256i out[8]) {
    __m256i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    const __m256i* k_tbl = get_k512_avx2();
#pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m256i kw = _mm256_add_epi64(k_tbl[r * 16 + i], W[i]);
            __m256i h_kw = _mm256_add_epi64(h, kw);
            __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));
            __m256i T1 = _mm256_add_epi64(h_kw, e_terms);
            __m256i T2 = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));
            h = g; g = f; f = e; e = _mm256_add_epi64(d, T1);
            d = c; c = b; b = a; a = _mm256_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm256_add_epi64(_mm256_add_epi64(W[i], W[(i + 9) & 15]),
                                        _mm256_add_epi64(s0_AVX2(W[(i + 1) & 15]), s1_AVX2(W[(i + 14) & 15])));
            }
        }
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_padded_block64_avx2_single(const __m256i iv[8], __m256i W[16], __m256i out[8]) {
    const __m256i C_S1_W15 = pbkdf2_simd_detail::C_S1_W15_AVX2.vec();
    const __m256i C_S0_W8 = pbkdf2_simd_detail::C_S0_W8_AVX2.vec();
    const __m256i C_S0_W15 = pbkdf2_simd_detail::C_S0_W15_AVX2.vec();
    const __m256i C_W8 = pbkdf2_simd_detail::C_W8_AVX2.vec();
    const __m256i C_W15 = pbkdf2_simd_detail::C_W15_AVX2.vec();
    const __m256i K_FUSED_8 = pbkdf2_simd_detail::K_FUSED_8_AVX2.vec();
    const __m256i K_FUSED_15 = pbkdf2_simd_detail::K_FUSED_15_AVX2.vec();

    __m256i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    const __m256i* k_tbl = get_k512_avx2();

#define STEP_AVX2(k_term, w_val)                                                                                       \
    do {                                                                                                               \
        __m256i kw = _mm256_add_epi64((k_term), (w_val));                                                              \
        __m256i h_kw = _mm256_add_epi64(h, kw);                                                                        \
        __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));                                              \
        __m256i T1 = _mm256_add_epi64(h_kw, e_terms);                                                                  \
        __m256i T2 = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));                                                  \
        h = g; g = f; f = e; e = _mm256_add_epi64(d, T1); d = c; c = b; b = a; a = _mm256_add_epi64(T1, T2);           \
    } while (0)
#define STEP_FUSED_AVX2(k_fused)                                                                                       \
    do {                                                                                                               \
        __m256i h_kw = _mm256_add_epi64(h, (k_fused));                                                                 \
        __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));                                              \
        __m256i T1 = _mm256_add_epi64(h_kw, e_terms);                                                                  \
        __m256i T2 = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));                                                  \
        h = g; g = f; f = e; e = _mm256_add_epi64(d, T1); d = c; c = b; b = a; a = _mm256_add_epi64(T1, T2);           \
    } while (0)

    STEP_AVX2(k_tbl[0], W[0]); W[0] = _mm256_add_epi64(W[0], s0_AVX2(W[1]));
    STEP_AVX2(k_tbl[1], W[1]); W[1] = _mm256_add_epi64(W[1], _mm256_add_epi64(s0_AVX2(W[2]), C_S1_W15));
    STEP_AVX2(k_tbl[2], W[2]); W[2] = _mm256_add_epi64(W[2], _mm256_add_epi64(s0_AVX2(W[3]), s1_AVX2(W[0])));
    STEP_AVX2(k_tbl[3], W[3]); W[3] = _mm256_add_epi64(W[3], _mm256_add_epi64(s0_AVX2(W[4]), s1_AVX2(W[1])));
    STEP_AVX2(k_tbl[4], W[4]); W[4] = _mm256_add_epi64(W[4], _mm256_add_epi64(s0_AVX2(W[5]), s1_AVX2(W[2])));
    STEP_AVX2(k_tbl[5], W[5]); W[5] = _mm256_add_epi64(W[5], _mm256_add_epi64(s0_AVX2(W[6]), s1_AVX2(W[3])));
    STEP_AVX2(k_tbl[6], W[6]); W[6] = _mm256_add_epi64(W[6], _mm256_add_epi64(_mm256_add_epi64(s0_AVX2(W[7]), C_W15), s1_AVX2(W[4])));
    STEP_AVX2(k_tbl[7], W[7]); W[7] = _mm256_add_epi64(W[7], _mm256_add_epi64(_mm256_add_epi64(C_S0_W8, W[0]), s1_AVX2(W[5])));

    STEP_FUSED_AVX2(K_FUSED_8); W[8] = _mm256_add_epi64(C_W8, _mm256_add_epi64(W[1], s1_AVX2(W[6])));
    STEP_FUSED_AVX2(k_tbl[9]); W[9] = _mm256_add_epi64(W[2], s1_AVX2(W[7]));
    STEP_FUSED_AVX2(k_tbl[10]); W[10] = _mm256_add_epi64(W[3], s1_AVX2(W[8]));
    STEP_FUSED_AVX2(k_tbl[11]); W[11] = _mm256_add_epi64(W[4], s1_AVX2(W[9]));
    STEP_FUSED_AVX2(k_tbl[12]); W[12] = _mm256_add_epi64(W[5], s1_AVX2(W[10]));
    STEP_FUSED_AVX2(k_tbl[13]); W[13] = _mm256_add_epi64(W[6], s1_AVX2(W[11]));
    STEP_FUSED_AVX2(k_tbl[14]); W[14] = _mm256_add_epi64(C_S0_W15, _mm256_add_epi64(W[7], s1_AVX2(W[12])));
    STEP_FUSED_AVX2(K_FUSED_15); W[15] = _mm256_add_epi64(_mm256_add_epi64(C_W15, s0_AVX2(W[0])), _mm256_add_epi64(W[8], s1_AVX2(W[13])));

#undef STEP_AVX2
#undef STEP_FUSED_AVX2

#pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m256i kw = _mm256_add_epi64(k_tbl[r * 16 + i], W[i]);
            __m256i h_kw = _mm256_add_epi64(h, kw);
            __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));
            __m256i T1 = _mm256_add_epi64(h_kw, e_terms);
            __m256i T2 = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));
            h = g; g = f; f = e; e = _mm256_add_epi64(d, T1);
            d = c; c = b; b = a; a = _mm256_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm256_add_epi64(_mm256_add_epi64(W[i], W[(i + 9) & 15]),
                                        _mm256_add_epi64(s0_AVX2(W[(i + 1) & 15]), s1_AVX2(W[(i + 14) & 15])));
            }
        }
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_padded_block64_avx2_x2(const __m256i iv_a[8], const __m256i iv_b[8],
                                                 __m256i Wa[16], __m256i Wb[16]) {
    const __m256i C_S1_W15 = pbkdf2_simd_detail::C_S1_W15_AVX2.vec();
    const __m256i C_S0_W8 = pbkdf2_simd_detail::C_S0_W8_AVX2.vec();
    const __m256i C_S0_W15 = pbkdf2_simd_detail::C_S0_W15_AVX2.vec();
    const __m256i C_W8 = pbkdf2_simd_detail::C_W8_AVX2.vec();
    const __m256i C_W15 = pbkdf2_simd_detail::C_W15_AVX2.vec();
    const __m256i K_FUSED_8 = pbkdf2_simd_detail::K_FUSED_8_AVX2.vec();
    const __m256i K_FUSED_15 = pbkdf2_simd_detail::K_FUSED_15_AVX2.vec();

    __m256i a_a = iv_a[0], b_a = iv_a[1], c_a = iv_a[2], d_a = iv_a[3];
    __m256i e_a = iv_a[4], f_a = iv_a[5], g_a = iv_a[6], h_a = iv_a[7];
    __m256i a_b = iv_b[0], b_b = iv_b[1], c_b = iv_b[2], d_b = iv_b[3];
    __m256i e_b = iv_b[4], f_b = iv_b[5], g_b = iv_b[6], h_b = iv_b[7];
    const __m256i* k_tbl = get_k512_avx2();

#define STEP2(k_term, wa, wb)                                                                                          \
    do {                                                                                                               \
        { __m256i kw = _mm256_add_epi64((k_term), (wa));                                                              \
          __m256i h_kw = _mm256_add_epi64(h_a, kw);                                                                    \
          __m256i e_terms = _mm256_add_epi64(S1_AVX2(e_a), CH_AVX2(e_a, f_a, g_a));                                    \
          __m256i T1 = _mm256_add_epi64(h_kw, e_terms);                                                                \
          __m256i T2 = _mm256_add_epi64(S0_AVX2(a_a), MAJ_AVX2(a_a, b_a, c_a));                                        \
          h_a = g_a; g_a = f_a; f_a = e_a; e_a = _mm256_add_epi64(d_a, T1);                                            \
          d_a = c_a; c_a = b_a; b_a = a_a; a_a = _mm256_add_epi64(T1, T2); }                                           \
        { __m256i kw = _mm256_add_epi64((k_term), (wb));                                                              \
          __m256i h_kw = _mm256_add_epi64(h_b, kw);                                                                    \
          __m256i e_terms = _mm256_add_epi64(S1_AVX2(e_b), CH_AVX2(e_b, f_b, g_b));                                    \
          __m256i T1 = _mm256_add_epi64(h_kw, e_terms);                                                                \
          __m256i T2 = _mm256_add_epi64(S0_AVX2(a_b), MAJ_AVX2(a_b, b_b, c_b));                                        \
          h_b = g_b; g_b = f_b; f_b = e_b; e_b = _mm256_add_epi64(d_b, T1);                                            \
          d_b = c_b; c_b = b_b; b_b = a_b; a_b = _mm256_add_epi64(T1, T2); }                                           \
    } while (0)

#define STEPF2(kf, wa, wb)                                                                                             \
    do {                                                                                                               \
        { __m256i h_kw = _mm256_add_epi64(h_a, (kf));                                                                  \
          __m256i e_terms = _mm256_add_epi64(S1_AVX2(e_a), CH_AVX2(e_a, f_a, g_a));                                    \
          __m256i T1 = _mm256_add_epi64(h_kw, e_terms);                                                                \
          __m256i T2 = _mm256_add_epi64(S0_AVX2(a_a), MAJ_AVX2(a_a, b_a, c_a));                                        \
          h_a = g_a; g_a = f_a; f_a = e_a; e_a = _mm256_add_epi64(d_a, T1);                                            \
          d_a = c_a; c_a = b_a; b_a = a_a; a_a = _mm256_add_epi64(T1, T2); }                                           \
        { __m256i h_kw = _mm256_add_epi64(h_b, (kf));                                                                  \
          __m256i e_terms = _mm256_add_epi64(S1_AVX2(e_b), CH_AVX2(e_b, f_b, g_b));                                    \
          __m256i T1 = _mm256_add_epi64(h_kw, e_terms);                                                                \
          __m256i T2 = _mm256_add_epi64(S0_AVX2(a_b), MAJ_AVX2(a_b, b_b, c_b));                                        \
          h_b = g_b; g_b = f_b; f_b = e_b; e_b = _mm256_add_epi64(d_b, T1);                                            \
          d_b = c_b; c_b = b_b; b_b = a_b; a_b = _mm256_add_epi64(T1, T2); }                                           \
    } while (0)

    STEP2(k_tbl[0], Wa[0], Wb[0]);
    Wa[0] = _mm256_add_epi64(Wa[0], s0_AVX2(Wa[1])); Wb[0] = _mm256_add_epi64(Wb[0], s0_AVX2(Wb[1]));
    STEP2(k_tbl[1], Wa[1], Wb[1]);
    Wa[1] = _mm256_add_epi64(Wa[1], _mm256_add_epi64(s0_AVX2(Wa[2]), C_S1_W15));
    Wb[1] = _mm256_add_epi64(Wb[1], _mm256_add_epi64(s0_AVX2(Wb[2]), C_S1_W15));
    STEP2(k_tbl[2], Wa[2], Wb[2]);
    Wa[2] = _mm256_add_epi64(Wa[2], _mm256_add_epi64(s0_AVX2(Wa[3]), s1_AVX2(Wa[0])));
    Wb[2] = _mm256_add_epi64(Wb[2], _mm256_add_epi64(s0_AVX2(Wb[3]), s1_AVX2(Wb[0])));
    STEP2(k_tbl[3], Wa[3], Wb[3]);
    Wa[3] = _mm256_add_epi64(Wa[3], _mm256_add_epi64(s0_AVX2(Wa[4]), s1_AVX2(Wa[1])));
    Wb[3] = _mm256_add_epi64(Wb[3], _mm256_add_epi64(s0_AVX2(Wb[4]), s1_AVX2(Wb[1])));
    STEP2(k_tbl[4], Wa[4], Wb[4]);
    Wa[4] = _mm256_add_epi64(Wa[4], _mm256_add_epi64(s0_AVX2(Wa[5]), s1_AVX2(Wa[2])));
    Wb[4] = _mm256_add_epi64(Wb[4], _mm256_add_epi64(s0_AVX2(Wb[5]), s1_AVX2(Wb[2])));
    STEP2(k_tbl[5], Wa[5], Wb[5]);
    Wa[5] = _mm256_add_epi64(Wa[5], _mm256_add_epi64(s0_AVX2(Wa[6]), s1_AVX2(Wa[3])));
    Wb[5] = _mm256_add_epi64(Wb[5], _mm256_add_epi64(s0_AVX2(Wb[6]), s1_AVX2(Wb[3])));
    STEP2(k_tbl[6], Wa[6], Wb[6]);
    Wa[6] = _mm256_add_epi64(Wa[6], _mm256_add_epi64(_mm256_add_epi64(s0_AVX2(Wa[7]), C_W15), s1_AVX2(Wa[4])));
    Wb[6] = _mm256_add_epi64(Wb[6], _mm256_add_epi64(_mm256_add_epi64(s0_AVX2(Wb[7]), C_W15), s1_AVX2(Wb[4])));
    STEP2(k_tbl[7], Wa[7], Wb[7]);
    Wa[7] = _mm256_add_epi64(Wa[7], _mm256_add_epi64(_mm256_add_epi64(C_S0_W8, Wa[0]), s1_AVX2(Wa[5])));
    Wb[7] = _mm256_add_epi64(Wb[7], _mm256_add_epi64(_mm256_add_epi64(C_S0_W8, Wb[0]), s1_AVX2(Wb[5])));

    STEPF2(K_FUSED_8, Wa[8], Wb[8]);
    Wa[8] = _mm256_add_epi64(C_W8, _mm256_add_epi64(Wa[1], s1_AVX2(Wa[6])));
    Wb[8] = _mm256_add_epi64(C_W8, _mm256_add_epi64(Wb[1], s1_AVX2(Wb[6])));
    STEPF2(k_tbl[9], Wa[9], Wb[9]);
    Wa[9] = _mm256_add_epi64(Wa[2], s1_AVX2(Wa[7])); Wb[9] = _mm256_add_epi64(Wb[2], s1_AVX2(Wb[7]));
    STEPF2(k_tbl[10], Wa[10], Wb[10]);
    Wa[10] = _mm256_add_epi64(Wa[3], s1_AVX2(Wa[8])); Wb[10] = _mm256_add_epi64(Wb[3], s1_AVX2(Wb[8]));
    STEPF2(k_tbl[11], Wa[11], Wb[11]);
    Wa[11] = _mm256_add_epi64(Wa[4], s1_AVX2(Wa[9])); Wb[11] = _mm256_add_epi64(Wb[4], s1_AVX2(Wb[9]));
    STEPF2(k_tbl[12], Wa[12], Wb[12]);
    Wa[12] = _mm256_add_epi64(Wa[5], s1_AVX2(Wa[10])); Wb[12] = _mm256_add_epi64(Wb[5], s1_AVX2(Wb[10]));
    STEPF2(k_tbl[13], Wa[13], Wb[13]);
    Wa[13] = _mm256_add_epi64(Wa[6], s1_AVX2(Wa[11])); Wb[13] = _mm256_add_epi64(Wb[6], s1_AVX2(Wb[11]));
    STEPF2(k_tbl[14], Wa[14], Wb[14]);
    Wa[14] = _mm256_add_epi64(C_S0_W15, _mm256_add_epi64(Wa[7], s1_AVX2(Wa[12])));
    Wb[14] = _mm256_add_epi64(C_S0_W15, _mm256_add_epi64(Wb[7], s1_AVX2(Wb[12])));
    STEPF2(K_FUSED_15, Wa[15], Wb[15]);
    Wa[15] = _mm256_add_epi64(_mm256_add_epi64(C_W15, s0_AVX2(Wa[0])), _mm256_add_epi64(Wa[8], s1_AVX2(Wa[13])));
    Wb[15] = _mm256_add_epi64(_mm256_add_epi64(C_W15, s0_AVX2(Wb[0])), _mm256_add_epi64(Wb[8], s1_AVX2(Wb[13])));

#undef STEP2
#undef STEPF2

#pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            {
                __m256i kw = _mm256_add_epi64(k_tbl[r * 16 + i], Wa[i]);
                __m256i h_kw = _mm256_add_epi64(h_a, kw);
                __m256i e_terms = _mm256_add_epi64(S1_AVX2(e_a), CH_AVX2(e_a, f_a, g_a));
                __m256i T1 = _mm256_add_epi64(h_kw, e_terms);
                __m256i T2 = _mm256_add_epi64(S0_AVX2(a_a), MAJ_AVX2(a_a, b_a, c_a));
                h_a = g_a; g_a = f_a; f_a = e_a; e_a = _mm256_add_epi64(d_a, T1);
                d_a = c_a; c_a = b_a; b_a = a_a; a_a = _mm256_add_epi64(T1, T2);
            }
            {
                __m256i kw = _mm256_add_epi64(k_tbl[r * 16 + i], Wb[i]);
                __m256i h_kw = _mm256_add_epi64(h_b, kw);
                __m256i e_terms = _mm256_add_epi64(S1_AVX2(e_b), CH_AVX2(e_b, f_b, g_b));
                __m256i T1 = _mm256_add_epi64(h_kw, e_terms);
                __m256i T2 = _mm256_add_epi64(S0_AVX2(a_b), MAJ_AVX2(a_b, b_b, c_b));
                h_b = g_b; g_b = f_b; f_b = e_b; e_b = _mm256_add_epi64(d_b, T1);
                d_b = c_b; c_b = b_b; b_b = a_b; a_b = _mm256_add_epi64(T1, T2);
            }
            if (r < 4) {
                Wa[i] = _mm256_add_epi64(_mm256_add_epi64(Wa[i], Wa[(i + 9) & 15]),
                                         _mm256_add_epi64(s0_AVX2(Wa[(i + 1) & 15]), s1_AVX2(Wa[(i + 14) & 15])));
                Wb[i] = _mm256_add_epi64(_mm256_add_epi64(Wb[i], Wb[(i + 9) & 15]),
                                         _mm256_add_epi64(s0_AVX2(Wb[(i + 1) & 15]), s1_AVX2(Wb[(i + 14) & 15])));
            }
        }
    }

    Wa[0] = _mm256_add_epi64(iv_a[0], a_a); Wa[1] = _mm256_add_epi64(iv_a[1], b_a);
    Wa[2] = _mm256_add_epi64(iv_a[2], c_a); Wa[3] = _mm256_add_epi64(iv_a[3], d_a);
    Wa[4] = _mm256_add_epi64(iv_a[4], e_a); Wa[5] = _mm256_add_epi64(iv_a[5], f_a);
    Wa[6] = _mm256_add_epi64(iv_a[6], g_a); Wa[7] = _mm256_add_epi64(iv_a[7], h_a);
    Wb[0] = _mm256_add_epi64(iv_b[0], a_b); Wb[1] = _mm256_add_epi64(iv_b[1], b_b);
    Wb[2] = _mm256_add_epi64(iv_b[2], c_b); Wb[3] = _mm256_add_epi64(iv_b[3], d_b);
    Wb[4] = _mm256_add_epi64(iv_b[4], e_b); Wb[5] = _mm256_add_epi64(iv_b[5], f_b);
    Wb[6] = _mm256_add_epi64(iv_b[6], g_b); Wb[7] = _mm256_add_epi64(iv_b[7], h_b);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void pbkdf2_8lane_interleaved_stream(
    const __m256i ipad_lo[8], const __m256i opad_lo[8],
    const __m256i ipad_hi[8], const __m256i opad_hi[8],
    const __m256i init_lo[8], const __m256i init_hi[8],
    __m256i T_lo[8], __m256i T_hi[8], uint32_t iterations)
{
    __m256i Wlo[16], Whi[16];
#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) { Wlo[i] = init_lo[i]; Whi[i] = init_hi[i]; }

    uint32_t it = 1;
    for (; it + 4 <= iterations; it += 4) {
#pragma GCC unroll 4
        for (int j = 0; j < 4; ++j) {
            sha512_padded_block64_avx2_x2(ipad_lo, ipad_hi, Wlo, Whi);
            sha512_padded_block64_avx2_x2(opad_lo, opad_hi, Wlo, Whi);
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                T_lo[i] = _mm256_xor_si256(T_lo[i], Wlo[i]);
                T_hi[i] = _mm256_xor_si256(T_hi[i], Whi[i]);
            }
        }
    }
    for (; it < iterations; ++it) {
        sha512_padded_block64_avx2_x2(ipad_lo, ipad_hi, Wlo, Whi);
        sha512_padded_block64_avx2_x2(opad_lo, opad_hi, Wlo, Whi);
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            T_lo[i] = _mm256_xor_si256(T_lo[i], Wlo[i]);
            T_hi[i] = _mm256_xor_si256(T_hi[i], Whi[i]);
        }
    }
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_salt_fastforward_avx2(const __m256i iv[8], const __m256i kw_salt_vec[80], __m256i out[8]) {
    __m256i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    for (int i = 0; i < 80; ++i) {
        __m256i kw = kw_salt_vec[i];
        __m256i h_kw = _mm256_add_epi64(h, kw);
        __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));
        __m256i T1 = _mm256_add_epi64(h_kw, e_terms);
        __m256i T2 = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi64(d, T1);
        d = c; c = b; b = a; a = _mm256_add_epi64(T1, T2);
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_salt_fastforward_avx2(const __m256i iv[8], const uint64_t kw_salt[80], __m256i out[8]) {
    alignas(32) __m256i kw_vec[80];
    for (int i = 0; i < 80; ++i) kw_vec[i] = _mm256_set1_epi64x((long long)kw_salt[i]);
    sha512_salt_fastforward_avx2(iv, kw_vec, out);
}

inline void precompute_kw_salt(const uint64_t salt_blk64[16], uint64_t kw_salt[80]) {
    pbkdf2_simd_detail::precompute_kw_salt_from_W(salt_blk64, kw_salt);
}

[[gnu::target("avx2")]]
inline void pbkdf2_hmac_sha512_8way_avx2(const char* p1, size_t l1, const char* p2, size_t l2, const char* p3,
                                         size_t l3, const char* p4, size_t l4, const char* p5, size_t l5,
                                         const char* p6, size_t l6, const char* p7, size_t l7, const char* p8,
                                         size_t l8, const uint8_t* salt, size_t salt_len, uint32_t iterations,
                                         uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64],
                                         uint8_t out5[64], uint8_t out6[64], uint8_t out7[64], uint8_t out8[64],
                                         const uint64_t* precomputed_salt_blk64 = nullptr,
                                         const uint64_t* precomputed_kw_salt = nullptr,
                                         const void* precomputed_kw_salt_vec = nullptr) {
    using namespace pbkdf2_simd_detail;

    const void* passes[8] = {p1, p2, p3, p4, p5, p6, p7, p8};
    const size_t lens[8] = {l1, l2, l3, l4, l5, l6, l7, l8};
    alignas(32) uint64_t ipad_all[16][8], opad_all[16][8];
    prepare_pads<8>(passes, lens, ipad_all, opad_all);

    __m256i ipad_iv_lo[8], ipad_iv_hi[8], opad_iv_lo[8], opad_iv_hi[8];
    __m256i W[16];
    for (int i = 0; i < 16; ++i) W[i] = _mm256_load_si256((const __m256i*)&ipad_all[i][0]);
    sha512_block64_avx2(get_iv_avx2(), W, ipad_iv_lo);
    for (int i = 0; i < 16; ++i) W[i] = _mm256_load_si256((const __m256i*)&ipad_all[i][4]);
    sha512_block64_avx2(get_iv_avx2(), W, ipad_iv_hi);
    for (int i = 0; i < 16; ++i) W[i] = _mm256_load_si256((const __m256i*)&opad_all[i][0]);
    sha512_block64_avx2(get_iv_avx2(), W, opad_iv_lo);
    for (int i = 0; i < 16; ++i) W[i] = _mm256_load_si256((const __m256i*)&opad_all[i][4]);
    sha512_block64_avx2(get_iv_avx2(), W, opad_iv_hi);

    __m256i s_lo[8], s_hi[8];
    if (precomputed_kw_salt_vec) {
        const auto* kw_vec = static_cast<const __m256i*>(precomputed_kw_salt_vec);
        sha512_salt_fastforward_avx2(ipad_iv_lo, kw_vec, s_lo);
        sha512_salt_fastforward_avx2(ipad_iv_hi, kw_vec, s_hi);
    } else if (precomputed_kw_salt) {
        sha512_salt_fastforward_avx2(ipad_iv_lo, precomputed_kw_salt, s_lo);
        sha512_salt_fastforward_avx2(ipad_iv_hi, precomputed_kw_salt, s_hi);
    } else {
        uint64_t salt_W[16];
        if (precomputed_salt_blk64) for (int i = 0; i < 16; ++i) salt_W[i] = precomputed_salt_blk64[i];
        else (void)prepare_salt_W(salt, salt_len, salt_W);
        __m256i Wsalt[16];
        for (int i = 0; i < 16; ++i) Wsalt[i] = _mm256_set1_epi64x((long long)salt_W[i]);
        for (int i = 0; i < 16; ++i) W[i] = Wsalt[i];
        sha512_block64_avx2(ipad_iv_lo, W, s_lo);
        for (int i = 0; i < 16; ++i) W[i] = Wsalt[i];
        sha512_block64_avx2(ipad_iv_hi, W, s_hi);
    }

    __m256i T_lo[8], T_hi[8];
    for (int i = 0; i < 8; ++i) W[i] = s_lo[i];
    sha512_padded_block64_avx2_single(opad_iv_lo, W, T_lo);
    for (int i = 0; i < 8; ++i) W[i] = s_hi[i];
    sha512_padded_block64_avx2_single(opad_iv_hi, W, T_hi);

    pbkdf2_8lane_interleaved_stream(ipad_iv_lo, opad_iv_lo, ipad_iv_hi, opad_iv_hi, T_lo, T_hi, T_lo, T_hi,
                                    iterations);

    uint8_t* outs[8] = {out1, out2, out3, out4, out5, out6, out7, out8};
    // OTM-24: vpshufb AVX2 — 4 × u64 por instrução. Máscara repetida em
    // cada lane de 128 bits (vpshufb só opera intra-lane).
    const __m256i bswap_mask = _mm256_setr_epi8(
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
    for (int i = 0; i < 8; ++i) {
        alignas(32) uint64_t lo[4], hi[4];
        _mm256_store_si256((__m256i*)lo, _mm256_shuffle_epi8(T_lo[i], bswap_mask));
        _mm256_store_si256((__m256i*)hi, _mm256_shuffle_epi8(T_hi[i], bswap_mask));
        for (int l = 0; l < 4; ++l) {
            std::memcpy(outs[l] + i * 8, &lo[l], 8);
            std::memcpy(outs[4 + l] + i * 8, &hi[l], 8);
        }
    }
}

#undef ROR256_64
#undef CH_AVX2
#undef MAJ_AVX2
#undef S0_AVX2
#undef S1_AVX2
#undef s0_AVX2
#undef s1_AVX2

// ---------------------------------------------------------------------------
// AVX-512
// ---------------------------------------------------------------------------
#define CH_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xCA)
#define MAJ_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xE8)
#define S0_AVX512(x)                                                                                                   \
    _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34), _mm512_ror_epi64(x, 39), 0x96)
#define S1_AVX512(x)                                                                                                   \
    _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18), _mm512_ror_epi64(x, 41), 0x96)
#define s0_AVX512(x)                                                                                                   \
    _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 1), _mm512_ror_epi64(x, 8), _mm512_srli_epi64(x, 7), 0x96)
#define s1_AVX512(x)                                                                                                   \
    _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61), _mm512_srli_epi64(x, 6), 0x96)

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_block64_avx512(const __m512i iv[8], __m512i W[16], __m512i out[8]) {
    __m512i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    const __m512i* k_tbl = get_k512_avx512();
#pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m512i kw = _mm512_add_epi64(k_tbl[r * 16 + i], W[i]);
            __m512i h_kw = _mm512_add_epi64(h, kw);
            __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));
            __m512i T1 = _mm512_add_epi64(h_kw, e_terms);
            __m512i T2 = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));
            h = g; g = f; f = e; e = _mm512_add_epi64(d, T1);
            d = c; c = b; b = a; a = _mm512_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm512_add_epi64(_mm512_add_epi64(W[i], W[(i + 9) & 15]),
                                        _mm512_add_epi64(s0_AVX512(W[(i + 1) & 15]), s1_AVX512(W[(i + 14) & 15])));
            }
        }
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_padded_block64_avx512_single(const __m512i iv[8], __m512i W[16], __m512i out[8]) {
    const __m512i C_S1_W15 = pbkdf2_simd_detail::C_S1_W15_AVX512.vec();
    const __m512i C_S0_W8 = pbkdf2_simd_detail::C_S0_W8_AVX512.vec();
    const __m512i C_S0_W15 = pbkdf2_simd_detail::C_S0_W15_AVX512.vec();
    const __m512i C_W8 = pbkdf2_simd_detail::C_W8_AVX512.vec();
    const __m512i C_W15 = pbkdf2_simd_detail::C_W15_AVX512.vec();
    const __m512i K_FUSED_8 = pbkdf2_simd_detail::K_FUSED_8_AVX512.vec();
    const __m512i K_FUSED_15 = pbkdf2_simd_detail::K_FUSED_15_AVX512.vec();

    __m512i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    const __m512i* k_tbl = get_k512_avx512();

#define S(k_term, w_val)                                                                                               \
    do { __m512i kw = _mm512_add_epi64((k_term), (w_val));                                                            \
         __m512i h_kw = _mm512_add_epi64(h, kw);                                                                      \
         __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));                                        \
         __m512i T1 = _mm512_add_epi64(h_kw, e_terms);                                                                \
         __m512i T2 = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));                                            \
         h = g; g = f; f = e; e = _mm512_add_epi64(d, T1); d = c; c = b; b = a; a = _mm512_add_epi64(T1, T2); } while (0)
#define SF(kf)                                                                                                         \
    do { __m512i h_kw = _mm512_add_epi64(h, (kf));                                                                    \
         __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));                                        \
         __m512i T1 = _mm512_add_epi64(h_kw, e_terms);                                                                \
         __m512i T2 = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));                                            \
         h = g; g = f; f = e; e = _mm512_add_epi64(d, T1); d = c; c = b; b = a; a = _mm512_add_epi64(T1, T2); } while (0)

    S(k_tbl[0], W[0]); W[0] = _mm512_add_epi64(W[0], s0_AVX512(W[1]));
    S(k_tbl[1], W[1]); W[1] = _mm512_add_epi64(W[1], _mm512_add_epi64(s0_AVX512(W[2]), C_S1_W15));
    S(k_tbl[2], W[2]); W[2] = _mm512_add_epi64(W[2], _mm512_add_epi64(s0_AVX512(W[3]), s1_AVX512(W[0])));
    S(k_tbl[3], W[3]); W[3] = _mm512_add_epi64(W[3], _mm512_add_epi64(s0_AVX512(W[4]), s1_AVX512(W[1])));
    S(k_tbl[4], W[4]); W[4] = _mm512_add_epi64(W[4], _mm512_add_epi64(s0_AVX512(W[5]), s1_AVX512(W[2])));
    S(k_tbl[5], W[5]); W[5] = _mm512_add_epi64(W[5], _mm512_add_epi64(s0_AVX512(W[6]), s1_AVX512(W[3])));
    S(k_tbl[6], W[6]); W[6] = _mm512_add_epi64(W[6], _mm512_add_epi64(_mm512_add_epi64(s0_AVX512(W[7]), C_W15), s1_AVX512(W[4])));
    S(k_tbl[7], W[7]); W[7] = _mm512_add_epi64(W[7], _mm512_add_epi64(_mm512_add_epi64(C_S0_W8, W[0]), s1_AVX512(W[5])));

    SF(K_FUSED_8); W[8] = _mm512_add_epi64(C_W8, _mm512_add_epi64(W[1], s1_AVX512(W[6])));
    SF(k_tbl[9]); W[9] = _mm512_add_epi64(W[2], s1_AVX512(W[7]));
    SF(k_tbl[10]); W[10] = _mm512_add_epi64(W[3], s1_AVX512(W[8]));
    SF(k_tbl[11]); W[11] = _mm512_add_epi64(W[4], s1_AVX512(W[9]));
    SF(k_tbl[12]); W[12] = _mm512_add_epi64(W[5], s1_AVX512(W[10]));
    SF(k_tbl[13]); W[13] = _mm512_add_epi64(W[6], s1_AVX512(W[11]));
    SF(k_tbl[14]); W[14] = _mm512_add_epi64(C_S0_W15, _mm512_add_epi64(W[7], s1_AVX512(W[12])));
    SF(K_FUSED_15); W[15] = _mm512_add_epi64(_mm512_add_epi64(C_W15, s0_AVX512(W[0])), _mm512_add_epi64(W[8], s1_AVX512(W[13])));

#undef S
#undef SF

#pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m512i kw = _mm512_add_epi64(k_tbl[r * 16 + i], W[i]);
            __m512i h_kw = _mm512_add_epi64(h, kw);
            __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));
            __m512i T1 = _mm512_add_epi64(h_kw, e_terms);
            __m512i T2 = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));
            h = g; g = f; f = e; e = _mm512_add_epi64(d, T1);
            d = c; c = b; b = a; a = _mm512_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm512_add_epi64(_mm512_add_epi64(W[i], W[(i + 9) & 15]),
                                        _mm512_add_epi64(s0_AVX512(W[(i + 1) & 15]), s1_AVX512(W[(i + 14) & 15])));
            }
        }
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_padded_block64_avx512_x2(const __m512i iv_a[8], const __m512i iv_b[8],
                                                   __m512i Wa[16], __m512i Wb[16]) {
    const __m512i C_S1_W15 = pbkdf2_simd_detail::C_S1_W15_AVX512.vec();
    const __m512i C_S0_W8 = pbkdf2_simd_detail::C_S0_W8_AVX512.vec();
    const __m512i C_S0_W15 = pbkdf2_simd_detail::C_S0_W15_AVX512.vec();
    const __m512i C_W8 = pbkdf2_simd_detail::C_W8_AVX512.vec();
    const __m512i C_W15 = pbkdf2_simd_detail::C_W15_AVX512.vec();
    const __m512i K_FUSED_8 = pbkdf2_simd_detail::K_FUSED_8_AVX512.vec();
    const __m512i K_FUSED_15 = pbkdf2_simd_detail::K_FUSED_15_AVX512.vec();

    __m512i a_a = iv_a[0], b_a = iv_a[1], c_a = iv_a[2], d_a = iv_a[3];
    __m512i e_a = iv_a[4], f_a = iv_a[5], g_a = iv_a[6], h_a = iv_a[7];
    __m512i a_b = iv_b[0], b_b = iv_b[1], c_b = iv_b[2], d_b = iv_b[3];
    __m512i e_b = iv_b[4], f_b = iv_b[5], g_b = iv_b[6], h_b = iv_b[7];
    const __m512i* k_tbl = get_k512_avx512();

#define STEP2(k_term, wa, wb)                                                                                          \
    do {                                                                                                               \
        { __m512i kw = _mm512_add_epi64((k_term), (wa));                                                              \
          __m512i h_kw = _mm512_add_epi64(h_a, kw);                                                                    \
          __m512i e_terms = _mm512_add_epi64(S1_AVX512(e_a), CH_AVX512(e_a, f_a, g_a));                                \
          __m512i T1 = _mm512_add_epi64(h_kw, e_terms);                                                                \
          __m512i T2 = _mm512_add_epi64(S0_AVX512(a_a), MAJ_AVX512(a_a, b_a, c_a));                                    \
          h_a = g_a; g_a = f_a; f_a = e_a; e_a = _mm512_add_epi64(d_a, T1);                                            \
          d_a = c_a; c_a = b_a; b_a = a_a; a_a = _mm512_add_epi64(T1, T2); }                                           \
        { __m512i kw = _mm512_add_epi64((k_term), (wb));                                                              \
          __m512i h_kw = _mm512_add_epi64(h_b, kw);                                                                    \
          __m512i e_terms = _mm512_add_epi64(S1_AVX512(e_b), CH_AVX512(e_b, f_b, g_b));                                \
          __m512i T1 = _mm512_add_epi64(h_kw, e_terms);                                                                \
          __m512i T2 = _mm512_add_epi64(S0_AVX512(a_b), MAJ_AVX512(a_b, b_b, c_b));                                    \
          h_b = g_b; g_b = f_b; f_b = e_b; e_b = _mm512_add_epi64(d_b, T1);                                            \
          d_b = c_b; c_b = b_b; b_b = a_b; a_b = _mm512_add_epi64(T1, T2); }                                           \
    } while (0)

#define STEPF2(kf, wa, wb)                                                                                             \
    do {                                                                                                               \
        { __m512i h_kw = _mm512_add_epi64(h_a, (kf));                                                                  \
          __m512i e_terms = _mm512_add_epi64(S1_AVX512(e_a), CH_AVX512(e_a, f_a, g_a));                                \
          __m512i T1 = _mm512_add_epi64(h_kw, e_terms);                                                                \
          __m512i T2 = _mm512_add_epi64(S0_AVX512(a_a), MAJ_AVX512(a_a, b_a, c_a));                                    \
          h_a = g_a; g_a = f_a; f_a = e_a; e_a = _mm512_add_epi64(d_a, T1);                                            \
          d_a = c_a; c_a = b_a; b_a = a_a; a_a = _mm512_add_epi64(T1, T2); }                                           \
        { __m512i h_kw = _mm512_add_epi64(h_b, (kf));                                                                  \
          __m512i e_terms = _mm512_add_epi64(S1_AVX512(e_b), CH_AVX512(e_b, f_b, g_b));                                \
          __m512i T1 = _mm512_add_epi64(h_kw, e_terms);                                                                \
          __m512i T2 = _mm512_add_epi64(S0_AVX512(a_b), MAJ_AVX512(a_b, b_b, c_b));                                    \
          h_b = g_b; g_b = f_b; f_b = e_b; e_b = _mm512_add_epi64(d_b, T1);                                            \
          d_b = c_b; c_b = b_b; b_b = a_b; a_b = _mm512_add_epi64(T1, T2); }                                           \
    } while (0)

    STEP2(k_tbl[0], Wa[0], Wb[0]);
    Wa[0] = _mm512_add_epi64(Wa[0], s0_AVX512(Wa[1])); Wb[0] = _mm512_add_epi64(Wb[0], s0_AVX512(Wb[1]));
    STEP2(k_tbl[1], Wa[1], Wb[1]);
    Wa[1] = _mm512_add_epi64(Wa[1], _mm512_add_epi64(s0_AVX512(Wa[2]), C_S1_W15));
    Wb[1] = _mm512_add_epi64(Wb[1], _mm512_add_epi64(s0_AVX512(Wb[2]), C_S1_W15));
    STEP2(k_tbl[2], Wa[2], Wb[2]);
    Wa[2] = _mm512_add_epi64(Wa[2], _mm512_add_epi64(s0_AVX512(Wa[3]), s1_AVX512(Wa[0])));
    Wb[2] = _mm512_add_epi64(Wb[2], _mm512_add_epi64(s0_AVX512(Wb[3]), s1_AVX512(Wb[0])));
    STEP2(k_tbl[3], Wa[3], Wb[3]);
    Wa[3] = _mm512_add_epi64(Wa[3], _mm512_add_epi64(s0_AVX512(Wa[4]), s1_AVX512(Wa[1])));
    Wb[3] = _mm512_add_epi64(Wb[3], _mm512_add_epi64(s0_AVX512(Wb[4]), s1_AVX512(Wb[1])));
    STEP2(k_tbl[4], Wa[4], Wb[4]);
    Wa[4] = _mm512_add_epi64(Wa[4], _mm512_add_epi64(s0_AVX512(Wa[5]), s1_AVX512(Wa[2])));
    Wb[4] = _mm512_add_epi64(Wb[4], _mm512_add_epi64(s0_AVX512(Wb[5]), s1_AVX512(Wb[2])));
    STEP2(k_tbl[5], Wa[5], Wb[5]);
    Wa[5] = _mm512_add_epi64(Wa[5], _mm512_add_epi64(s0_AVX512(Wa[6]), s1_AVX512(Wa[3])));
    Wb[5] = _mm512_add_epi64(Wb[5], _mm512_add_epi64(s0_AVX512(Wb[6]), s1_AVX512(Wb[3])));
    STEP2(k_tbl[6], Wa[6], Wb[6]);
    Wa[6] = _mm512_add_epi64(Wa[6], _mm512_add_epi64(_mm512_add_epi64(s0_AVX512(Wa[7]), C_W15), s1_AVX512(Wa[4])));
    Wb[6] = _mm512_add_epi64(Wb[6], _mm512_add_epi64(_mm512_add_epi64(s0_AVX512(Wb[7]), C_W15), s1_AVX512(Wb[4])));
    STEP2(k_tbl[7], Wa[7], Wb[7]);
    Wa[7] = _mm512_add_epi64(Wa[7], _mm512_add_epi64(_mm512_add_epi64(C_S0_W8, Wa[0]), s1_AVX512(Wa[5])));
    Wb[7] = _mm512_add_epi64(Wb[7], _mm512_add_epi64(_mm512_add_epi64(C_S0_W8, Wb[0]), s1_AVX512(Wb[5])));

    STEPF2(K_FUSED_8, Wa[8], Wb[8]);
    Wa[8] = _mm512_add_epi64(C_W8, _mm512_add_epi64(Wa[1], s1_AVX512(Wa[6])));
    Wb[8] = _mm512_add_epi64(C_W8, _mm512_add_epi64(Wb[1], s1_AVX512(Wb[6])));
    STEPF2(k_tbl[9], Wa[9], Wb[9]);
    Wa[9] = _mm512_add_epi64(Wa[2], s1_AVX512(Wa[7])); Wb[9] = _mm512_add_epi64(Wb[2], s1_AVX512(Wb[7]));
    STEPF2(k_tbl[10], Wa[10], Wb[10]);
    Wa[10] = _mm512_add_epi64(Wa[3], s1_AVX512(Wa[8])); Wb[10] = _mm512_add_epi64(Wb[3], s1_AVX512(Wb[8]));
    STEPF2(k_tbl[11], Wa[11], Wb[11]);
    Wa[11] = _mm512_add_epi64(Wa[4], s1_AVX512(Wa[9])); Wb[11] = _mm512_add_epi64(Wb[4], s1_AVX512(Wb[9]));
    STEPF2(k_tbl[12], Wa[12], Wb[12]);
    Wa[12] = _mm512_add_epi64(Wa[5], s1_AVX512(Wa[10])); Wb[12] = _mm512_add_epi64(Wb[5], s1_AVX512(Wb[10]));
    STEPF2(k_tbl[13], Wa[13], Wb[13]);
    Wa[13] = _mm512_add_epi64(Wa[6], s1_AVX512(Wa[11])); Wb[13] = _mm512_add_epi64(Wb[6], s1_AVX512(Wb[11]));
    STEPF2(k_tbl[14], Wa[14], Wb[14]);
    Wa[14] = _mm512_add_epi64(C_S0_W15, _mm512_add_epi64(Wa[7], s1_AVX512(Wa[12])));
    Wb[14] = _mm512_add_epi64(C_S0_W15, _mm512_add_epi64(Wb[7], s1_AVX512(Wb[12])));
    STEPF2(K_FUSED_15, Wa[15], Wb[15]);
    Wa[15] = _mm512_add_epi64(_mm512_add_epi64(C_W15, s0_AVX512(Wa[0])), _mm512_add_epi64(Wa[8], s1_AVX512(Wa[13])));
    Wb[15] = _mm512_add_epi64(_mm512_add_epi64(C_W15, s0_AVX512(Wb[0])), _mm512_add_epi64(Wb[8], s1_AVX512(Wb[13])));

#undef STEP2
#undef STEPF2

#pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            { __m512i kw = _mm512_add_epi64(k_tbl[r * 16 + i], Wa[i]);
              __m512i h_kw = _mm512_add_epi64(h_a, kw);
              __m512i e_terms = _mm512_add_epi64(S1_AVX512(e_a), CH_AVX512(e_a, f_a, g_a));
              __m512i T1 = _mm512_add_epi64(h_kw, e_terms);
              __m512i T2 = _mm512_add_epi64(S0_AVX512(a_a), MAJ_AVX512(a_a, b_a, c_a));
              h_a = g_a; g_a = f_a; f_a = e_a; e_a = _mm512_add_epi64(d_a, T1);
              d_a = c_a; c_a = b_a; b_a = a_a; a_a = _mm512_add_epi64(T1, T2); }
            { __m512i kw = _mm512_add_epi64(k_tbl[r * 16 + i], Wb[i]);
              __m512i h_kw = _mm512_add_epi64(h_b, kw);
              __m512i e_terms = _mm512_add_epi64(S1_AVX512(e_b), CH_AVX512(e_b, f_b, g_b));
              __m512i T1 = _mm512_add_epi64(h_kw, e_terms);
              __m512i T2 = _mm512_add_epi64(S0_AVX512(a_b), MAJ_AVX512(a_b, b_b, c_b));
              h_b = g_b; g_b = f_b; f_b = e_b; e_b = _mm512_add_epi64(d_b, T1);
              d_b = c_b; c_b = b_b; b_b = a_b; a_b = _mm512_add_epi64(T1, T2); }
            if (r < 4) {
                Wa[i] = _mm512_add_epi64(_mm512_add_epi64(Wa[i], Wa[(i + 9) & 15]),
                                         _mm512_add_epi64(s0_AVX512(Wa[(i + 1) & 15]), s1_AVX512(Wa[(i + 14) & 15])));
                Wb[i] = _mm512_add_epi64(_mm512_add_epi64(Wb[i], Wb[(i + 9) & 15]),
                                         _mm512_add_epi64(s0_AVX512(Wb[(i + 1) & 15]), s1_AVX512(Wb[(i + 14) & 15])));
            }
        }
    }

    Wa[0] = _mm512_add_epi64(iv_a[0], a_a); Wa[1] = _mm512_add_epi64(iv_a[1], b_a);
    Wa[2] = _mm512_add_epi64(iv_a[2], c_a); Wa[3] = _mm512_add_epi64(iv_a[3], d_a);
    Wa[4] = _mm512_add_epi64(iv_a[4], e_a); Wa[5] = _mm512_add_epi64(iv_a[5], f_a);
    Wa[6] = _mm512_add_epi64(iv_a[6], g_a); Wa[7] = _mm512_add_epi64(iv_a[7], h_a);
    Wb[0] = _mm512_add_epi64(iv_b[0], a_b); Wb[1] = _mm512_add_epi64(iv_b[1], b_b);
    Wb[2] = _mm512_add_epi64(iv_b[2], c_b); Wb[3] = _mm512_add_epi64(iv_b[3], d_b);
    Wb[4] = _mm512_add_epi64(iv_b[4], e_b); Wb[5] = _mm512_add_epi64(iv_b[5], f_b);
    Wb[6] = _mm512_add_epi64(iv_b[6], g_b); Wb[7] = _mm512_add_epi64(iv_b[7], h_b);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void pbkdf2_16lane_interleaved_stream(
    const __m512i ipad_lo[8], const __m512i opad_lo[8],
    const __m512i ipad_hi[8], const __m512i opad_hi[8],
    const __m512i init_lo[8], const __m512i init_hi[8],
    __m512i T_lo[8], __m512i T_hi[8], uint32_t iterations)
{
    __m512i Wlo[16], Whi[16];
#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) { Wlo[i] = init_lo[i]; Whi[i] = init_hi[i]; }

    uint32_t it = 1;
    for (; it + 4 <= iterations; it += 4) {
#pragma GCC unroll 4
        for (int j = 0; j < 4; ++j) {
            sha512_padded_block64_avx512_x2(ipad_lo, ipad_hi, Wlo, Whi);
            sha512_padded_block64_avx512_x2(opad_lo, opad_hi, Wlo, Whi);
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                T_lo[i] = _mm512_xor_si512(T_lo[i], Wlo[i]);
                T_hi[i] = _mm512_xor_si512(T_hi[i], Whi[i]);
            }
        }
    }
    for (; it < iterations; ++it) {
        sha512_padded_block64_avx512_x2(ipad_lo, ipad_hi, Wlo, Whi);
        sha512_padded_block64_avx512_x2(opad_lo, opad_hi, Wlo, Whi);
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            T_lo[i] = _mm512_xor_si512(T_lo[i], Wlo[i]);
            T_hi[i] = _mm512_xor_si512(T_hi[i], Whi[i]);
        }
    }
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_salt_fastforward_avx512(const __m512i iv[8], const __m512i kw_salt_vec[80], __m512i out[8]) {
    __m512i a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];
    for (int i = 0; i < 80; ++i) {
        __m512i kw = kw_salt_vec[i];
        __m512i h_kw = _mm512_add_epi64(h, kw);
        __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));
        __m512i T1 = _mm512_add_epi64(h_kw, e_terms);
        __m512i T2 = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));
        h = g; g = f; f = e; e = _mm512_add_epi64(d, T1);
        d = c; c = b; b = a; a = _mm512_add_epi64(T1, T2);
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_salt_fastforward_avx512(const __m512i iv[8], const uint64_t kw_salt[80], __m512i out[8]) {
    alignas(64) __m512i kw_vec[80];
    for (int i = 0; i < 80; ++i) kw_vec[i] = _mm512_set1_epi64((long long)kw_salt[i]);
    sha512_salt_fastforward_avx512(iv, kw_vec, out);
}

[[gnu::target("avx512f,avx512vl,avx512bw")]]
inline void pbkdf2_hmac_sha512_16way_avx512(
    const char* p1, size_t l1, const char* p2, size_t l2, const char* p3, size_t l3, const char* p4, size_t l4,
    const char* p5, size_t l5, const char* p6, size_t l6, const char* p7, size_t l7, const char* p8, size_t l8,
    const char* p9, size_t l9, const char* p10, size_t l10, const char* p11, size_t l11, const char* p12, size_t l12,
    const char* p13, size_t l13, const char* p14, size_t l14, const char* p15, size_t l15, const char* p16, size_t l16,
    const uint8_t* salt, size_t salt_len, uint32_t iterations, uint8_t out1[64], uint8_t out2[64], uint8_t out3[64],
    uint8_t out4[64], uint8_t out5[64], uint8_t out6[64], uint8_t out7[64], uint8_t out8[64], uint8_t out9[64],
    uint8_t out10[64], uint8_t out11[64], uint8_t out12[64], uint8_t out13[64], uint8_t out14[64], uint8_t out15[64],
    uint8_t out16[64], const uint64_t* precomputed_salt_blk64, const uint64_t* precomputed_kw_salt,
    const void* precomputed_kw_salt_vec) {
    using namespace pbkdf2_simd_detail;

    const void* passes[16] = {p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, p16};
    const size_t lens[16] = {l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16};
    alignas(64) uint64_t ipad_all[16][16], opad_all[16][16];
    prepare_pads<16>(passes, lens, ipad_all, opad_all);

    __m512i ipad_iv_lo[8], ipad_iv_hi[8], opad_iv_lo[8], opad_iv_hi[8], W[16];
    for (int i = 0; i < 16; ++i) W[i] = _mm512_load_si512((const __m512i*)&ipad_all[i][0]);
    sha512_block64_avx512(get_iv_avx512(), W, ipad_iv_lo);
    for (int i = 0; i < 16; ++i) W[i] = _mm512_load_si512((const __m512i*)&ipad_all[i][8]);
    sha512_block64_avx512(get_iv_avx512(), W, ipad_iv_hi);
    for (int i = 0; i < 16; ++i) W[i] = _mm512_load_si512((const __m512i*)&opad_all[i][0]);
    sha512_block64_avx512(get_iv_avx512(), W, opad_iv_lo);
    for (int i = 0; i < 16; ++i) W[i] = _mm512_load_si512((const __m512i*)&opad_all[i][8]);
    sha512_block64_avx512(get_iv_avx512(), W, opad_iv_hi);

    __m512i s_lo[8], s_hi[8];
    if (precomputed_kw_salt_vec) {
        const auto* kw_vec = static_cast<const __m512i*>(precomputed_kw_salt_vec);
        sha512_salt_fastforward_avx512(ipad_iv_lo, kw_vec, s_lo);
        sha512_salt_fastforward_avx512(ipad_iv_hi, kw_vec, s_hi);
    } else if (precomputed_kw_salt) {
        sha512_salt_fastforward_avx512(ipad_iv_lo, precomputed_kw_salt, s_lo);
        sha512_salt_fastforward_avx512(ipad_iv_hi, precomputed_kw_salt, s_hi);
    } else {
        uint64_t salt_W[16];
        if (precomputed_salt_blk64) for (int i = 0; i < 16; ++i) salt_W[i] = precomputed_salt_blk64[i];
        else (void)prepare_salt_W(salt, salt_len, salt_W);
        __m512i Wsalt[16];
        for (int i = 0; i < 16; ++i) Wsalt[i] = _mm512_set1_epi64((long long)salt_W[i]);
        for (int i = 0; i < 16; ++i) W[i] = Wsalt[i];
        sha512_block64_avx512(ipad_iv_lo, W, s_lo);
        for (int i = 0; i < 16; ++i) W[i] = Wsalt[i];
        sha512_block64_avx512(ipad_iv_hi, W, s_hi);
    }

    __m512i T_lo[8], T_hi[8];
    for (int i = 0; i < 8; ++i) W[i] = s_lo[i];
    sha512_padded_block64_avx512_single(opad_iv_lo, W, T_lo);
    for (int i = 0; i < 8; ++i) W[i] = s_hi[i];
    sha512_padded_block64_avx512_single(opad_iv_hi, W, T_hi);

    pbkdf2_16lane_interleaved_stream(ipad_iv_lo, opad_iv_lo, ipad_iv_hi, opad_iv_hi, T_lo, T_hi, T_lo, T_hi,
                                     iterations);

    uint8_t* outs[16] = {out1, out2, out3, out4, out5, out6, out7, out8, out9, out10, out11, out12, out13, out14, out15, out16};
    // OTM-24: vpshufb AVX-512 — 8 × u64 por instrução. Máscara replicada 4×
    // (o vpshufb de 512 bits opera em 4 lanes independentes de 128 bits).
    alignas(64) static constexpr uint8_t bswap_bytes[64] = {
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    };
    const __m512i bswap_mask = _mm512_load_si512((const __m512i*)bswap_bytes);
    for (int i = 0; i < 8; ++i) {
        alignas(64) uint64_t lo[8], hi[8];
        _mm512_store_si512((__m512i*)lo, _mm512_shuffle_epi8(T_lo[i], bswap_mask));
        _mm512_store_si512((__m512i*)hi, _mm512_shuffle_epi8(T_hi[i], bswap_mask));
        for (int l = 0; l < 8; ++l) {
            std::memcpy(outs[l] + i * 8, &lo[l], 8);
            std::memcpy(outs[8 + l] + i * 8, &hi[l], 8);
        }
    }
}

#undef CH_AVX512
#undef MAJ_AVX512
#undef S0_AVX512
#undef S1_AVX512
#undef s0_AVX512
#undef s1_AVX512

#endif  // x86
