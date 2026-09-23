#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include "math/UInt.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <bit>
#include <xmmintrin.h>

// A rota SIMD só existe em x86 (mesmo padrão de sha512.cpp). Em outras
// arquiteturas os símbolos declarados em sha256.hpp continuam existindo,
// porém definidos pelos fallbacks escalares no fim deste arquivo.
// Defina SHA256_NO_SIMD para forçar a rota escalar em x86 (debug/compat).
#if !defined(SHA256_NO_SIMD) && (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86))
  #define SHA256_X86 1
  #include <immintrin.h>
#endif


// =========================================================================
// IMPLEMENTAÇÕES SIMD (Ocultas/Compiladas)
// =========================================================================

alignas(64) static constexpr std::array<uint32_t, 64> K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static constexpr std::array<uint32_t, 8> SHA256_IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

template <uint8_t lanes>
constexpr inline void sha256_init_simd(std::array<std::array<uint32_t, 8>, lanes> arr) noexcept {
    for (uint8_t i = 0; i < lanes; ++i) {
        arr[i] = SHA256_IV;
    }
}

void sha256_init_sse(SHA256_SSE_State* ctx) {
    sha256_init_simd<4>(ctx->state);
}
void sha256_init_avx2(SHA256_AVX2_State* ctx) {
    sha256_init_simd<8>(ctx->state);
}
void sha256_init_avx512(SHA256_AVX512_State* ctx) {
    sha256_init_simd<16>(ctx->state);
}


#ifdef SHA256_X86

// =========================================================================
// IMPLEMENTAÇÃO SSE4.1
// =========================================================================
[[gnu::target("sse4.1")]]
void sha256_transform_sse(SHA256_SSE_State* __restrict ctx, const std::array<std::array<uint32_t, 16>, 4> &W_in) {
    __m128i a = _mm_loadu_si128((__m128i*)ctx->state[0].data());
    __m128i b = _mm_loadu_si128((__m128i*)ctx->state[1].data());
    __m128i c = _mm_loadu_si128((__m128i*)ctx->state[2].data());
    __m128i d = _mm_loadu_si128((__m128i*)ctx->state[3].data());
    __m128i e = _mm_loadu_si128((__m128i*)ctx->state[4].data());
    __m128i f = _mm_loadu_si128((__m128i*)ctx->state[5].data());
    __m128i g = _mm_loadu_si128((__m128i*)ctx->state[6].data());
    __m128i h = _mm_loadu_si128((__m128i*)ctx->state[7].data());

    #define ROR128(x, n) _mm_xor_si128(_mm_srli_epi32(x, n), _mm_slli_epi32(x, 32 - (n)))
    #define CH128(x, y, z) _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z)))
    #define MAJ128(x, y, z) _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)))
    #define S0_128(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 2), ROR128(x, 13)), ROR128(x, 22))
    #define S1_128(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 6), ROR128(x, 11)), ROR128(x, 25))
    #define s0_128(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 7), ROR128(x, 18)), _mm_srli_epi32(x, 3))
    #define s1_128(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 17), ROR128(x, 19)), _mm_srli_epi32(x, 10))

    __m128i W[64];
    #pragma GCC unroll 16
    for (uint8_t t = 0; t < 16; t++)
        W[t] = _mm_loadu_si128((__m128i*)W_in[t].data());

    // Otimização de ILP extrema (Árvore binária de dependências)
    #pragma GCC unroll 48
    for (uint8_t t = 16; t < 64; t++) {
        __m128i s_1 = _mm_add_epi32(W[t - 16], s0_128(W[t - 15]));
        __m128i s_2 = _mm_add_epi32(W[t - 7], s1_128(W[t - 2]));
        W[t] = _mm_add_epi32(s_1, s_2);
    }

    #pragma GCC unroll 64
    for (uint8_t t = 0; t < 64; t++) {
        __m128i KW = _mm_add_epi32(_mm_set1_epi32(K256[t]), W[t]);
        __m128i h_S1 = _mm_add_epi32(h, S1_128(e));
        __m128i ch_KW = _mm_add_epi32(CH128(e, f, g), KW);
        __m128i T1 = _mm_add_epi32(h_S1, ch_KW);

        __m128i T2 = _mm_add_epi32(S0_128(a), MAJ128(a, b, c));

        h = g; g = f; f = e; e = _mm_add_epi32(d, T1);
        d = c; c = b; b = a; a = _mm_add_epi32(T1, T2);
    }
    #undef ROR128
    #undef CH128
    #undef MAJ128
    #undef S0_128
    #undef S1_128
    #undef s0_128
    #undef s1_128

    _mm_storeu_si128((__m128i*)ctx->state[0].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[0].data()), a));
    _mm_storeu_si128((__m128i*)ctx->state[1].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[1].data()), b));
    _mm_storeu_si128((__m128i*)ctx->state[2].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[2].data()), c));
    _mm_storeu_si128((__m128i*)ctx->state[3].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[3].data()), d));
    _mm_storeu_si128((__m128i*)ctx->state[4].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[4].data()), e));
    _mm_storeu_si128((__m128i*)ctx->state[5].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[5].data()), f));
    _mm_storeu_si128((__m128i*)ctx->state[6].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[6].data()), g));
    _mm_storeu_si128((__m128i*)ctx->state[7].data(), _mm_add_epi32(_mm_loadu_si128((__m128i*)ctx->state[7].data()), h));
}

// =========================================================================
// IMPLEMENTAÇÃO AVX2
// =========================================================================
[[gnu::target("avx2")]]
void sha256_transform_avx2(SHA256_AVX2_State* __restrict ctx, const uint32_t W_in[16][8]) {
    __m256i a = _mm256_loadu_si256((__m256i*)ctx->state[0].data());
    __m256i b = _mm256_loadu_si256((__m256i*)ctx->state[1].data());
    __m256i c = _mm256_loadu_si256((__m256i*)ctx->state[2].data());
    __m256i d = _mm256_loadu_si256((__m256i*)ctx->state[3].data());
    __m256i e = _mm256_loadu_si256((__m256i*)ctx->state[4].data());
    __m256i f = _mm256_loadu_si256((__m256i*)ctx->state[5].data());
    __m256i g = _mm256_loadu_si256((__m256i*)ctx->state[6].data());
    __m256i h = _mm256_loadu_si256((__m256i*)ctx->state[7].data());

    #define ROR256(x, n) _mm256_xor_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))
    #define CH256(x, y, z) _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
    #define MAJ256(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)))
    #define S0_256(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 2), ROR256(x, 13)), ROR256(x, 22))
    #define S1_256(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 6), ROR256(x, 11)), ROR256(x, 25))
    #define s0_256(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 7), ROR256(x, 18)), _mm256_srli_epi32(x, 3))
    #define s1_256(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 17), ROR256(x, 19)), _mm256_srli_epi32(x, 10))

    __m256i W[64];
    #pragma GCC unroll 16
    for (int t = 0; t < 16; t++) W[t] = _mm256_loadu_si256((__m256i*)W_in[t]);

    #pragma GCC unroll 48
    for (int t = 16; t < 64; t++) {
        __m256i s_1 = _mm256_add_epi32(W[t - 16], s0_256(W[t - 15]));
        __m256i s_2 = _mm256_add_epi32(W[t - 7], s1_256(W[t - 2]));
        W[t] = _mm256_add_epi32(s_1, s_2);
    }

    #pragma GCC unroll 64
    for (int t = 0; t < 64; t++) {
        __m256i KW = _mm256_add_epi32(_mm256_set1_epi32(K256[t]), W[t]);
        __m256i h_S1 = _mm256_add_epi32(h, S1_256(e));
        __m256i ch_KW = _mm256_add_epi32(CH256(e, f, g), KW);
        __m256i T1 = _mm256_add_epi32(h_S1, ch_KW);

        __m256i T2 = _mm256_add_epi32(S0_256(a), MAJ256(a, b, c));

        h = g; g = f; f = e; e = _mm256_add_epi32(d, T1);
        d = c; c = b; b = a; a = _mm256_add_epi32(T1, T2);
    }
    #undef ROR256
    #undef CH256
    #undef MAJ256
    #undef S0_256
    #undef S1_256
    #undef s0_256
    #undef s1_256

    _mm256_storeu_si256((__m256i*)ctx->state[0].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[0].data()), a));
    _mm256_storeu_si256((__m256i*)ctx->state[1].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[1].data()), b));
    _mm256_storeu_si256((__m256i*)ctx->state[2].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[2].data()), c));
    _mm256_storeu_si256((__m256i*)ctx->state[3].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[3].data()), d));
    _mm256_storeu_si256((__m256i*)ctx->state[4].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[4].data()), e));
    _mm256_storeu_si256((__m256i*)ctx->state[5].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[5].data()), f));
    _mm256_storeu_si256((__m256i*)ctx->state[6].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[6].data()), g));
    _mm256_storeu_si256((__m256i*)ctx->state[7].data(), _mm256_add_epi32(_mm256_loadu_si256((__m256i*)ctx->state[7].data()), h));
}

// =========================================================================
// IMPLEMENTAÇÃO AVX-512
// =========================================================================
[[gnu::target("avx512f,avx512vl")]]
void sha256_transform_avx512(SHA256_AVX512_State* __restrict ctx, const uint32_t W_in[16][16]) {
    __m512i a = _mm512_loadu_si512((__m512i*)ctx->state[0].data());
    __m512i b = _mm512_loadu_si512((__m512i*)ctx->state[1].data());
    __m512i c = _mm512_loadu_si512((__m512i*)ctx->state[2].data());
    __m512i d = _mm512_loadu_si512((__m512i*)ctx->state[3].data());
    __m512i e = _mm512_loadu_si512((__m512i*)ctx->state[4].data());
    __m512i f = _mm512_loadu_si512((__m512i*)ctx->state[5].data());
    __m512i g = _mm512_loadu_si512((__m512i*)ctx->state[6].data());
    __m512i h = _mm512_loadu_si512((__m512i*)ctx->state[7].data());

    #define CH512(x, y, z) _mm512_ternarylogic_epi32(x, y, z, 0xCA)
    #define MAJ512(x, y, z) _mm512_ternarylogic_epi32(x, y, z, 0xE8)
    #define S0_512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(x, 2), _mm512_ror_epi32(x, 13)), _mm512_ror_epi32(x, 22))
    #define S1_512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(x, 6), _mm512_ror_epi32(x, 11)), _mm512_ror_epi32(x, 25))
    #define s0_512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(x, 7), _mm512_ror_epi32(x, 18)), _mm512_srli_epi32(x, 3))
    #define s1_512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(x, 17), _mm512_ror_epi32(x, 19)), _mm512_srli_epi32(x, 10))

    __m512i W[64];
    #pragma GCC unroll 16
    for (int t = 0; t < 16; t++) W[t] = _mm512_loadu_si512((__m512i*)W_in[t]);

    #pragma GCC unroll 48
    for (int t = 16; t < 64; t++) {
        __m512i s_1 = _mm512_add_epi32(W[t - 16], s0_512(W[t - 15]));
        __m512i s_2 = _mm512_add_epi32(W[t - 7], s1_512(W[t - 2]));
        W[t] = _mm512_add_epi32(s_1, s_2);
    }

    #pragma GCC unroll 64
    for (int t = 0; t < 64; t++) {
        __m512i KW = _mm512_add_epi32(_mm512_set1_epi32(K256[t]), W[t]);
        __m512i h_S1 = _mm512_add_epi32(h, S1_512(e));
        __m512i ch_KW = _mm512_add_epi32(CH512(e, f, g), KW);
        __m512i T1 = _mm512_add_epi32(h_S1, ch_KW);

        __m512i T2 = _mm512_add_epi32(S0_512(a), MAJ512(a, b, c));

        h = g; g = f; f = e; e = _mm512_add_epi32(d, T1);
        d = c; c = b; b = a; a = _mm512_add_epi32(T1, T2);
    }
    #undef CH512
    #undef MAJ512
    #undef S0_512
    #undef S1_512
    #undef s0_512
    #undef s1_512

    _mm512_storeu_si512((__m512i*)ctx->state[0].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[0].data()), a));
    _mm512_storeu_si512((__m512i*)ctx->state[1].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[1].data()), b));
    _mm512_storeu_si512((__m512i*)ctx->state[2].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[2].data()), c));
    _mm512_storeu_si512((__m512i*)ctx->state[3].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[3].data()), d));
    _mm512_storeu_si512((__m512i*)ctx->state[4].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[4].data()), e));
    _mm512_storeu_si512((__m512i*)ctx->state[5].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[5].data()), f));
    _mm512_storeu_si512((__m512i*)ctx->state[6].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[6].data()), g));
    _mm512_storeu_si512((__m512i*)ctx->state[7].data(), _mm512_add_epi32(_mm512_loadu_si512((__m512i*)ctx->state[7].data()), h));
}

#else  // !SHA256_X86 — fallbacks portáveis (lane a lane), sem intrínsecas

namespace sha256_scalar_fallback {

[[gnu::always_inline]] inline uint32_t ror(uint32_t x, int n) noexcept { return std::rotr(x, n); }
[[gnu::always_inline]] inline uint32_t bsig0(uint32_t x) noexcept { return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22); }
[[gnu::always_inline]] inline uint32_t bsig1(uint32_t x) noexcept { return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25); }
[[gnu::always_inline]] inline uint32_t ssig0(uint32_t x) noexcept { return ror(x, 7) ^ ror(x, 18) ^ (x >> 3); }
[[gnu::always_inline]] inline uint32_t ssig1(uint32_t x) noexcept { return ror(x, 17) ^ ror(x, 19) ^ (x >> 10); }
[[gnu::always_inline]] inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (~x & z); }
[[gnu::always_inline]] inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }

template <unsigned Lanes>
inline void transform_lanes(uint32_t (&state)[8][Lanes], const uint32_t W_in[16][Lanes]) noexcept {
    for (unsigned lane = 0; lane < Lanes; ++lane) {
    std::array<uint32_t, 64> W;
        #pragma GCC unroll 16
        for (int t = 0; t < 16; ++t) W[t] = W_in[t][lane];
        #pragma GCC unroll 48
        for (int t = 16; t < 64; ++t)
            W[t] = ssig1(W[t - 2]) + W[t - 7] + ssig0(W[t - 15]) + W[t - 16];

        uint32_t a = state[0][lane], b = state[1][lane], c = state[2][lane], d = state[3][lane];
        uint32_t e = state[4][lane], f = state[5][lane], g = state[6][lane], h = state[7][lane];

        #pragma GCC unroll 64
        for (int t = 0; t < 64; ++t) {
            const uint32_t T1 = h + bsig1(e) + ch(e, f, g) + K256[t] + W[t];
            const uint32_t T2 = bsig0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        state[0][lane] += a; state[1][lane] += b; state[2][lane] += c; state[3][lane] += d;
        state[4][lane] += e; state[5][lane] += f; state[6][lane] += g; state[7][lane] += h;
    }
}

} // namespace sha256_scalar_fallback

void sha256_transform_sse(SHA256_SSE_State* ctx, const uint32_t W_in[16][4]) {
    sha256_scalar_fallback::transform_lanes<4>(ctx->state, W_in);
}
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]) {
    sha256_scalar_fallback::transform_lanes<8>(ctx->state, W_in);
}
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]) {
    sha256_scalar_fallback::transform_lanes<16>(ctx->state, W_in);
}

#endif // SHA256_X86

// =========================================================================
// IMPLEMENTAÇÃO ESCALAR
// =========================================================================

namespace crypto {

[[gnu::always_inline]] static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
[[gnu::always_inline]] static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
[[gnu::always_inline]] static inline uint32_t Sigma0(uint32_t x) { return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22); }
[[gnu::always_inline]] static inline uint32_t Sigma1(uint32_t x) { return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25); }
[[gnu::always_inline]] static inline uint32_t sigma0(uint32_t x) { return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3); }
[[gnu::always_inline]] static inline uint32_t sigma1(uint32_t x) { return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10); }

SHA256::SHA256() { reset(); }

void SHA256::reset() {
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i)
        h_[i] = SHA256_IV[i];

    total_len_ = 0;
    buf_len_ = 0;
}

void SHA256::update(const void* data, size_t len) {
    auto p = static_cast<const uint8_t*>(data);
    total_len_ += len;

    if (buf_len_ > 0) {
        size_t to_copy = std::min(len, static_cast<size_t>(64) - buf_len_);
        std::memcpy(buf_ + buf_len_, p, to_copy);
        buf_len_ += to_copy;
        p += to_copy;
        len -= to_copy;
        if (buf_len_ == 64) {
            process_block(buf_);
            buf_len_ = 0;
        }
    }

    while (len >= 64) {
        process_block(p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_len_ = len;
    }
}

void SHA256::finalize(uint8_t out[32]) {
    uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 56) {
        std::memset(buf_ + buf_len_, 0, 64 - buf_len_);
        process_block(buf_);
        buf_len_ = 0;
    }
    std::memset(buf_ + buf_len_, 0, 56 - buf_len_);

    uint64_t bit_len_be = std::byteswap(bit_len);
    std::memcpy(buf_ + 56, &bit_len_be, 8);
    process_block(buf_);

    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        uint32_t out_be = std::byteswap(h_[i]);
        std::memcpy(&out[i * 4], &out_be, 4);
    }
}

void SHA256::hash(const void* data, uint8_t len, uint8_t out[32]) {
    if (len <= 55) {
        alignas(16) uint8_t block[64] = {0};
        if (len != 0) std::memcpy(block, data, len);
        block[len] = 0x80;
        uint64_t bit_len_be = __builtin_bswap64(static_cast<uint64_t>(len) * 8);
        std::memcpy(block + 56, &bit_len_be, 8);

#if defined(__SHA__)
        std::array<uint32_t, 8> state = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        cryptowords::detail::sha256_process_x86(state.data(), block, 64);
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            uint32_t out_be = __builtin_bswap32(state[i]);
            std::memcpy(out + i * 4, &out_be, 4);
        }
        return;
#else
        SHA256 ctx;
        ctx.process_block(block);
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            uint32_t out_be = __builtin_bswap32(ctx.h_[i]);
            std::memcpy(out + i * 4, &out_be, 4);
        }
        return;
#endif
    }

    SHA256 ctx;
    ctx.update(data, len);
    ctx.finalize(out);
}

void SHA256::hash33(const std::array<u8, 33> &in, std::array<u8, 32> &out) noexcept {
    hash(in.data(), 33, out.data());
}

void SHA256::process_block(const uint8_t block[64]) {

    uint32_t W[64];
    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) {
        std::memcpy(&W[i], &block[i * 4], 4);
        W[i] = std::byteswap(W[i]);
    }
    #pragma GCC unroll 48
    for (int i = 16; i < 64; ++i) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

    #pragma GCC unroll 64
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K256[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

}
