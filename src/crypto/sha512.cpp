#include "../../include/crypto/sha512.hpp"
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <bit>
#include <emmintrin.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

// =========================================================================
// CONSTANTES
// =========================================================================

alignas(64) static constexpr uint64_t K512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static constexpr uint64_t SHA512_IV[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// =========================================================================
// INICIALIZAÇÃO SIMD
// =========================================================================

void sha512_init_sse(SHA512_SSE_State* ctx) {
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) { ctx->state[i][0] = SHA512_IV[i]; ctx->state[i][1] = SHA512_IV[i]; }
}
void sha512_init_avx2(SHA512_AVX2_State* ctx) {
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) for (int j = 0; j < 4; ++j) ctx->state[i][j] = SHA512_IV[i];
}
void sha512_init_avx512(SHA512_AVX512_State* ctx) {
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) for (int j = 0; j < 8; ++j) ctx->state[i][j] = SHA512_IV[i];
}

// =========================================================================
// MACROS DE ROTAÇÃO
// =========================================================================

#define ROR128_64(x, n) _mm_xor_si128  (_mm_srli_epi64  (x, n), _mm_slli_epi64  (x, 64 - (n)))
#define ROR256_64(x, n) _mm256_xor_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))



// =========================================================================
// SSE4.1 — 2 hashes paralelos (janela deslizante W[16])
// =========================================================================
[[gnu::target("sse4.1")]]
void sha512_transform_sse(SHA512_SSE_State* ctx, const uint64_t W_in[16][2]) {
    __m128i a = _mm_loadu_si128((__m128i*)ctx->state[0]);
    __m128i b = _mm_loadu_si128((__m128i*)ctx->state[1]);
    __m128i c = _mm_loadu_si128((__m128i*)ctx->state[2]);
    __m128i d = _mm_loadu_si128((__m128i*)ctx->state[3]);
    __m128i e = _mm_loadu_si128((__m128i*)ctx->state[4]);
    __m128i f = _mm_loadu_si128((__m128i*)ctx->state[5]);
    __m128i g = _mm_loadu_si128((__m128i*)ctx->state[6]);
    __m128i h = _mm_loadu_si128((__m128i*)ctx->state[7]);

    #define CH_SSE(x, y, z) _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z)))
    #define MAJ_SSE(x, y, z) _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)))
    #define S0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 28), ROR128_64(x, 34)), ROR128_64(x, 39))
    #define S1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 14), ROR128_64(x, 18)), ROR128_64(x, 41))
    #define s0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 1), ROR128_64(x, 8)), _mm_srli_epi64(x, 7))
    #define s1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 19), ROR128_64(x, 61)), _mm_srli_epi64(x, 6))

    __m128i W[16];
    #pragma GCC unroll 16
    for (int t = 0; t < 16; ++t) W[t] = _mm_loadu_si128((__m128i*)W_in[t]);

    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            const __m128i k = _mm_set1_epi64x((long long)K512[r * 16 + i]);

            __m128i h_s1  = _mm_add_epi64(h, S1_SSE(e));
            __m128i ch_k  = _mm_add_epi64(CH_SSE(e, f, g), k);
            __m128i ch_kw = _mm_add_epi64(ch_k, W[i]);
            __m128i T1    = _mm_add_epi64(h_s1, ch_kw);
            __m128i T2    = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));

            h = g; g = f; f = e;
            e = _mm_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm_add_epi64(T1, T2);

            if (r < 4) {
                const __m128i w1  = W[(i + 1)  & 15];
                const __m128i w9  = W[(i + 9)  & 15];
                const __m128i w14 = W[(i + 14) & 15];
                W[i] = _mm_add_epi64(W[i],
                        _mm_add_epi64(_mm_add_epi64(s0_SSE(w1), w9), s1_SSE(w14)));
            }
        }
    }
    #undef CH_SSE
    #undef MAJ_SSE
    #undef S0_SSE
    #undef S1_SSE
    #undef s0_SSE
    #undef s1_SSE

    #define STORE_ADD(idx, reg) _mm_storeu_si128((__m128i*)ctx->state[idx], \
        _mm_add_epi64(_mm_loadu_si128((__m128i*)ctx->state[idx]), (reg)))
    STORE_ADD(0, a); STORE_ADD(1, b); STORE_ADD(2, c); STORE_ADD(3, d);
    STORE_ADD(4, e); STORE_ADD(5, f); STORE_ADD(6, g); STORE_ADD(7, h);
    #undef STORE_ADD
}

// =========================================================================
// AVX2 — 4 hashes paralelos
// =========================================================================
[[gnu::target("avx2")]]
void sha512_transform_avx2(SHA512_AVX2_State* ctx, const uint64_t W_in[16][4]) {
    __m256i a = _mm256_loadu_si256((__m256i*)ctx->state[0]);
    __m256i b = _mm256_loadu_si256((__m256i*)ctx->state[1]);
    __m256i c = _mm256_loadu_si256((__m256i*)ctx->state[2]);
    __m256i d = _mm256_loadu_si256((__m256i*)ctx->state[3]);
    __m256i e = _mm256_loadu_si256((__m256i*)ctx->state[4]);
    __m256i f = _mm256_loadu_si256((__m256i*)ctx->state[5]);
    __m256i g = _mm256_loadu_si256((__m256i*)ctx->state[6]);
    __m256i h = _mm256_loadu_si256((__m256i*)ctx->state[7]);

    #define CH_AVX2(x, y, z) _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
    #define MAJ_AVX2(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)))
    #define S0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 28), ROR256_64(x, 34)), ROR256_64(x, 39))
    #define S1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 14), ROR256_64(x, 18)), ROR256_64(x, 41))
    #define s0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 1), ROR256_64(x, 8)), _mm256_srli_epi64(x, 7))
    #define s1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 19), ROR256_64(x, 61)), _mm256_srli_epi64(x, 6))

    __m256i W[16];
    #pragma GCC unroll 16
    for (int t = 0; t < 16; ++t) W[t] = _mm256_loadu_si256((__m256i*)W_in[t]);

    // ---- 5 blocos de 16 rodadas. Schedule interleavado em cada rodada. ----
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            const __m256i k = _mm256_set1_epi64x((long long)K512[r * 16 + i]);

            // Árvore balanceada: T1 = ((h + S1) + ((Ch + k) + W))
            __m256i h_s1  = _mm256_add_epi64(h, S1_AVX2(e));
            __m256i ch_k  = _mm256_add_epi64(CH_AVX2(e, f, g), k);
            __m256i ch_kw = _mm256_add_epi64(ch_k, W[i]);
            __m256i T1    = _mm256_add_epi64(h_s1, ch_kw);
            __m256i T2    = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));

            h = g; g = f; f = e;
            e = _mm256_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm256_add_epi64(T1, T2);

            // --- Schedule update: W[i] = W[i] + s0(W[i+1]) + W[i+9] + s1(W[i+14])
            //     Todas as leituras usam índices mod 16 já atualizados corretamente.
            if (r < 4) {
                const __m256i w1  = W[(i + 1)  & 15];
                const __m256i w9  = W[(i + 9)  & 15];
                const __m256i w14 = W[(i + 14) & 15];

                __m256i s0w1  = s0_AVX2(w1);
                __m256i s1w14 = s1_AVX2(w14);

                W[i] = _mm256_add_epi64(W[i],
                        _mm256_add_epi64(_mm256_add_epi64(s0w1, w9), s1w14));
            }
        }
    }
    #undef CH_AVX2
    #undef MAJ_AVX2
    #undef S0_AVX2
    #undef S1_AVX2
    #undef s0_AVX2
    #undef s1_AVX2

    #define STORE_ADD(idx, reg) _mm256_storeu_si256((__m256i*)ctx->state[idx], \
        _mm256_add_epi64(_mm256_loadu_si256((__m256i*)ctx->state[idx]), (reg)))
    STORE_ADD(0, a); STORE_ADD(1, b); STORE_ADD(2, c); STORE_ADD(3, d);
    STORE_ADD(4, e); STORE_ADD(5, f); STORE_ADD(6, g); STORE_ADD(7, h);
    #undef STORE_ADD
}

// =========================================================================
// AVX-512 — 8 hashes paralelos
// =========================================================================
[[gnu::target("avx512f,avx512vl,avx512bw")]]
void sha512_transform_avx512(SHA512_AVX512_State* ctx, const uint64_t W_in[16][8]) {
    __m512i a = _mm512_loadu_si512((__m512i*)ctx->state[0]);
    __m512i b = _mm512_loadu_si512((__m512i*)ctx->state[1]);
    __m512i c = _mm512_loadu_si512((__m512i*)ctx->state[2]);
    __m512i d = _mm512_loadu_si512((__m512i*)ctx->state[3]);
    __m512i e = _mm512_loadu_si512((__m512i*)ctx->state[4]);
    __m512i f = _mm512_loadu_si512((__m512i*)ctx->state[5]);
    __m512i g = _mm512_loadu_si512((__m512i*)ctx->state[6]);
    __m512i h = _mm512_loadu_si512((__m512i*)ctx->state[7]);

    #define CH_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xCA)
    #define MAJ_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xE8)
    #define S0_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34)), _mm512_ror_epi64(x, 39))
    #define S1_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18)), _mm512_ror_epi64(x, 41))
    #define s0_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 1), _mm512_ror_epi64(x, 8)), _mm512_srli_epi64(x, 7))
    #define s1_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61)), _mm512_srli_epi64(x, 6))

    __m512i W[16];
    #pragma GCC unroll 16
    for (int t = 0; t < 16; ++t) W[t] = _mm512_loadu_si512((__m512i*)W_in[t]);

    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            const __m512i k = _mm512_set1_epi64((long long)K512[r * 16 + i]);

            __m512i h_s1  = _mm512_add_epi64(h, S1_AVX512(e));
            __m512i ch_k  = _mm512_add_epi64(CH_AVX512(e, f, g), k);
            __m512i ch_kw = _mm512_add_epi64(ch_k, W[i]);
            __m512i T1    = _mm512_add_epi64(h_s1, ch_kw);
            __m512i T2    = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));

            h = g; g = f; f = e;
            e = _mm512_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm512_add_epi64(T1, T2);

            if (r < 4) {
                const __m512i w1  = W[(i + 1)  & 15];
                const __m512i w9  = W[(i + 9)  & 15];
                const __m512i w14 = W[(i + 14) & 15];
                W[i] = _mm512_add_epi64(W[i],
                        _mm512_add_epi64(_mm512_add_epi64(s0_AVX512(w1), w9), s1_AVX512(w14)));
            }
        }
    }
    #undef CH_AVX512
    #undef MAJ_AVX512
    #undef S0_AVX512
    #undef S1_AVX512
    #undef s0_AVX512
    #undef s1_AVX512

    #define STORE_ADD(idx, reg) _mm512_storeu_si512((__m512i*)ctx->state[idx], \
        _mm512_add_epi64(_mm512_loadu_si512((__m512i*)ctx->state[idx]), (reg)))
    STORE_ADD(0, a); STORE_ADD(1, b); STORE_ADD(2, c); STORE_ADD(3, d);
    STORE_ADD(4, e); STORE_ADD(5, f); STORE_ADD(6, g); STORE_ADD(7, h);
    #undef STORE_ADD
}

#undef ROR128_64
#undef ROR256_64

// =========================================================================
// ESCALAR
// =========================================================================

namespace crypto {

[[gnu::always_inline]] static inline uint64_t Ch64    (uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
[[gnu::always_inline]] static inline uint64_t Maj64   (uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
[[gnu::always_inline]] static inline uint64_t Sigma0_64(uint64_t x) { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); }
[[gnu::always_inline]] static inline uint64_t Sigma1_64(uint64_t x) { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); }
[[gnu::always_inline]] static inline uint64_t sigma0_64(uint64_t x) { return std::rotr(x, 1)  ^ std::rotr(x, 8)  ^ (x >> 7); }
[[gnu::always_inline]] static inline uint64_t sigma1_64(uint64_t x) { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }

SHA512::SHA512() { reset(); }

void SHA512::reset() {
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) h_[i] = SHA512_IV[i];
    total_len_ = 0;
    buf_len_   = 0;
}

void SHA512::update(const void* data, size_t len) {
    auto p = static_cast<const uint8_t*>(data);
    total_len_ += len;

    if (buf_len_ > 0) {
        size_t to_copy = std::min(len, static_cast<size_t>(128) - buf_len_);
        std::memcpy(buf_ + buf_len_, p, to_copy);
        buf_len_ += to_copy;
        p += to_copy;
        len -= to_copy;
        if (buf_len_ == 128) { process_block(buf_); buf_len_ = 0; }
    }
    while (len >= 128) { process_block(p); p += 128; len -= 128; }
    if (len > 0) { std::memcpy(buf_, p, len); buf_len_ = len; }
}

void SHA512::finalize(uint8_t out[64]) {
    const uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 112) {
        std::memset(buf_ + buf_len_, 0, 128 - buf_len_);
        process_block(buf_);
        buf_len_ = 0;
    }
    std::memset(buf_ + buf_len_, 0, 112 - buf_len_);
    std::memset(buf_ + 112, 0, 8);
    const uint64_t bit_len_be = __builtin_bswap64(bit_len);
    std::memcpy(buf_ + 120, &bit_len_be, 8);
    process_block(buf_);

    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        uint64_t v = __builtin_bswap64(h_[i]);
        std::memcpy(out + i * 8, &v, 8);
    }
}

void SHA512::hash(const void* data, size_t len, uint8_t out[64]) {
    SHA512 ctx; ctx.update(data, len); ctx.finalize(out);
}

void SHA512::process_block(const uint8_t block[128]) {
    uint64_t W[16];
    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) {
        uint64_t v; std::memcpy(&v, block + i * 8, 8);
        W[i] = __builtin_bswap64(v);
    }

    uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            const uint64_t T1 = h + Sigma1_64(e) + Ch64(e, f, g) + K512[r * 16 + i] + W[i];
            const uint64_t T2 = Sigma0_64(a) + Maj64(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
        if (r < 4) {
            #pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                const uint64_t w1  = W[(i + 1)  & 15];
                const uint64_t w9  = W[(i + 9)  & 15];
                const uint64_t w14 = W[(i + 14) & 15];
                const uint64_t s0v = std::rotr(w1, 1) ^ std::rotr(w1, 8) ^ (w1 >> 7);
                const uint64_t s1v = std::rotr(w14, 19) ^ std::rotr(w14, 61) ^ (w14 >> 6);
                W[i] += s0v + w9 + s1v;
            }
        }
    }

    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

// =========================================================================
// TRANSPOSE HELPERS
// =========================================================================
#ifdef __x86_64__
// 8x8 de epi64 (AVX-512) — 24 shuffles para 8 vetores
[[gnu::target("avx512f,avx512vl")]]
static inline void transpose8x8_epi64(__m512i v[8]) {
    __m512i a[8];
    a[0] = _mm512_unpacklo_epi64(v[0], v[1]);
    a[1] = _mm512_unpackhi_epi64(v[0], v[1]);
    a[2] = _mm512_unpacklo_epi64(v[2], v[3]);
    a[3] = _mm512_unpackhi_epi64(v[2], v[3]);
    a[4] = _mm512_unpacklo_epi64(v[4], v[5]);
    a[5] = _mm512_unpackhi_epi64(v[4], v[5]);
    a[6] = _mm512_unpacklo_epi64(v[6], v[7]);
    a[7] = _mm512_unpackhi_epi64(v[6], v[7]);

    __m512i b[8];
    b[0] = _mm512_shuffle_i64x2(a[0], a[2], 0x88);
    b[1] = _mm512_shuffle_i64x2(a[1], a[3], 0x88);
    b[2] = _mm512_shuffle_i64x2(a[0], a[2], 0xDD);
    b[3] = _mm512_shuffle_i64x2(a[1], a[3], 0xDD);
    b[4] = _mm512_shuffle_i64x2(a[4], a[6], 0x88);
    b[5] = _mm512_shuffle_i64x2(a[5], a[7], 0x88);
    b[6] = _mm512_shuffle_i64x2(a[4], a[6], 0xDD);
    b[7] = _mm512_shuffle_i64x2(a[5], a[7], 0xDD);

    v[0] = _mm512_shuffle_i64x2(b[0], b[4], 0x88);
    v[1] = _mm512_shuffle_i64x2(b[1], b[5], 0x88);
    v[2] = _mm512_shuffle_i64x2(b[2], b[6], 0x88);
    v[3] = _mm512_shuffle_i64x2(b[3], b[7], 0x88);
    v[4] = _mm512_shuffle_i64x2(b[0], b[4], 0xDD);
    v[5] = _mm512_shuffle_i64x2(b[1], b[5], 0xDD);
    v[6] = _mm512_shuffle_i64x2(b[2], b[6], 0xDD);
    v[7] = _mm512_shuffle_i64x2(b[3], b[7], 0xDD);
}

// 4x4 de epi64 (AVX2) — 8 ops para 4 vetores
[[gnu::target("avx2")]]
static inline void transpose4x4_epi64(__m256i v[4]) {
    __m256i a0 = _mm256_unpacklo_epi64(v[0], v[1]);
    __m256i a1 = _mm256_unpackhi_epi64(v[0], v[1]);
    __m256i a2 = _mm256_unpacklo_epi64(v[2], v[3]);
    __m256i a3 = _mm256_unpackhi_epi64(v[2], v[3]);
    v[0] = _mm256_permute2x128_si256(a0, a2, 0x20);
    v[1] = _mm256_permute2x128_si256(a1, a3, 0x20);
    v[2] = _mm256_permute2x128_si256(a0, a2, 0x31);
    v[3] = _mm256_permute2x128_si256(a1, a3, 0x31);
}
#endif

// -------------------------------------------------------------------------
// TEMPLATE HASHING — preset / complete (single-hash)
// -------------------------------------------------------------------------
void SHA512::preset(const void* prefix, size_t prefix_len, size_t suffix_len) {
    reset();
    update(prefix, prefix_len);
    template_suffix_len_ = suffix_len;

    if (buf_len_ + suffix_len <= 111) {
        template_single_block_ = true;
        const size_t pad_start = buf_len_ + suffix_len;

        buf_[pad_start] = 0x80;
        if (pad_start + 1 < 112)
            std::memset(buf_ + pad_start + 1, 0, 112 - (pad_start + 1));

        const uint64_t total_bits = (total_len_ + suffix_len) * 8;
        const uint64_t bit_len_be = __builtin_bswap64(total_bits);
        std::memset(buf_ + 112, 0, 8);
        std::memcpy(buf_ + 120, &bit_len_be, 8);
    } else {
        template_single_block_ = false;
    }
}

void SHA512::complete(const void* suffix, uint8_t out[64]) const {
    complete(suffix, template_suffix_len_, out);
}

void SHA512::complete(const void* suffix, size_t suffix_len, uint8_t out[64]) const {
    SHA512 temp = *this;
    if (template_single_block_ && suffix_len == template_suffix_len_) {
        std::memcpy(temp.buf_ + temp.buf_len_, suffix, template_suffix_len_);
        temp.process_block(temp.buf_);
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            uint64_t v = __builtin_bswap64(temp.h_[i]);
            std::memcpy(out + i * 8, &v, 8);
        }
    } else {
        temp.update(suffix, suffix_len);
        temp.finalize(out);
    }
}

// =========================================================================
// BATCH SIMD — N hashes em paralelo
// =========================================================================

void SHA512::complete_batch_scalar(const void* suffixes, size_t stride,
                                   uint8_t* out, size_t count) const {
    const auto* base = static_cast<const uint8_t*>(suffixes);
    for (size_t i = 0; i < count; ++i)
        complete(base + i * stride, out + i * 64);
}

// ---------- SSE4.1 (2 lanes) ----------
#ifdef __x86_64__
[[gnu::target("sse4.1")]]
void SHA512::complete_batch_sse(const void* suffixes, size_t stride,
                                uint8_t* out, size_t count) const {
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    const __m128i bswap_mask = _mm_set_epi8(
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7);

    const size_t slot = buf_len_;
    const size_t slen = template_suffix_len_;
    const auto*  base_ptr = static_cast<const uint8_t*>(suffixes);

    alignas(16) uint8_t blocks[2][128];
    std::memcpy(blocks[0], buf_, 128);
    std::memcpy(blocks[1], buf_, 128);

    for (size_t base = 0; base < count; base += 2) {
        const size_t lanes = (count - base < 2) ? (count - base) : 2;

        for (size_t l = 0; l < lanes; ++l)
            std::memcpy(blocks[l] + slot, base_ptr + (base + l) * stride, slen);
        if (lanes < 2)
            std::memcpy(blocks[1] + slot, base_ptr + (base + lanes - 1) * stride, slen);

        // Transpõe 2 blocos × 16 palavras → W[16]
        __m128i W[16];
        #pragma GCC unroll 8
        for (int t = 0; t < 16; t += 2) {
            __m128i A = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(blocks[0] + t * 8)), bswap_mask);
            __m128i B = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(blocks[1] + t * 8)), bswap_mask);
            W[t]     = _mm_unpacklo_epi64(A, B);
            W[t + 1] = _mm_unpackhi_epi64(A, B);
        }

        SHA512_SSE_State state;
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            _mm_store_si128((__m128i*)state.state[i], _mm_set1_epi64x((long long)h_[i]));

        sha512_transform_sse(&state, reinterpret_cast<const uint64_t(*)[2]>(W));

        alignas(16) uint64_t tmp[8][2];
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            _mm_store_si128((__m128i*)tmp[i], _mm_load_si128((const __m128i*)state.state[i]));

        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            for (size_t l = 0; l < lanes; ++l) {
                uint64_t v = __builtin_bswap64(tmp[i][l]);
                std::memcpy(out + (base + l) * 64 + i * 8, &v, 8);
            }
        }
    }
}

// ---------- AVX2 (4 lanes) ----------
[[gnu::target("avx2")]]
void SHA512::complete_batch_avx2(const void* suffixes, size_t stride,
                                 uint8_t* out, size_t count) const {
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    const __m256i bswap_mask = _mm256_set_epi8(
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7);

    const size_t slot = buf_len_;
    const size_t slen = template_suffix_len_;
    const auto*  base_ptr = static_cast<const uint8_t*>(suffixes);

    alignas(32) uint8_t blocks[4][128];
    #pragma GCC unroll 4
    for (int l = 0; l < 4; ++l) std::memcpy(blocks[l], buf_, 128);

    for (size_t base = 0; base < count; base += 4) {
        const size_t lanes = (count - base < 4) ? (count - base) : 4;

        for (size_t l = 0; l < lanes; ++l)
            std::memcpy(blocks[l] + slot, base_ptr + (base + l) * stride, slen);
        for (size_t l = lanes; l < 4; ++l)
            std::memcpy(blocks[l] + slot, base_ptr + (base + lanes - 1) * stride, slen);

        // Transpõe 4 blocos × 16 palavras → W[16]
        __m256i W[16];
        #pragma GCC unroll 4
        for (int t = 0; t < 16; t += 4) {
            __m256i v[4];
            #pragma GCC unroll 4
            for (int l = 0; l < 4; ++l)
                v[l] = _mm256_shuffle_epi8(
                    _mm256_loadu_si256((const __m256i*)(blocks[l] + t * 8)), bswap_mask);
            transpose4x4_epi64(v);
            #pragma GCC unroll 4
            for (int i = 0; i < 4; ++i) W[t + i] = v[i];
        }

        SHA512_AVX2_State state;
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            _mm256_store_si256((__m256i*)state.state[i], _mm256_set1_epi64x((long long)h_[i]));

        sha512_transform_avx2(&state, reinterpret_cast<const uint64_t(*)[4]>(W));

        // Transpõe resultado: dois 4x4 (words 0-3 e 4-7)
        transpose4x4_epi64(reinterpret_cast<__m256i*>(state.state));
        transpose4x4_epi64(reinterpret_cast<__m256i*>(state.state) + 4);

        #pragma GCC unroll 4
        for (size_t l = 0; l < lanes; ++l) {
            __m256i lo = _mm256_shuffle_epi8(_mm256_load_si256((const __m256i*)state.state[l]),     bswap_mask);
            __m256i hi = _mm256_shuffle_epi8(_mm256_load_si256((const __m256i*)state.state[l + 4]), bswap_mask);
            _mm256_storeu_si256((__m256i*)(out + (base + l) * 64),     lo);
            _mm256_storeu_si256((__m256i*)(out + (base + l) * 64 + 32), hi);
        }
    }
}

// ---------- AVX-512 (8 lanes) ----------
[[gnu::target("avx512f,avx512vl,avx512bw")]]
void SHA512::complete_batch_avx512(const void* suffixes, size_t stride,
                                   uint8_t* out, size_t count) const {
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    const __m512i bswap_mask = _mm512_set_epi8(
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7);

    const size_t slot = buf_len_;
    const size_t slen = template_suffix_len_;
    const auto*  base_ptr = static_cast<const uint8_t*>(suffixes);

    alignas(64) uint8_t blocks[8][128];
    #pragma GCC unroll 8
    for (int l = 0; l < 8; ++l) std::memcpy(blocks[l], buf_, 128);

    for (size_t base = 0; base < count; base += 8) {
        const size_t lanes = (count - base < 8) ? (count - base) : 8;

        for (size_t l = 0; l < lanes; ++l)
            std::memcpy(blocks[l] + slot, base_ptr + (base + l) * stride, slen);
        for (size_t l = lanes; l < 8; ++l)
            std::memcpy(blocks[l] + slot, base_ptr + (base + lanes - 1) * stride, slen);

        // Transpõe 8 blocos × 16 palavras → W[16]
        __m512i W[16];
        {
            __m512i v[8];
            #pragma GCC unroll 8
            for (int l = 0; l < 8; ++l)
                v[l] = _mm512_shuffle_epi8(
                    _mm512_loadu_si512((const __m512i*)blocks[l]), bswap_mask);
            transpose8x8_epi64(v);
            #pragma GCC unroll 8
            for (int t = 0; t < 8; ++t) W[t] = v[t];

            #pragma GCC unroll 8
            for (int l = 0; l < 8; ++l)
                v[l] = _mm512_shuffle_epi8(
                    _mm512_loadu_si512((const __m512i*)(blocks[l] + 64)), bswap_mask);
            transpose8x8_epi64(v);
            #pragma GCC unroll 8
            for (int t = 0; t < 8; ++t) W[8 + t] = v[t];
        }

        SHA512_AVX512_State state;
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            _mm512_store_si512((__m512i*)state.state[i], _mm512_set1_epi64((long long)h_[i]));

        sha512_transform_avx512(&state, reinterpret_cast<const uint64_t(*)[8]>(W));

        transpose8x8_epi64(reinterpret_cast<__m512i*>(state.state));

        #pragma GCC unroll 8
        for (size_t l = 0; l < lanes; ++l) {
            __m512i v = _mm512_load_si512((const __m512i*)state.state[l]);
            v = _mm512_shuffle_epi8(v, bswap_mask);
            _mm512_storeu_si512((__m512i*)(out + (base + l) * 64), v);
        }
    }
}
#else
void SHA512::complete_batch_sse   (const void* s, size_t st, uint8_t* o, size_t c) const { complete_batch_scalar(s, st, o, c); }
void SHA512::complete_batch_avx2  (const void* s, size_t st, uint8_t* o, size_t c) const { complete_batch_scalar(s, st, o, c); }
void SHA512::complete_batch_avx512(const void* s, size_t st, uint8_t* o, size_t c) const { complete_batch_scalar(s, st, o, c); }
#endif

// ---------- Despachante Dinâmico ----------
void SHA512::complete_batch(const void* suffixes, size_t stride,
                            uint8_t* out, size_t count) const {
    if (count == 0) return;

    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    if (__builtin_cpu_supports("avx512f") &&
        __builtin_cpu_supports("avx512vl") &&
        __builtin_cpu_supports("avx512bw")) {
        complete_batch_avx512(suffixes, stride, out, count);
        return;
    }
    if (__builtin_cpu_supports("avx2")) {
        complete_batch_avx2(suffixes, stride, out, count);
        return;
    }
    if (__builtin_cpu_supports("sse4.1")) {
        complete_batch_sse(suffixes, stride, out, count);
        return;
    }
#endif
    complete_batch_scalar(suffixes, stride, out, count);
}

} // namespace crypto
