#include "../include/sha512.hpp"
#include <cstring>
#include <algorithm>

#ifdef __x86_64__
#include <immintrin.h>
#endif

// =========================================================================
// IMPLEMENTAÇÕES SIMD (Ocultas/Compiladas)
// Originalmente em sha512_simd.cpp
// =========================================================================


// Constantes do SHA-512 (80 palavras de 64 bits)
static constexpr uint64_t K512[80] = {
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
// INICIALIZACAO
// =========================================================================
void sha512_init_sse(SHA512_SSE_State* ctx) {
    for (int i = 0; i < 8; i++) for (int j = 0; j < 2; j++) ctx->state[i][j] = SHA512_IV[i];
}
void sha512_init_avx2(SHA512_AVX2_State* ctx) {
    for (int i = 0; i < 8; i++) for (int j = 0; j < 4; j++) ctx->state[i][j] = SHA512_IV[i];
}
void sha512_init_avx512(SHA512_AVX512_State* ctx) {
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) ctx->state[i][j] = SHA512_IV[i];
}

// =========================================================================
// TRANSPOSICAO (AoS -> SoA) com Endian Swap de 64 bits
// =========================================================================
#define TRANSPOSE_IMPL_64(lanes)     for (int w = 0; w < 16; w++) {         for (int lane = 0; lane < lanes; lane++) {             uint64_t word;             memcpy(&word, blocks[lane] + (w * 8), 8);             W_out[w][lane] = __builtin_bswap64(word);         }     }

void sha512_transpose_sse(const uint8_t* blocks[2], uint64_t W_out[16][2]) { TRANSPOSE_IMPL_64(2) }
void sha512_transpose_avx2(const uint8_t* blocks[4], uint64_t W_out[16][4]) { TRANSPOSE_IMPL_64(4) }
void sha512_transpose_avx512(const uint8_t* blocks[8], uint64_t W_out[16][8]) { TRANSPOSE_IMPL_64(8) }

// =========================================================================
// IMPLEMENTACAO SSE4.1 (2 Hashes)
// =========================================================================
[[gnu::target("sse4.1")]]
void sha512_transform_sse(SHA512_SSE_State* ctx, const uint64_t W_in[16][2]) {
    __m128i a = _mm_load_si128((__m128i*)ctx->state[0]);
    __m128i b = _mm_load_si128((__m128i*)ctx->state[1]);
    __m128i c = _mm_load_si128((__m128i*)ctx->state[2]);
    __m128i d = _mm_load_si128((__m128i*)ctx->state[3]);
    __m128i e = _mm_load_si128((__m128i*)ctx->state[4]);
    __m128i f = _mm_load_si128((__m128i*)ctx->state[5]);
    __m128i g = _mm_load_si128((__m128i*)ctx->state[6]);
    __m128i h = _mm_load_si128((__m128i*)ctx->state[7]);

    #define ROR128_64(x, n) _mm_xor_si128(_mm_srli_epi64(x, n), _mm_slli_epi64(x, 64 - (n)))
    auto CH  = [](__m128i x, __m128i y, __m128i z) { return _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z))); };
    auto MAJ = [](__m128i x, __m128i y, __m128i z) { return _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y))); };
    auto S0  = [&](__m128i x) { return _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 28), ROR128_64(x, 34)), ROR128_64(x, 39)); };
    auto S1  = [&](__m128i x) { return _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 14), ROR128_64(x, 18)), ROR128_64(x, 41)); };
    auto s0  = [&](__m128i x) { return _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 1), ROR128_64(x, 8)), _mm_srli_epi64(x, 7)); };
    auto s1  = [&](__m128i x) { return _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 19), ROR128_64(x, 61)), _mm_srli_epi64(x, 6)); };
    #undef ROR128_64

    __m128i W[80];
    for (int t = 0; t < 16; t++) W[t] = _mm_loadu_si128((__m128i*)W_in[t]);

    for (int t = 16; t < 80; t++)
        W[t] = _mm_add_epi64(_mm_add_epi64(W[t - 16], s0(W[t - 15])), _mm_add_epi64(s1(W[t - 2]), W[t - 7]));

    for (int t = 0; t < 80; t++) {
        __m128i k_vec = _mm_set1_epi64x(K512[t]);
        __m128i T1 = _mm_add_epi64(h, _mm_add_epi64(S1(e), _mm_add_epi64(CH(e, f, g), _mm_add_epi64(k_vec, W[t]))));
        __m128i T2 = _mm_add_epi64(S0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm_add_epi64(d, T1);
        d = c; c = b; b = a; a = _mm_add_epi64(T1, T2);
    }

    _mm_store_si128((__m128i*)ctx->state[0], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[0]), a));
    _mm_store_si128((__m128i*)ctx->state[1], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[1]), b));
    _mm_store_si128((__m128i*)ctx->state[2], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[2]), c));
    _mm_store_si128((__m128i*)ctx->state[3], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[3]), d));
    _mm_store_si128((__m128i*)ctx->state[4], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[4]), e));
    _mm_store_si128((__m128i*)ctx->state[5], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[5]), f));
    _mm_store_si128((__m128i*)ctx->state[6], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[6]), g));
    _mm_store_si128((__m128i*)ctx->state[7], _mm_add_epi64(_mm_load_si128((__m128i*)ctx->state[7]), h));
}

// =========================================================================
// IMPLEMENTACAO AVX2 (4 Hashes)
// =========================================================================
[[gnu::target("avx2")]]
void sha512_transform_avx2(SHA512_AVX2_State* ctx, const uint64_t W_in[16][4]) {
    __m256i a = _mm256_load_si256((__m256i*)ctx->state[0]);
    __m256i b = _mm256_load_si256((__m256i*)ctx->state[1]);
    __m256i c = _mm256_load_si256((__m256i*)ctx->state[2]);
    __m256i d = _mm256_load_si256((__m256i*)ctx->state[3]);
    __m256i e = _mm256_load_si256((__m256i*)ctx->state[4]);
    __m256i f = _mm256_load_si256((__m256i*)ctx->state[5]);
    __m256i g = _mm256_load_si256((__m256i*)ctx->state[6]);
    __m256i h = _mm256_load_si256((__m256i*)ctx->state[7]);

    #define ROR256_64(x, n) _mm256_xor_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))
    auto CH  = [](__m256i x, __m256i y, __m256i z) { return _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z))); };
    auto MAJ = [](__m256i x, __m256i y, __m256i z) { return _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y))); };
    auto S0  = [&](__m256i x) { return _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 28), ROR256_64(x, 34)), ROR256_64(x, 39)); };
    auto S1  = [&](__m256i x) { return _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 14), ROR256_64(x, 18)), ROR256_64(x, 41)); };
    auto s0  = [&](__m256i x) { return _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 1), ROR256_64(x, 8)), _mm256_srli_epi64(x, 7)); };
    auto s1  = [&](__m256i x) { return _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 19), ROR256_64(x, 61)), _mm256_srli_epi64(x, 6)); };
    #undef ROR256_64

    __m256i W[80];
    for (int t = 0; t < 16; t++) W[t] = _mm256_loadu_si256((__m256i*)W_in[t]);

    for (int t = 16; t < 80; t++)
        W[t] = _mm256_add_epi64(_mm256_add_epi64(W[t - 16], s0(W[t - 15])), _mm256_add_epi64(s1(W[t - 2]), W[t - 7]));

    for (int t = 0; t < 80; t++) {
        __m256i k_vec = _mm256_set1_epi64x(K512[t]);
        __m256i T1 = _mm256_add_epi64(h, _mm256_add_epi64(S1(e), _mm256_add_epi64(CH(e, f, g), _mm256_add_epi64(k_vec, W[t]))));
        __m256i T2 = _mm256_add_epi64(S0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi64(d, T1);
        d = c; c = b; b = a; a = _mm256_add_epi64(T1, T2);
    }

    _mm256_store_si256((__m256i*)ctx->state[0], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[0]), a));
    _mm256_store_si256((__m256i*)ctx->state[1], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[1]), b));
    _mm256_store_si256((__m256i*)ctx->state[2], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[2]), c));
    _mm256_store_si256((__m256i*)ctx->state[3], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[3]), d));
    _mm256_store_si256((__m256i*)ctx->state[4], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[4]), e));
    _mm256_store_si256((__m256i*)ctx->state[5], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[5]), f));
    _mm256_store_si256((__m256i*)ctx->state[6], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[6]), g));
    _mm256_store_si256((__m256i*)ctx->state[7], _mm256_add_epi64(_mm256_load_si256((__m256i*)ctx->state[7]), h));

}

// =========================================================================
// IMPLEMENTACAO AVX-512 (8 Hashes) - Rotação Nativa de 64 bits
// =========================================================================
[[gnu::target("avx512f,avx512vl")]]
void sha512_transform_avx512(SHA512_AVX512_State* ctx, const uint64_t W_in[16][8]) {
    __m512i a = _mm512_load_si512((__m512i*)ctx->state[0]);
    __m512i b = _mm512_load_si512((__m512i*)ctx->state[1]);
    __m512i c = _mm512_load_si512((__m512i*)ctx->state[2]);
    __m512i d = _mm512_load_si512((__m512i*)ctx->state[3]);
    __m512i e = _mm512_load_si512((__m512i*)ctx->state[4]);
    __m512i f = _mm512_load_si512((__m512i*)ctx->state[5]);
    __m512i g = _mm512_load_si512((__m512i*)ctx->state[6]);
    __m512i h = _mm512_load_si512((__m512i*)ctx->state[7]);

    auto CH  = [](__m512i x, __m512i y, __m512i z) __attribute__((target("avx512f,avx512vl"))) {
        return _mm512_xor_si512(z, _mm512_and_si512(x, _mm512_xor_si512(y, z)));
    };
    auto MAJ = [](__m512i x, __m512i y, __m512i z) __attribute__((target("avx512f,avx512vl"))) {
        return _mm512_xor_si512(_mm512_and_si512(x, y),_mm512_and_si512(z, _mm512_xor_si512(x, y)));
    };
    auto S0  = [](__m512i x) __attribute__((target("avx512f,avx512vl"))) {
        return _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34)), _mm512_ror_epi64(x, 39));
    };
    auto S1  = [](__m512i x) __attribute__((target("avx512f,avx512vl"))) {
        return _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18)), _mm512_ror_epi64(x, 41));
    };
    auto s0  = [](__m512i x) __attribute__((target("avx512f,avx512vl"))) {
        return _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 1), _mm512_ror_epi64(x, 8)), _mm512_srli_epi64(x, 7));
    };
    auto s1  = [](__m512i x) __attribute__((target("avx512f,avx512vl"))) {
        return _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61)), _mm512_srli_epi64(x, 6));
    };

    __m512i W[80];
    for (int t = 0; t < 16; t++) {
        W[t] = _mm512_loadu_si512((__m512i*)W_in[t]);
    }
    for (int t = 16; t < 80; t++) {
        W[t] = _mm512_add_epi64(_mm512_add_epi64(W[t - 16], s0(W[t - 15])), _mm512_add_epi64(s1(W[t - 2]), W[t - 7]));
    }

    for (int t = 0; t < 80; t++) {
        __m512i k_vec = _mm512_set1_epi64(K512[t]);
        __m512i T1 = _mm512_add_epi64(h, _mm512_add_epi64(S1(e), _mm512_add_epi64(CH(e, f, g), _mm512_add_epi64(k_vec, W[t]))));
        __m512i T2 = _mm512_add_epi64(S0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm512_add_epi64(d, T1);
        d = c; c = b; b = a; a = _mm512_add_epi64(T1, T2);
    }

    _mm512_store_si512((__m512i*)ctx->state[0], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[0]), a));
    _mm512_store_si512((__m512i*)ctx->state[1], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[1]), b));
    _mm512_store_si512((__m512i*)ctx->state[2], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[2]), c));
    _mm512_store_si512((__m512i*)ctx->state[3], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[3]), d));
    _mm512_store_si512((__m512i*)ctx->state[4], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[4]), e));
    _mm512_store_si512((__m512i*)ctx->state[5], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[5]), f));
    _mm512_store_si512((__m512i*)ctx->state[6], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[6]), g));
    _mm512_store_si512((__m512i*)ctx->state[7], _mm512_add_epi64(_mm512_load_si512((__m512i*)ctx->state[7]), h));
}

// =========================================================================
// IMPLEMENTAÇÃO ESCALAR E INTERMEDIADOR INTELIGENTE
// =========================================================================

namespace crypto {

static constexpr uint64_t K512_SCALAR[80] = {
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

static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static inline uint64_t Ch64(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static inline uint64_t Maj64(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint64_t Sigma0_64(uint64_t x) { return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39); }
static inline uint64_t Sigma1_64(uint64_t x) { return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41); }
static inline uint64_t sigma0_64(uint64_t x) { return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7); }
static inline uint64_t sigma1_64(uint64_t x) { return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6); }

SHA512::SHA512() { reset(); }

void SHA512::reset() {
    h_[0] = 0x6a09e667f3bcc908; h_[1] = 0xbb67ae8584caa73b; h_[2] = 0x3c6ef372fe94f82b; h_[3] = 0xa54ff53a5f1d36f1;
    h_[4] = 0x510e527fade682d1; h_[5] = 0x9b05688c2b3e6c1f; h_[6] = 0x1f83d9abfb41bd6b; h_[7] = 0x5be0cd19137e2179;
    total_len_ = 0;
    buf_len_ = 0;
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
        if (buf_len_ == 128) {
            process_block(buf_);
            buf_len_ = 0;
        }
    }

    while (len >= 128) {
        process_block(p);
        p += 128;
        len -= 128;
    }

    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_len_ = len;
    }
}

void SHA512::finalize(uint8_t out[64]) {
    uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 112) {
        std::memset(buf_ + buf_len_, 0, 128 - buf_len_);
        process_block(buf_);
        buf_len_ = 0;
    }
    std::memset(buf_ + buf_len_, 0, 112 - buf_len_);
    for (int i = 7; i >= 0; --i) {
        buf_[120 + (7 - i)] = static_cast<uint8_t>(bit_len >> (i * 8));
    }
    std::memset(buf_ + 112, 0, 8); // High 64 bits of length are 0
    process_block(buf_);

    for (int i = 0; i < 8; ++i) {
        out[i * 8] = static_cast<uint8_t>(h_[i] >> 56);
        out[i * 8 + 1] = static_cast<uint8_t>(h_[i] >> 48);
        out[i * 8 + 2] = static_cast<uint8_t>(h_[i] >> 40);
        out[i * 8 + 3] = static_cast<uint8_t>(h_[i] >> 32);
        out[i * 8 + 4] = static_cast<uint8_t>(h_[i] >> 24);
        out[i * 8 + 5] = static_cast<uint8_t>(h_[i] >> 16);
        out[i * 8 + 6] = static_cast<uint8_t>(h_[i] >> 8);
        out[i * 8 + 7] = static_cast<uint8_t>(h_[i]);
    }
}

void SHA512::hash(const void* data, size_t len, uint8_t out[64]) {
    SHA512 ctx;
    ctx.update(data, len);
    ctx.finalize(out);
}

void SHA512::process_block(const uint8_t block[128]) {
    uint64_t W[80];
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint64_t(block[i * 8]) << 56) | (uint64_t(block[i * 8 + 1]) << 48) |
               (uint64_t(block[i * 8 + 2]) << 40) | (uint64_t(block[i * 8 + 3]) << 32) |
               (uint64_t(block[i * 8 + 4]) << 24) | (uint64_t(block[i * 8 + 5]) << 16) |
               (uint64_t(block[i * 8 + 6]) << 8)  | uint64_t(block[i * 8 + 7]);
    }
    for (int i = 16; i < 80; ++i) {
        W[i] = sigma1_64(W[i - 2]) + W[i - 7] + sigma0_64(W[i - 15]) + W[i - 16];
    }

    uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t T1 = h + Sigma1_64(e) + Ch64(e, f, g) + K512_SCALAR[i] + W[i];
        uint64_t T2 = Sigma0_64(a) + Maj64(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

// O Intermediador Inteligente
void SHA512::hash_batch(const std::vector<std::string_view>& inputs, 
                        std::vector<std::array<uint8_t, 64>>& outputs,
                        HashMode512 mode) {
    outputs.resize(inputs.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        hash(inputs[i].data(), inputs[i].size(), outputs[i].data());
    }
}

} // namespace crypto
