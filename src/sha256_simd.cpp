#include "../include/sha256_simd.hpp"
#include <immintrin.h>
#include <string.h>

// Constantes do SHA-256
static constexpr uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static constexpr uint32_t SHA256_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// =========================================================================
// INICIALIZAÇÃO
// =========================================================================
void sha256_init_sse(SHA256_SSE_State* ctx) {
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) ctx->state[i][j] = SHA256_IV[i];
}
void sha256_init_avx2(SHA256_AVX2_State* ctx) {
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) ctx->state[i][j] = SHA256_IV[i];
}
void sha256_init_avx512(SHA256_AVX512_State* ctx) {
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 16; j++) ctx->state[i][j] = SHA256_IV[i];
}

// =========================================================================
// TRANSPOSIÇÃO (AoS -> SoA) com Endian Swap embutido
// =========================================================================
#define TRANSPOSE_IMPL(lanes) \
    for (int w = 0; w < 16; w++) { \
        for (int lane = 0; lane < lanes; lane++) { \
            uint32_t word; \
            memcpy(&word, blocks[lane] + (w * 4), 4); \
            W_out[w][lane] = __builtin_bswap32(word); \
        } \
    }

void sha256_transpose_sse(const uint8_t* blocks[4], uint32_t W_out[16][4]) { TRANSPOSE_IMPL(4) }
void sha256_transpose_avx2(const uint8_t* blocks[8], uint32_t W_out[16][8]) { TRANSPOSE_IMPL(8) }
void sha256_transpose_avx512(const uint8_t* blocks[16], uint32_t W_out[16][16]) { TRANSPOSE_IMPL(16) }

// =========================================================================
// IMPLEMENTAÇÃO SSE4.1 (4 Hashes)
// =========================================================================
[[gnu::target("sse4.1")]]
void sha256_transform_sse(SHA256_SSE_State* ctx, const uint32_t W_in[16][4]) {
    __m128i a = _mm_load_si128((__m128i*)ctx->state[0]);
    __m128i b = _mm_load_si128((__m128i*)ctx->state[1]);
    __m128i c = _mm_load_si128((__m128i*)ctx->state[2]);
    __m128i d = _mm_load_si128((__m128i*)ctx->state[3]);
    __m128i e = _mm_load_si128((__m128i*)ctx->state[4]);
    __m128i f = _mm_load_si128((__m128i*)ctx->state[5]);
    __m128i g = _mm_load_si128((__m128i*)ctx->state[6]);
    __m128i h = _mm_load_si128((__m128i*)ctx->state[7]);

    #define ROR128(x, n) _mm_xor_si128(_mm_srli_epi32(x, n), _mm_slli_epi32(x, 32 - (n)))
    auto CH  = [](__m128i x, __m128i y, __m128i z) __attribute__((target("sse4.1"))) { return _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z))); };
    auto MAJ = [](__m128i x, __m128i y, __m128i z) __attribute__((target("sse4.1"))) { return _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y))); };
    auto S0  = [&](__m128i x) __attribute__((target("sse4.1"))) { return _mm_xor_si128(_mm_xor_si128(ROR128(x, 2), ROR128(x, 13)), ROR128(x, 22)); };
    auto S1  = [&](__m128i x) __attribute__((target("sse4.1"))) { return _mm_xor_si128(_mm_xor_si128(ROR128(x, 6), ROR128(x, 11)), ROR128(x, 25)); };
    auto s0  = [&](__m128i x) __attribute__((target("sse4.1"))) { return _mm_xor_si128(_mm_xor_si128(ROR128(x, 7), ROR128(x, 18)), _mm_srli_epi32(x, 3)); };
    auto s1  = [&](__m128i x) __attribute__((target("sse4.1"))) { return _mm_xor_si128(_mm_xor_si128(ROR128(x, 17), ROR128(x, 19)), _mm_srli_epi32(x, 10)); };
    #undef ROR128

    __m128i W[64];
    for (int t = 0; t < 16; t++) W[t] = _mm_loadu_si128((__m128i*)W_in[t]);

    for (int t = 16; t < 64; t++)
        W[t] = _mm_add_epi32(_mm_add_epi32(W[t - 16], s0(W[t - 15])), _mm_add_epi32(s1(W[t - 2]), W[t - 7]));

    for (int t = 0; t < 64; t++) {
        __m128i k_vec = _mm_set1_epi32(K256[t]);
        __m128i T1 = _mm_add_epi32(h, _mm_add_epi32(S1(e), _mm_add_epi32(CH(e, f, g), _mm_add_epi32(k_vec, W[t]))));
        __m128i T2 = _mm_add_epi32(S0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm_add_epi32(d, T1);
        d = c; c = b; b = a; a = _mm_add_epi32(T1, T2);
    }

    _mm_store_si128((__m128i*)ctx->state[0], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[0]), a));
    _mm_store_si128((__m128i*)ctx->state[1], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[1]), b));
    _mm_store_si128((__m128i*)ctx->state[2], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[2]), c));
    _mm_store_si128((__m128i*)ctx->state[3], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[3]), d));
    _mm_store_si128((__m128i*)ctx->state[4], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[4]), e));
    _mm_store_si128((__m128i*)ctx->state[5], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[5]), f));
    _mm_store_si128((__m128i*)ctx->state[6], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[6]), g));
    _mm_store_si128((__m128i*)ctx->state[7], _mm_add_epi32(_mm_load_si128((__m128i*)ctx->state[7]), h));
}

// =========================================================================
// IMPLEMENTAÇÃO AVX2 (8 Hashes)
// =========================================================================
[[gnu::target("avx2")]]
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]) {
    __m256i a = _mm256_load_si256((__m256i*)ctx->state[0]);
    __m256i b = _mm256_load_si256((__m256i*)ctx->state[1]);
    __m256i c = _mm256_load_si256((__m256i*)ctx->state[2]);
    __m256i d = _mm256_load_si256((__m256i*)ctx->state[3]);
    __m256i e = _mm256_load_si256((__m256i*)ctx->state[4]);
    __m256i f = _mm256_load_si256((__m256i*)ctx->state[5]);
    __m256i g = _mm256_load_si256((__m256i*)ctx->state[6]);
    __m256i h = _mm256_load_si256((__m256i*)ctx->state[7]);


    #define ROR256(x, n) _mm256_xor_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))
    auto CH  = [](__m256i x, __m256i y, __m256i z) __attribute__((target("avx2"))) { return _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z))); };
    auto MAJ = [](__m256i x, __m256i y, __m256i z) __attribute__((target("avx2"))) { return _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y))); };
    auto S0  = [&](__m256i x) __attribute__((target("avx2"))) { return _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 2), ROR256(x, 13)), ROR256(x, 22)); };
    auto S1  = [&](__m256i x) __attribute__((target("avx2"))) { return _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 6), ROR256(x, 11)), ROR256(x, 25)); };
    auto s0  = [&](__m256i x) __attribute__((target("avx2"))) { return _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 7), ROR256(x, 18)), _mm256_srli_epi32(x, 3)); };
    auto s1  = [&](__m256i x) __attribute__((target("avx2"))) { return _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 17), ROR256(x, 19)), _mm256_srli_epi32(x, 10)); };
    #undef ROR256

    __m256i W[64];
    for (int t = 0; t < 16; t++) W[t] = _mm256_loadu_si256((__m256i*)W_in[t]);

    for (int t = 16; t < 64; t++)
        W[t] = _mm256_add_epi32(_mm256_add_epi32(W[t - 16], s0(W[t - 15])), _mm256_add_epi32(s1(W[t - 2]), W[t - 7]));

    for (int t = 0; t < 64; t++) {
        __m256i k_vec = _mm256_set1_epi32(K256[t]);
        __m256i T1 = _mm256_add_epi32(h, _mm256_add_epi32(S1(e), _mm256_add_epi32(CH(e, f, g), _mm256_add_epi32(k_vec, W[t]))));
        __m256i T2 = _mm256_add_epi32(S0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, T1);
        d = c; c = b; b = a; a = _mm256_add_epi32(T1, T2);
    }

    _mm256_store_si256((__m256i*)ctx->state[0], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[0]), a));
    _mm256_store_si256((__m256i*)ctx->state[1], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[1]), b));
    _mm256_store_si256((__m256i*)ctx->state[2], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[2]), c));
    _mm256_store_si256((__m256i*)ctx->state[3], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[3]), d));
    _mm256_store_si256((__m256i*)ctx->state[4], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[4]), e));
    _mm256_store_si256((__m256i*)ctx->state[5], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[5]), f));
    _mm256_store_si256((__m256i*)ctx->state[6], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[6]), g));
    _mm256_store_si256((__m256i*)ctx->state[7], _mm256_add_epi32(_mm256_load_si256((__m256i*)ctx->state[7]), h));
}

// =========================================================================
// IMPLEMENTAÇÃO AVX-512 (16 Hashes) - Uso de Rotação Nativa
// =========================================================================
[[gnu::target("avx512f,avx512vl")]]
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]) {
    __m512i a = _mm512_load_si512((__m512i*)ctx->state[0]);
    __m512i b = _mm512_load_si512((__m512i*)ctx->state[1]);
    __m512i c = _mm512_load_si512((__m512i*)ctx->state[2]);
    __m512i d = _mm512_load_si512((__m512i*)ctx->state[3]);
    __m512i e = _mm512_load_si512((__m512i*)ctx->state[4]);
    __m512i f = _mm512_load_si512((__m512i*)ctx->state[5]);
    __m512i g = _mm512_load_si512((__m512i*)ctx->state[6]);
    __m512i h = _mm512_load_si512((__m512i*)ctx->state[7]);

    #define ROR512(x, n) _mm512_xor_si512(_mm512_srli_epi32(x, n), _mm512_slli_epi32(x, 32 - (n)))
    auto CH  = [](__m512i x, __m512i y, __m512i z) __attribute__((target("avx512f,avx512vl"))) { return _mm512_xor_si512(z, _mm512_and_si512(x, _mm512_xor_si512(y, z))); };
    auto MAJ = [](__m512i x, __m512i y, __m512i z) __attribute__((target("avx512f,avx512vl"))) { return _mm512_xor_si512(_mm512_and_si512(x, y), _mm512_and_si512(z, _mm512_xor_si512(x, y))); };
    auto S0  = [&](__m512i x) __attribute__((target("avx512f,avx512vl"))) { return _mm512_xor_si512(_mm512_xor_si512(ROR512(x, 2), ROR512(x, 13)), ROR512(x, 22)); };
    auto S1  = [&](__m512i x) __attribute__((target("avx512f,avx512vl"))) { return _mm512_xor_si512(_mm512_xor_si512(ROR512(x, 6), ROR512(x, 11)), ROR512(x, 25)); };
    auto s0  = [&](__m512i x) __attribute__((target("avx512f,avx512vl"))) { return _mm512_xor_si512(_mm512_xor_si512(ROR512(x, 7), ROR512(x, 18)), _mm512_srli_epi32(x, 3)); };
    auto s1  = [&](__m512i x) __attribute__((target("avx512f,avx512vl"))) { return _mm512_xor_si512(_mm512_xor_si512(ROR512(x, 17), ROR512(x, 19)), _mm512_srli_epi32(x, 10)); };
    #undef ROR512

    __m512i W[64];
    for (int t = 0; t < 16; t++) W[t] = _mm512_loadu_si512((__m512i*)W_in[t]);

    for (int t = 16; t < 64; t++)
        W[t] = _mm512_add_epi32(_mm512_add_epi32(W[t - 16], s0(W[t - 15])), _mm512_add_epi32(s1(W[t - 2]), W[t - 7]));

    for (int t = 0; t < 64; t++) {
        __m512i k_vec = _mm512_set1_epi32(K256[t]);
        __m512i T1 = _mm512_add_epi32(h, _mm512_add_epi32(S1(e), _mm512_add_epi32(CH(e, f, g), _mm512_add_epi32(k_vec, W[t]))));
        __m512i T2 = _mm512_add_epi32(S0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm512_add_epi32(d, T1);
        d = c; c = b; b = a; a = _mm512_add_epi32(T1, T2);
    }

    _mm512_store_si512((__m512i*)ctx->state[0], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[0]), a));
    _mm512_store_si512((__m512i*)ctx->state[1], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[1]), b));
    _mm512_store_si512((__m512i*)ctx->state[2], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[2]), c));
    _mm512_store_si512((__m512i*)ctx->state[3], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[3]), d));
    _mm512_store_si512((__m512i*)ctx->state[4], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[4]), e));
    _mm512_store_si512((__m512i*)ctx->state[5], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[5]), f));
    _mm512_store_si512((__m512i*)ctx->state[6], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[6]), g));
    _mm512_store_si512((__m512i*)ctx->state[7], _mm512_add_epi32(_mm512_load_si512((__m512i*)ctx->state[7]), h));
}
