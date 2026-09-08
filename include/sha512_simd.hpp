#ifndef SHA512_SIMD_HPP
#define SHA512_SIMD_HPP

#include <stdint.h>

// =========================================================================
// ESTRUTURAS DE ESTADO SHA-512 (Structure of Arrays - SoA)
// Nota: SHA-512 usa palavras de 64 bits, entao a capacidade de hashes em
// cada vetor cai pela metade comparado ao SHA-256 (que usa 32 bits).
// =========================================================================

// SSE: 128 bits / 64 bits = 2 Hashes
struct alignas(16) SHA512_SSE_State {
    uint64_t state[8][2];
};

// AVX2: 256 bits / 64 bits = 4 Hashes
struct alignas(32) SHA512_AVX2_State {
    uint64_t state[8][4];
};

// AVX-512: 512 bits / 64 bits = 8 Hashes
struct alignas(64) SHA512_AVX512_State {
    uint64_t state[8][8];
};

// =========================================================================
// INTERFACE DA API
// =========================================================================

// 1. Inicializa os estados com os valores magicos do SHA-512
void sha512_init_sse(SHA512_SSE_State* ctx);
void sha512_init_avx2(SHA512_AVX2_State* ctx);
void sha512_init_avx512(SHA512_AVX512_State* ctx);

// 2. Transpoe blocos de 128 bytes para o formato SIMD
void sha512_transpose_sse(const uint8_t* blocks[2], uint64_t W_out[16][2]);
void sha512_transpose_avx2(const uint8_t* blocks[4], uint64_t W_out[16][4]);
void sha512_transpose_avx512(const uint8_t* blocks[8], uint64_t W_out[16][8]);

// 3. Funcoes de Transformacao (80 rounds do SHA-512)
void sha512_transform_sse(SHA512_SSE_State* ctx, const uint64_t W_in[16][2]);
void sha512_transform_avx2(SHA512_AVX2_State* ctx, const uint64_t W_in[16][4]);
void sha512_transform_avx512(SHA512_AVX512_State* ctx, const uint64_t W_in[16][8]);

#endif // SHA512_SIMD_HPP
