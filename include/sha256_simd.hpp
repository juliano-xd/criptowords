#ifndef SHA256_SIMD_HPP
#define SHA256_SIMD_HPP

#include <stdint.h>

// =========================================================================
// ESTRUTURAS DE ESTADO (Structure of Arrays - SoA)
// Alinhamento rigoroso na memória é exigido para instruções SIMD (load/store)
// =========================================================================

struct alignas(16) SHA256_SSE_State {
    uint32_t state[8][4];  // 8 variáveis de estado (a-h) x 4 hashes
};

struct alignas(32) SHA256_AVX2_State {
    uint32_t state[8][8];  // 8 variáveis de estado (a-h) x 8 hashes
};

struct alignas(64) SHA256_AVX512_State {
    uint32_t state[8][16]; // 8 variáveis de estado (a-h) x 16 hashes
};

// =========================================================================
// INTERFACE DA API
// =========================================================================

// 1. Inicializa os estados com os valores mágicos do SHA-256
void sha256_init_sse(SHA256_SSE_State* ctx);
void sha256_init_avx2(SHA256_AVX2_State* ctx);
void sha256_init_avx512(SHA256_AVX512_State* ctx);

// 2. Transpõe blocos de 64 bytes (Array of Structures) para o formato SIMD (Structure of Arrays)
void sha256_transpose_sse(const uint8_t* blocks[4], uint32_t W_out[16][4]);
void sha256_transpose_avx2(const uint8_t* blocks[8], uint32_t W_out[16][8]);
void sha256_transpose_avx512(const uint8_t* blocks[16], uint32_t W_out[16][16]);

// 3. Funções de Transformação (O núcleo da compressão do SHA-256)
void sha256_transform_sse(SHA256_SSE_State* ctx, const uint32_t W_in[16][4]);
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]);
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]);

#endif // SHA256_SIMD_HPP
