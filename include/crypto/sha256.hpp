#pragma once

#include "math/UInt.hpp"
#include <cstdint>
#include <cstddef>
#include <array>

namespace crypto {

// =========================================================================
// Classe SHA256 (API Limpa - Oculta implementações internas e estados SIMD)
// =========================================================================
class SHA256 {
public:
    // Construtor padrão (Streaming)
    SHA256();

    // Streaming API
    void reset();
    void update(const void* data, size_t len);
    void finalize(uint8_t out[32]);

    // Atalho Estático para Processamento de Alvo Único (Alta performance Escalar / SHA-NI)
    static void hash(const void* data, uint8_t len, uint8_t out[32]);
    static void hash33(const std::array<u8, 33> &in, std::array<u8, 32> &out) noexcept;

private:
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buf_len_;
    uint64_t total_len_;

    // Processamento de bloco Escalar nativo
    void process_block(const uint8_t block[64]);
};

} // namespace crypto

// =========================================================================
// Funções de Transformação SIMD Brutas (Necessárias para o Gerenciador de Lotes / PBKDF2)
// Expostas apenas como rotinas C-style para quem manipular o hardware diretamente.
// =========================================================================

// struct alignas(16) SHA256_SSE_State { uint32_t state[8][4]; };
struct alignas(16) SHA256_SSE_State { std::array<std::array<uint32_t, 8>, 4> state; };
struct alignas(32) SHA256_AVX2_State { std::array<std::array<uint32_t, 8>, 8> state; };
struct alignas(64) SHA256_AVX512_State { std::array<std::array<uint32_t, 8>, 16> state; };

void sha256_init_sse(SHA256_SSE_State* ctx);
void sha256_init_avx2(SHA256_AVX2_State* ctx);
void sha256_init_avx512(SHA256_AVX512_State* ctx);

void sha256_transform_sse(SHA256_SSE_State* ctx, const std::array<std::array<uint32_t, 16>, 4> &W_in);
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]);
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]);
