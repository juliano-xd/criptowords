#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string_view>
#include <array>

namespace crypto {

// =========================================================================
// Otimizações disponíveis
// =========================================================================
enum class HashMode {
    AUTO,
    SCALAR,
    SIMD_AVX2,
    SIMD_AVX512
};

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
    static void hash(const void* data, size_t len, uint8_t out[32]);

    // Intermediador Inteligente para Múltiplos Alvos
    // Decide automaticamente entre Escalar ou SIMD com base no lote
    static void hash_batch(const std::vector<std::string_view>& inputs, 
                           std::vector<std::array<uint8_t, 32>>& outputs,
                           HashMode mode = HashMode::AUTO);

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

struct alignas(16) SHA256_SSE_State { uint32_t state[8][4]; };
struct alignas(32) SHA256_AVX2_State { uint32_t state[8][8]; };
struct alignas(64) SHA256_AVX512_State { uint32_t state[8][16]; };

void sha256_init_sse(SHA256_SSE_State* ctx);
void sha256_init_avx2(SHA256_AVX2_State* ctx);
void sha256_init_avx512(SHA256_AVX512_State* ctx);

void sha256_transpose_sse(const uint8_t* blocks[4], uint32_t W_out[16][4]);
void sha256_transpose_avx2(const uint8_t* blocks[8], uint32_t W_out[16][8]);
void sha256_transpose_avx512(const uint8_t* blocks[16], uint32_t W_out[16][16]);

void sha256_transform_sse(SHA256_SSE_State* ctx, const uint32_t W_in[16][4]);
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]);
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]);

