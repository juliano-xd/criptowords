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
enum class HashMode512 {
    AUTO,
    SCALAR,
    SIMD_AVX2,
    SIMD_AVX512
};

// =========================================================================
// Classe SHA512 (API Limpa - Oculta implementações internas e estados SIMD)
// =========================================================================
class SHA512 {
public:
    // Construtor padrão
    SHA512();

    // Streaming API
    void reset();
    void update(const void* data, size_t len);
    void finalize(uint8_t out[64]);

    // Atalho Estático para Processamento de Alvo Único (Alta performance Escalar)
    static void hash(const void* data, size_t len, uint8_t out[64]);

    // Intermediador Inteligente para Múltiplos Alvos
    static void hash_batch(const std::vector<std::string_view>& inputs, 
                           std::vector<std::array<uint8_t, 64>>& outputs,
                           HashMode512 mode = HashMode512::AUTO);

private:
    uint64_t h_[8];
    uint8_t buf_[128];
    size_t buf_len_;
    uint64_t total_len_;

    void process_block(const uint8_t block[128]);
};

} // namespace crypto

// =========================================================================
// Funções de Transformação SIMD Brutas (Necessárias para o Gerenciador de Lotes / PBKDF2)
// Expostas apenas como rotinas C-style para quem manipular o hardware diretamente.
// =========================================================================

struct alignas(16) SHA512_SSE_State { uint64_t state[8][2]; };
struct alignas(32) SHA512_AVX2_State { uint64_t state[8][4]; };
struct alignas(64) SHA512_AVX512_State { uint64_t state[8][8]; };

void sha512_init_sse(SHA512_SSE_State* ctx);
void sha512_init_avx2(SHA512_AVX2_State* ctx);
void sha512_init_avx512(SHA512_AVX512_State* ctx);

void sha512_transform_sse(SHA512_SSE_State* ctx, const uint64_t W_in[16][2]);
void sha512_transform_avx2(SHA512_AVX2_State* ctx, const uint64_t W_in[16][4]);
void sha512_transform_avx512(SHA512_AVX512_State* ctx, const uint64_t W_in[16][8]);

