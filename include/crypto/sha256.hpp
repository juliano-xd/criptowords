#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace crypto {

class SHA256 {
   public:
    SHA256();
    void reset();
    void update(const void* data, size_t len);
    void finalize(uint8_t out[32]);

    // Hash de mensagem curta (≤55 B): bloco único com padding inline.
    // Aceita qualquer size_t; para len > 55 cai no caminho streaming.
    static void hash(const void* data, size_t len, uint8_t out[32]);
    static void hash33(const std::array<uint8_t, 33>& in, std::array<uint8_t, 32>& out) noexcept;

   private:
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buf_len_;
    uint64_t total_len_;
    void process_block(const uint8_t block[64]);
};

}  // namespace crypto

// Layouts: state[k] = hash word k, com LANES valores contíguos.
//   SSE   : 8 palavras × 4 lanes = 32 u32 (128 B)
//   AVX2  : 8 palavras × 8 lanes = 64 u32 (256 B)
//   AVX512: 8 palavras × 16 lanes = 128 u32 (512 B)
struct alignas(16) SHA256_SSE_State {
    std::array<std::array<uint32_t, 4>, 8> state;   // [word][lane]
};
struct alignas(32) SHA256_AVX2_State {
    std::array<std::array<uint32_t, 8>, 8> state;   // [word][lane]
};
struct alignas(64) SHA256_AVX512_State {
    std::array<std::array<uint32_t, 16>, 8> state;  // [word][lane]
};

void sha256_init_sse(SHA256_SSE_State* ctx);
void sha256_init_avx2(SHA256_AVX2_State* ctx);
void sha256_init_avx512(SHA256_AVX512_State* ctx);

void sha256_transform_sse(SHA256_SSE_State* ctx, const std::array<std::array<uint32_t, 4>, 16>& W_in);
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]);
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]);
