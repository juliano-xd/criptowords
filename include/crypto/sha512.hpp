#pragma once

#include <cstdint>
#include <cstddef>

namespace crypto {

    class SHA512 {
        public:
            SHA512();

            void reset();
            void update(const void* data, size_t len);
            void finalize(uint8_t out[64]);
            static void hash(const void* data, size_t len, uint8_t out[64]);

            // Template hashing — single-hash API
            void preset(const void* prefix, size_t prefix_len, size_t suffix_len);
            void complete(const void* suffix, uint8_t out[64]) const;
            void complete(const void* suffix, size_t suffix_len, uint8_t out[64]) const;

            // =========================================================
            // BATCH API — N hashes simultâneos via SIMD
            // =========================================================
            //   suffixes : base; sufixo i em ((const uint8_t*)suffixes) + i*stride
            //   stride   : bytes entre sufixos consecutivos
            //   out      : count * 64 bytes; hash i em out + i*64
            //   count    : número de hashes
            void complete_batch(const void* suffixes, size_t stride,
                                uint8_t* out, size_t count) const;

            // Variantes explícitas
            void complete_batch_scalar(const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;
            void complete_batch_sse   (const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;
            void complete_batch_avx2  (const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;
            void complete_batch_avx512(const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;

            uint64_t h_[8];

        private:
            alignas(16) uint8_t buf_[128];
            size_t buf_len_;
            uint64_t total_len_;
            size_t template_suffix_len_ = 0;
            bool   template_single_block_ = false;

            void process_block(const uint8_t block[128]);
    };
} // namespace crypto

struct alignas(16) SHA512_SSE_State    { uint64_t state[8][2]; };
struct alignas(32) SHA512_AVX2_State   { uint64_t state[8][4]; };
struct alignas(64) SHA512_AVX512_State { uint64_t state[8][8]; };

void sha512_init_sse(SHA512_SSE_State* ctx);
void sha512_init_avx2(SHA512_AVX2_State* ctx);
void sha512_init_avx512(SHA512_AVX512_State* ctx);

void sha512_transform_sse   (SHA512_SSE_State*,    const uint64_t W_in[16][2]);
void sha512_transform_avx2  (SHA512_AVX2_State*,   const uint64_t W_in[16][4]);
void sha512_transform_avx512(SHA512_AVX512_State*, const uint64_t W_in[16][8]);
