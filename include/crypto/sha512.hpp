#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace crypto {

    class SHA512 {
        public:
            SHA512();

            void reset();
            void update(const void* data, size_t len);
            void finalize(uint8_t out[64]);
            static void hash(const void* data, size_t len, uint8_t out[64]);

            // =========================================================
            // TEMPLATE HASHING — single-hash API
            // =========================================================
            //   preset() pre-computa, uma unica vez:
            //     - o bloco de 128 bytes ja com padding + length field
            //     - as 16 palavras big-endian do bloco (tmpl_w_)
            //     - o midstate apos as rodadas cujo W[] e' 100% constante
            //   complete() retoma a compressao na primeira rodada variavel.
            void preset(const void* prefix, size_t prefix_len, size_t suffix_len);
            void complete(const void* suffix, uint8_t out[64]) const;
            void complete(const void* suffix, size_t suffix_len, uint8_t out[64]) const;

            // =========================================================
            // BATCH API — N hashes simultaneos via SIMD
            // =========================================================
            //   suffixes : base; sufixo i em ((const uint8_t*)suffixes) + i*stride
            //   stride   : bytes entre sufixos consecutivos
            //   out      : count * 64 bytes; hash i em out + i*64
            //   count    : numero de hashes
            //
            //   Todos os metodos const sao thread-safe: nao mutam *this e
            //   usam apenas buffers locais. Um mesmo objeto pode ser
            //   compartilhado entre threads sem copia.
            void complete_batch(const void* suffixes, size_t stride,
                                uint8_t* out, size_t count) const;

            // Variantes explicitas
            void complete_batch_scalar(const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;
            void complete_batch_sse   (const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;
            void complete_batch_avx2  (const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;
            void complete_batch_avx512(const void* suffixes, size_t stride,
                                       uint8_t* out, size_t count) const;

            // =========================================================
            // PARALELISMO DE THREADS
            // =========================================================
            //   Particiona o batch em blocos multiplos de simd_lanes() e
            //   distribui entre `threads` workers (0 = hardware_concurrency).
            //   So vale a pena para count grande; em loop quente prefira
            //   paralelizar no chamador (ver complete_batch_range).
            void complete_batch_mt(const void* suffixes, size_t stride,
                                   uint8_t* out, size_t count,
                                   unsigned threads = 0) const;

            // Subfaixa [first, first+n) do batch — building block para
            // um pool de threads persistente do lado do chamador.
            void complete_batch_range(const void* suffixes, size_t stride,
                                      uint8_t* out, size_t first, size_t n) const;

            // Lanes SIMD efetivas nesta CPU (1, 2, 4 ou 8).
            static unsigned simd_lanes() noexcept;
            // Nome da rota escolhida: "scalar" | "sse4.1" | "avx2" | "avx512"
            static const char* simd_name() noexcept;

            // Numero de rodadas eliminadas pelo midstate do template atual.
            unsigned skipped_rounds() const noexcept { return tmpl_skip_; }

            uint64_t h_[8];

        private:
            alignas(64) uint8_t  buf_[128];
            alignas(64) uint64_t tmpl_w_[16];   // palavras BE do bloco template
            alignas(64) uint64_t tmpl_mid_[8];  // estado apos tmpl_skip_ rodadas

            size_t   buf_len_;
            uint64_t total_len_;
            size_t   template_suffix_len_  = 0;
            bool     template_single_block_ = false;

            uint32_t tmpl_skip_ = 0;   // rodadas pre-computadas (0..16)
            uint32_t tmpl_vlo_  = 16;  // primeira palavra variavel em W[0..15]
            uint32_t tmpl_vhi_  = 15;  // ultima  palavra variavel (vlo>vhi = vazio)

            void process_block(const uint8_t block[128]);
            void build_template_tables();
    };

    // =============================================================
    // SHA512Pool — pool de workers persistente (fork/join)
    // =============================================================
    // complete_batch_mt() cria e destroi threads a cada chamada; em
    // loop quente isso domina. Este pool cria as threads uma vez e
    // reusa. Um mesmo SHA512 const e' compartilhado sem copia.
    //
    //   crypto::SHA512      ctx;  ctx.preset(prefix, plen, slen);
    //   crypto::SHA512Pool  pool;              // 1x no programa
    //   for (...) pool.complete_batch(ctx, sufs, stride, out, N);
    //
    // Nao e' reentrante: uma chamada por vez por objeto pool.
    class SHA512Pool {
        public:
            explicit SHA512Pool(unsigned threads = 0);
            ~SHA512Pool();

            SHA512Pool(const SHA512Pool&)            = delete;
            SHA512Pool& operator=(const SHA512Pool&) = delete;

            unsigned threads() const noexcept { return nthreads_; }

            void complete_batch(const SHA512& ctx, const void* suffixes, size_t stride,
                                uint8_t* out, size_t count);

        private:
            struct Job {
                const SHA512* ctx      = nullptr;
                const void*   suffixes = nullptr;
                size_t        stride   = 0;
                uint8_t*      out      = nullptr;
                size_t        count    = 0;
            };

            void worker(unsigned id);

            unsigned                 nthreads_;
            std::vector<std::thread> workers_;
            std::mutex               m_;
            std::condition_variable  cv_start_;
            std::condition_variable  cv_done_;
            Job                      job_{};
            uint64_t                 gen_     = 0;
            unsigned                 pending_ = 0;
            bool                     stop_    = false;
    };
} // namespace crypto

// =============================================================================
// Kernels SIMD expostos (compatibilidade com a API anterior).
// state[i][lane]; 80 rodadas completas com feed-forward interno.
// =============================================================================
struct alignas(16) SHA512_SSE_State    { uint64_t state[8][2]; };
struct alignas(32) SHA512_AVX2_State   { uint64_t state[8][4]; };
struct alignas(64) SHA512_AVX512_State { uint64_t state[8][8]; };

void sha512_init_sse(SHA512_SSE_State* ctx);
void sha512_init_avx2(SHA512_AVX2_State* ctx);
void sha512_init_avx512(SHA512_AVX512_State* ctx);

void sha512_transform_sse   (SHA512_SSE_State*,    const uint64_t W_in[16][2]);
void sha512_transform_avx2  (SHA512_AVX2_State*,   const uint64_t W_in[16][4]);
void sha512_transform_avx512(SHA512_AVX512_State*, const uint64_t W_in[16][8]);
