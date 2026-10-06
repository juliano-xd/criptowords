#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include "../gpu/gpu_backend.hpp"

namespace cryptowords {

struct CoverageSnapshot;

// Número máximo de candidatos por batch de PBKDF2 (= 16 para AVX-512,
// 8 para AVX2, 4 para SSE; definido por ArchTraits). O storage é
// sobredimensionado para o caso AVX-512.
static constexpr size_t PW_SLOT_SIZE = 512;
static constexpr size_t MAX_BATCH_LANES = 16;
static constexpr size_t MAX_WORDS_PER_MNEMONIC = 24;
static constexpr uint32_t GPU_POST_BATCH = 512;

// -------------------------------------------------------------------------
// Salt HMAC + tabelas do key-schedule do PBKDF2. Imutável por execução;
// copiado para cada thread na criação do contexto.
// -------------------------------------------------------------------------
struct SaltCache {
    std::array<uint8_t, 256> buf{};
    size_t len = 0;

    alignas(64) std::array<uint64_t, 16> block64{};
    alignas(64) std::array<uint64_t, 80> kw_salt{};
    alignas(64) std::array<uint64_t, 80 * 2> kw_salt_sse{};
    alignas(64) std::array<uint64_t, 80 * 4> kw_salt_avx2{};
    alignas(64) std::array<uint64_t, 80 * 8> kw_salt_avx512{};
};

// -------------------------------------------------------------------------
// Cursor de enumeração — estado que o odômetro mantém por thread.
// -------------------------------------------------------------------------
struct EnumCursor {
    std::vector<size_t>   state;        // dígitos mixed-radix (Mixed)
    std::vector<size_t>   outer_state;  // dígitos outer (Streaming)
    std::vector<uint16_t> current_ids;  // mnemônico atual

    // Fila de candidatos para o último slot (Streaming).
    static constexpr size_t K_LAST_MAX = 256;
    std::array<uint16_t, K_LAST_MAX> k_last_w_list{};
    size_t k_last_w_count = 0;
    size_t k_last_w_idx   = 0;

    // Bloco BIP-39 sendo montado (Streaming).
    alignas(64) std::array<uint8_t, 64> k_block64{};

    size_t thread_idx = 0;
    size_t step_size  = 1;

    // Índices para listas pré-computadas (Pairs/Triplets).
    size_t pair_idx = 0, pair_end = 0;
    size_t triplet_idx = 0, triplet_end = 0;

    // Contador linear global. Usado em modo random (é o índice permutado).
    // Em modos normais permanece 0.
    uint64_t linear_counter = 0;

    bool done = false;
    bool last_candidate_accepted = true;
};

// -------------------------------------------------------------------------
// Lote de candidatos (IDs das palavras). Usado em dois estágios:
//   1. checksum_batch: candidatos esperando filtro SHA-256
//   2. pbkdf2_batch:   candidatos que passaram, esperando PBKDF2
// -------------------------------------------------------------------------
struct CandidateBatch {
    static constexpr size_t MAX_LANES = 32;   // cobre AVX-512 2x
    alignas(64) std::array<uint16_t, MAX_LANES * MAX_WORDS_PER_MNEMONIC> ids{};
    size_t size = 0;
};

// -------------------------------------------------------------------------
// Scratch do modo Streaming — vetores pré-computados para SHA-NI em pares.
// Alocado sob demanda, liberado com o contexto.
// -------------------------------------------------------------------------
struct StreamingScratch {
    std::vector<uint8_t> word_vecs;   // 16 B por palavra do wheel
    alignas(16) std::array<uint8_t, 16> clear_mask{};
    alignas(16) std::array<uint8_t, 16> shuf_mask{};
    alignas(16) std::array<uint8_t, 16> msg2{};
    alignas(16) std::array<uint8_t, 16> msg3{};
};

// -------------------------------------------------------------------------
// Estado do pós-PBKDF2 na GPU — ping-pong de dois buffers.
// -------------------------------------------------------------------------
struct GpuPostState {
    IGpuEngine* engine = nullptr;
    std::mutex* mutex  = nullptr;
    uint32_t    slot   = 0;

    std::array<std::vector<uint8_t>,  2> seeds;
    std::array<std::vector<uint16_t>, 2> mnems;
    std::array<uint32_t, 2> count{0, 0};
    std::array<bool,     2> inflight{false, false};
    std::array<uint32_t, 2> result{0xFFFFFFFFu, 0xFFFFFFFFu};
    uint32_t write_idx = 0;
};

// -------------------------------------------------------------------------
// Placeholder para futura backend CUDA/NVIDIA. Ignorado pelo caminho CPU;
// nenhum custo quando não utilizado.
// -------------------------------------------------------------------------
struct NvidiaContext {
    void* device = nullptr;
    void* stream = nullptr;
    std::vector<uint8_t> pinned_seeds;
    std::vector<uint16_t> pinned_mnems;
    uint32_t pending = 0;
};

// -------------------------------------------------------------------------
// Contadores por thread. `local_*` são flushados periodicamente; `cumulative_*`
// acumulam para checkpoint.
// -------------------------------------------------------------------------
struct ThreadCounters {
    size_t   local_tested     = 0;   // chaves submetidas ao PBKDF2
    size_t   local_valid      = 0;   // chaves que passaram no checksum
    size_t   local_eliminated = 0;   // chaves rejeitadas pelo checksum
    uint64_t cumulative_tested = 0;
    uint64_t cumulative_valid  = 0;
};

// -------------------------------------------------------------------------
// Contexto por thread. Buffers persistentes mínimos; o restante é alocado
// em stack dentro de flush_valid_batch.
// -------------------------------------------------------------------------
struct PipelineThreadContext {
    SaltCache      salt;
    EnumCursor     cursor;
    CandidateBatch checksum_batch;  // esperando filtro SHA-256
    CandidateBatch pbkdf2_batch;    // esperando PBKDF2
    StreamingScratch stream;
    GpuPostState   gpu;
    NvidiaContext  nvidia;
    ThreadCounters counters;

    std::array<uint8_t, 20> decoded_target{};

    const std::vector<CoverageSnapshot>* coverage_snapshots = nullptr;

    PipelineThreadContext() noexcept = default;
    PipelineThreadContext(const PipelineThreadContext&) = delete;
    PipelineThreadContext& operator=(const PipelineThreadContext&) = delete;
};

}  // namespace cryptowords
