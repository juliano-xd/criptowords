#pragma once
#include "../config.hpp"
#include "plan.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace cryptowords {

uint64_t search_total_space(const OptimizedMnemonics& opt) noexcept;

static constexpr uint32_t CKPT_MAGIC   = 0x56535743;  // 'CWSV'
static constexpr uint32_t CKPT_VERSION = 4;           // v4: original_wheels + bitset
static constexpr uint64_t CKPT_MARGIN  = 256;

// 2048 bits = 32 × uint64_t. Teste/marcação em 1 instrução; serialização
// natural para 256 B.
using WordBitset = std::array<uint64_t, 32>;

inline void bitset_set(WordBitset& bs, uint16_t w) noexcept {
    bs[w >> 6] |= (1ULL << (w & 63));
}
[[nodiscard]] inline bool bitset_test(const WordBitset& bs, uint16_t w) noexcept {
    return (bs[w >> 6] >> (w & 63)) & 1ULL;
}

// -------------------------------------------------------------------------
// CoverageSnapshot — descrição compacta de um espaço de busca já explorado.
// Execuções futuras com a mesma base_mnemonic usam para pular candidatos.
// -------------------------------------------------------------------------
struct CoverageSnapshot {
    std::vector<uint16_t> base_mnemonic;
    std::vector<WordBitset> allowed_at_position;   // um por incógnita
    std::vector<std::pair<uint16_t, uint8_t>> exact_counts;
    bool     distinct = false;
    uint64_t hash     = 0;                          // FNV-1a 64-bit
};

CoverageSnapshot make_coverage_snapshot(const OptimizedMnemonics& opt,
                                        const AppConfig& cfg) noexcept;

bool snapshot_covers(const CoverageSnapshot& s,
                     const std::vector<uint16_t>& mn) noexcept;

bool covered_by_any(const std::vector<CoverageSnapshot>& snaps,
                    const std::vector<uint16_t>& mn) noexcept;

#pragma pack(push, 1)
struct CheckpointHeader {
    uint32_t magic           = CKPT_MAGIC;
    uint32_t version         = CKPT_VERSION;
    uint32_t mode            = 0;
    uint32_t n_threads       = 0;
    uint64_t total_space     = 0;
    uint64_t total_processed = 0;
    uint64_t save_timestamp  = 0;
    uint32_t checksum_bits   = 0;
    uint32_t n_snapshots     = 0;
    uint64_t config_hash     = 0;
};

// Sem state[] — resume usa linear_index + seek_linear.
struct CheckpointThread {
    uint64_t linear_index = 0;
    uint64_t processed    = 0;
};
#pragma pack(pop)

struct Checkpoint {
    CheckpointHeader header;
    std::vector<CoverageSnapshot> snapshots;
    std::vector<CheckpointThread> threads;
    bool config_compatible = false;
};

uint64_t compute_config_hash(const OptimizedMnemonics& opt,
                             const AppConfig& cfg) noexcept;

bool save_checkpoint(const std::string& path,
                     const OptimizedMnemonics& opt,
                     const AppConfig& cfg,
                     const std::vector<uint64_t>& linear_indices,
                     const std::vector<uint64_t>& processed,
                     const std::vector<CoverageSnapshot>& snapshots) noexcept;

bool load_checkpoint(const std::string& path,
                     Checkpoint& out,
                     const OptimizedMnemonics& opt,
                     const AppConfig& cfg) noexcept;

inline uint64_t checkpoint_frontier(const Checkpoint& ckpt) noexcept {
    uint64_t min_idx = UINT64_MAX;
    for (const auto& t : ckpt.threads)
        if (t.linear_index < min_idx) min_idx = t.linear_index;
    if (min_idx == UINT64_MAX) return 0;
    return min_idx > CKPT_MARGIN ? min_idx - CKPT_MARGIN : 0;
}

}  // namespace cryptowords
