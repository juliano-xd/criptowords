#pragma once
#include <atomic>
#include <array>
#include <cstdint>
#include <cstring>

namespace cryptowords {

// -------------------------------------------------------------------------
// ThreadSnapshot — visão publicada por uma thread para a UI.
//
// A thread escreve via publish(); o monitor lê via read(). O campo `seq`
// alterna ímpar/par durante publish para garantir consistência sem lock.
// -------------------------------------------------------------------------
struct ThreadSnapshot {
    static constexpr size_t MAX_WORDS = 24;
    static constexpr size_t MAX_VARS  = 24;

    alignas(64) std::atomic<uint64_t> seq{0};

    // Estado da enumeração.
    std::array<uint32_t, MAX_WORDS> current_words{};
    std::array<uint32_t, MAX_VARS>  state{};
    uint32_t state_len    = 0;
    uint32_t mnemonic_len = 0;

    // Fila de candidatos do último slot (modo Streaming).
    uint32_t k_last_w_idx   = 0;
    uint32_t k_last_w_count = 0;

    // Contadores cumulativos desta thread.
    uint64_t cumulative_tested = 0;
    uint64_t cumulative_valid  = 0;

    // Posição linear na enumeração (para resume).
    uint64_t linear_index = 0;

    struct View {
        std::array<uint32_t, MAX_WORDS> current_words;
        std::array<uint32_t, MAX_VARS>  state;
        uint32_t state_len;
        uint32_t mnemonic_len;
        uint32_t k_last_w_idx;
        uint32_t k_last_w_count;
        uint64_t cumulative_tested;
        uint64_t cumulative_valid;
        uint64_t linear_index;
    };

    void publish(const uint16_t* cur_ids, size_t cur_len,
                 const size_t*   st,      size_t st_len,
                 uint32_t k_idx, uint32_t k_count,
                 uint64_t cum_tested, uint64_t cum_valid,
                 uint64_t li) noexcept {
        seq.fetch_add(1, std::memory_order_seq_cst);

        mnemonic_len = static_cast<uint32_t>(cur_len);
        const size_t nw = std::min(cur_len, MAX_WORDS);
        for (size_t i = 0; i < nw; ++i) current_words[i] = cur_ids[i];

        state_len = static_cast<uint32_t>(st_len);
        const size_t ns = std::min(st_len, MAX_VARS);
        for (size_t i = 0; i < ns; ++i) state[i] = static_cast<uint32_t>(st[i]);

        k_last_w_idx      = k_idx;
        k_last_w_count    = k_count;
        cumulative_tested = cum_tested;
        cumulative_valid  = cum_valid;
        linear_index      = li;

        seq.fetch_add(1, std::memory_order_seq_cst);
    }

    bool read(View& out) const noexcept {
        for (int retry = 0; retry < 8; ++retry) {
            const uint64_t s0 = seq.load(std::memory_order_seq_cst);
            if (s0 & 1) continue;

            out.current_words = current_words;
            out.state         = state;
            out.state_len         = state_len;
            out.mnemonic_len      = mnemonic_len;
            out.k_last_w_idx      = k_last_w_idx;
            out.k_last_w_count    = k_last_w_count;
            out.cumulative_tested = cumulative_tested;
            out.cumulative_valid  = cumulative_valid;
            out.linear_index      = linear_index;

            const uint64_t s1 = seq.load(std::memory_order_seq_cst);
            if (s0 == s1) return true;
        }
        return false;
    }
};

}  // namespace cryptowords
