#pragma once
#include "../config.hpp"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "../math/UInt.hpp"
#pragma GCC diagnostic pop
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct MnemonicSlice {
    bool is_variable = false;
    size_t word_idx  = 0;
    std::string text;
};

struct OptimizedMnemonics {
    std::vector<uint16_t>              base_mnemonic;
    std::vector<size_t>                unknown_positions;
    std::vector<std::vector<uint16_t>> wheels;

    double math_combinations  = 0.0;
    double total_combinations = 0.0;
    double valid_combinations = 0.0;

    UInt<4> exact_math_combinations  = UInt<4>(1);
    UInt<4> exact_total_combinations = UInt<4>(1);
    UInt<4> exact_valid_combinations = UInt<4>(1);

    // Prefixo fixo & OTM-09: Fatiamento em N-Slices
    std::string prefix_str;
    size_t      prefix_words = 0;
    std::vector<MnemonicSlice> slices;
    size_t      slice0_static_len = 0;

    // Entropia base pré-computada
    uint8_t  base_entropy[32] = {};
    uint64_t base_acc         = 0;
    size_t   base_bits        = 0;
    size_t   base_b_pos       = 0;

    size_t entropy_bits  = 0;
    size_t entropy_bytes = 0;
    size_t checksum_bits = 0;

    bool auto_deduce_last_word    = false;
    bool allowed_last_words[2048] = {false};
    bool direct_valid_wheels      = false;

    // OTM-02: Pruning Analítico de Pares em F_2^C
    bool has_valid_pairs = false;
    std::vector<std::pair<uint16_t, uint16_t>> valid_pairs;

    // OTM-03 / Generalização Afim em F_2^C (K >= 3)
    bool has_streaming_pruning = false;
    bool has_k3_pruning = false;

    // OTM-29: Funneling por Gradiente de Hamming & Estratégias
    std::vector<SearchStrategy> active_strategies;
    SearchStrategy              active_strategy      = SearchStrategy::Default;
    bool                        has_hamming_gradient = false;
    bool                        has_frequency        = false;
    bool                        has_typo             = false;
    bool                        has_midstate_caching = false;

    bool has_strategy(SearchStrategy s) const {
        for (auto x : active_strategies) if (x == s) return true;
        return false;
    }

    // OTM-09: Fatiamento no Bloco SHA-256 (Two-Sided Memory Patching)
    alignas(64) uint8_t base_block64[64] = {};
    std::vector<size_t> unknown_bit_offsets;
    uint8_t expected_checksum = 0;

    // OTM-30: Restrição de Não-Repetição (--distinct)
    bool   has_distinct_pruning   = false;
    size_t distinct_pruned_words  = 0;

    // OTM-31: Agendador por Código de Gray Multidimensional
    bool has_gray_code = true;

    // OTM-32: Beam Search / A* Heurístico Ordenado por Custo
    bool   has_beam_search  = false;
    size_t beam_shell_count = 1;

    // OTM-33: Dedução Cascata de Checksum (w_{N-1} = ?)
    bool has_cascade_deduction = false;

    // Alvo
    uint8_t  target_bytes[20] = {};
    uint32_t target_fast_hash = 0;
    uint64_t target_fast_hash64 = 0;
    bool     has_target       = false;
};
