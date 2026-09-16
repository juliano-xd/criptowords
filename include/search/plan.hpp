#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct OptimizedMnemonics {
    std::vector<uint16_t>              base_mnemonic;
    std::vector<size_t>                unknown_positions;
    std::vector<std::vector<uint16_t>> wheels;

    double math_combinations  = 0.0;
    double total_combinations = 0.0;
    double valid_combinations = 0.0;

    // Prefixo fixo
    std::string prefix_str;
    size_t      prefix_words = 0;

    // Entropia base pré-computada
    uint8_t  base_entropy[32] = {};
    uint64_t base_acc         = 0;
    size_t   base_bits        = 0;
    size_t   base_b_pos       = 0;

    size_t entropy_bits  = 0;
    size_t entropy_bytes = 0;
    size_t checksum_bits = 0;

    // Dedução de checksum na última palavra
    bool auto_deduce_last_word    = false;
    bool allowed_last_words[2048] = {false};

    // Alvo
    uint8_t  target_bytes[20] = {};
    uint32_t target_fast_hash = 0;
    bool     has_target       = false;
};
