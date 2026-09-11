#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

struct OptimizedMnemonics {
    std::vector<uint16_t> base_mnemonic;
    std::vector<size_t> unknown_positions;
    std::vector<std::vector<uint16_t>> wheels;

    double total_combinations = 0.0;
    double valid_combinations = 0.0;

    // Otimização de Prefixo
    std::string prefix_str;
    size_t prefix_words = 0;

    // Otimização de Entropia Base
    uint8_t base_entropy[32] = {};
    uint32_t base_acc = 0;
    size_t base_bits = 0;
    size_t base_b_pos = 0;

    // Dedução de Checksum
    bool auto_deduce_last_word = false;
    bool allowed_last_words[2048] = {false};

    // Alvo Otimizado
    uint8_t target_bytes[20] = {};
    uint32_t target_fast_hash = 0;
    bool has_target = false;

};
