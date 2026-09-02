#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

struct OptimizedMnemonics {
    std::vector<uint16_t> base_mnemonic;
    std::vector<size_t> unknown_positions;
    std::vector<std::vector<uint16_t>> wheels;

    double total_combinations = 0.0;
    double valid_combinations = 0.0;
};
