#pragma once
#include "bip39.hpp"
#include <cstdint>
#include <string>
#include <vector>

struct SearchConfig {
    // === INPUT DO USUÁRIO ===
    std::string passphrase = "";
    std::string target = "";
    cryptowords::TargetBytes target_bytes;
    int pbkdf2_rounds = 2048;
    int num_threads = 0;
    bool use_gpu = false;

    // === WORDLIST ===
    std::vector<std::string> wordlist;
    std::string wordlist_path = "../wordlist/english.txt";

    // === MNEMONIC ===
    std::vector<std::string> base_words;
    std::vector<size_t> unknown_positions;
    std::vector<std::vector<std::string>> candidates;

    // === COMPUTADO (pelo SearchOptimizer) ===
    uint64_t total_combinations = 0;
    bool has_target = false;

    // === DERIVED CLASS ===
    SearchConfig() = default;

    bool init_target() noexcept {
        if (target.empty()) {
            has_target = false;
            return true;
        }
        has_target = true;
        return target_bytes.init(target);
    }
};
