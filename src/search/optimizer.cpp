#include "../../include/search/optimizer.hpp"
#include "../../include/crypto/bip39.hpp"
#include <algorithm>
#include <numeric>
#include <cstring>

OptimizedMnemonics SearchOptimizer::build_plan(const AppConfig& cfg) {
    OptimizedMnemonics opt;
    size_t mnemonic_len = cfg.mnemonics.size();
    opt.base_mnemonic.resize(mnemonic_len, AppConfig::UNKNOWN_WORD);

    for (size_t i = 0; i < mnemonic_len; ++i) {
        if (std::holds_alternative<uint16_t>(cfg.mnemonics[i])) {
            uint16_t id = std::get<uint16_t>(cfg.mnemonics[i]);
            opt.base_mnemonic[i] = id;
            if (id == AppConfig::UNKNOWN_WORD) {
                opt.unknown_positions.push_back(i);
                std::vector<uint16_t> full_wheel(2048);
                std::ranges::iota(full_wheel.begin(), full_wheel.end(), 0);
                opt.wheels.push_back(std::move(full_wheel));
            }
        } else if (std::holds_alternative<std::vector<uint16_t>>(cfg.mnemonics[i])) {
            opt.base_mnemonic[i] = AppConfig::UNKNOWN_WORD;
            opt.unknown_positions.push_back(i);
            auto wheel = std::get<std::vector<uint16_t>>(cfg.mnemonics[i]);
            std::ranges::sort(wheel);
            opt.wheels.push_back(std::move(wheel));
        }
    }

    // ==========================================
    // OTIMIZAÇÃO 1: Prefixo Fixo e Base Entropy
    // ==========================================
    while (opt.prefix_words < mnemonic_len && opt.base_mnemonic[opt.prefix_words] != AppConfig::UNKNOWN_WORD) {
        opt.prefix_words++;
    }

    for (size_t i = 0; i < opt.prefix_words; ++i) {
        opt.prefix_str += cfg.wordlist[opt.base_mnemonic[i]];
        if (i < mnemonic_len - 1) opt.prefix_str += cfg.separator;
    }

    opt.checksum_bits = mnemonic_len * 11 / 33;
    opt.entropy_bits = mnemonic_len * 11 - opt.checksum_bits;
    opt.entropy_bytes = opt.entropy_bits / 8;
    const size_t checksum_bits = opt.checksum_bits;
    const size_t entropy_bytes = opt.entropy_bytes;

    for (size_t i = 0; i < opt.prefix_words; ++i) {
        opt.base_acc = (opt.base_acc << 11) | (opt.base_mnemonic[i] & 0x7FF);
        opt.base_bits += 11;
        while (opt.base_bits >= 8) {
            opt.base_bits -= 8;
            if (opt.base_b_pos < entropy_bytes) {
                opt.base_entropy[opt.base_b_pos++] = (opt.base_acc >> opt.base_bits) & 0xFF;
            }
        }
        opt.base_acc &= (1ULL << opt.base_bits) - 1;
    }

    // ==========================================
    // OTIMIZAÇÃO 2: Dedução de Checksum (Última Palavra)
    // ==========================================
    if (cfg.only_valids && !opt.unknown_positions.empty() && opt.unknown_positions.back() == mnemonic_len - 1) {
        opt.auto_deduce_last_word = true;

        size_t last_wheel_idx = opt.wheels.size() - 1;
        for (uint16_t id : opt.wheels[last_wheel_idx]) {
            opt.allowed_last_words[id] = true;
        }

        size_t entropy_bits_in_last_word = 11 - checksum_bits;
        size_t num_base_states = 1ULL << entropy_bits_in_last_word;

        std::vector<uint16_t> new_last_wheel;
        new_last_wheel.reserve(num_base_states);
        for (size_t e = 0; e < num_base_states; ++e) {
            new_last_wheel.push_back(static_cast<uint16_t>(e << checksum_bits));
        }
        opt.wheels[last_wheel_idx] = std::move(new_last_wheel);
    }

    // ==========================================
    // OTIMIZAÇÃO 3: Pruning Simples
    // ==========================================
    if (cfg.only_valids && opt.unknown_positions.size() == 1 && !opt.auto_deduce_last_word) {
        size_t var_idx = opt.unknown_positions[0];
        std::vector<uint16_t> filtered_wheel;
        std::vector<uint16_t> test_mn = opt.base_mnemonic;
        for (uint16_t candidate_id : opt.wheels[0]) {
            test_mn[var_idx] = candidate_id;
            if (cryptowords::Bip39Deriver::verify_checksum(test_mn)) {
                filtered_wheel.push_back(candidate_id);
            }
        }
        opt.wheels[0] = std::move(filtered_wheel);
    }

    // Cálculo de Combinações
    opt.math_combinations = 1.0;
    for (size_t i = 0; i < mnemonic_len; ++i) {
        if (std::holds_alternative<std::vector<uint16_t>>(cfg.mnemonics[i])) {
            opt.math_combinations *= static_cast<double>(std::get<std::vector<uint16_t>>(cfg.mnemonics[i]).size());
        } else if (std::holds_alternative<uint16_t>(cfg.mnemonics[i])) {
            if (std::get<uint16_t>(cfg.mnemonics[i]) == AppConfig::UNKNOWN_WORD) {
                opt.math_combinations *= 2048.0;
            }
        }
    }

    opt.total_combinations = 1.0;
    for (const auto& w : opt.wheels) {
        opt.total_combinations *= static_cast<double>(w.size());
    }

    opt.valid_combinations = opt.total_combinations;
    if (cfg.only_valids && opt.unknown_positions.size() != 1 && !opt.auto_deduce_last_word) {
        opt.valid_combinations = opt.total_combinations / static_cast<double>(1ULL << checksum_bits);
    }

    // ==========================================
    // OTIMIZAÇÃO 4: Reversão / Pré-computação do Target
    // ==========================================
    if (!cfg.target.empty()) {
        opt.has_target = true;
        if (cfg.coin == CoinTarget::BTC) {
            cryptowords::Bip39Deriver::decode_base58_btc_address(cfg.target, opt.target_bytes);
        } else {
            cryptowords::Bip39Deriver::decode_hex_eth_address(cfg.target, opt.target_bytes);
        }
        std::memcpy(&opt.target_fast_hash, opt.target_bytes, 4);
    }

    return opt;
}
