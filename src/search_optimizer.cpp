#include "../include/search_optimizer.hpp"
#include "../include/bip39.hpp"
#include <algorithm>
#include <numeric>
#include <print>
#include <string_view>
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

    const size_t checksum_bits = mnemonic_len * 11 / 33;
    size_t entropy_bits = mnemonic_len * 11 - checksum_bits;
    size_t entropy_bytes = entropy_bits / 8;

    for (size_t i = 0; i < opt.prefix_words; ++i) {
        opt.base_acc = (opt.base_acc << 11) | (opt.base_mnemonic[i] & 0x7FF);
        opt.base_bits += 11;
        while (opt.base_bits >= 8) {
            if (opt.base_b_pos < entropy_bytes) {
                opt.base_entropy[opt.base_b_pos++] = (opt.base_acc >> (opt.base_bits - 8)) & 0xFF;
                opt.base_bits -= 8;
            } else break;
        }
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
    opt.total_combinations = 1.0;
    for (const auto& w : opt.wheels) {
        opt.total_combinations *= static_cast<double>(w.size());
    }

    opt.valid_combinations = opt.total_combinations;
    if (cfg.only_valids && opt.unknown_positions.size() != 1 && !opt.auto_deduce_last_word) {
        opt.valid_combinations = opt.total_combinations / 16.0;
    }


    // ==========================================
    // OTIMIZAÇÃO 4: Reversão / Pre-computação do Target
    // ==========================================
    if (!cfg.target.empty()) {
        opt.has_target = true;
        if (cfg.coin == CoinTarget::BTC) {
            cryptowords::Bip39Deriver::decode_base58_btc_address(cfg.target, opt.target_bytes);
        } else {
            cryptowords::Bip39Deriver::decode_hex_eth_address(cfg.target, opt.target_bytes);
        }
        // Extrai os 4 primeiros bytes (32 bits) para Rejeição Precoce ultra-rápida (bypass memcmp)
        std::memcpy(&opt.target_fast_hash, opt.target_bytes, 4);
    }

    return opt;
}

void SearchOptimizer::print_report(const OptimizedMnemonics& opt, const AppConfig& cfg) {
    std::println("\n[=] PLANO DE BUSCA OTIMIZADO");

    auto get_word = [&cfg](uint16_t id) -> std::string_view {
        return cfg.wordlist[id];
    };

    size_t wheel_idx = 0;
    for (size_t i = 0; i < opt.base_mnemonic.size(); ++i) {
        if (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD) {
            std::println("    [{:02}] [FIXO]      Word ID: {:04} ('{}')", i, opt.base_mnemonic[i],
                         get_word(opt.base_mnemonic[i]));
        } else {
            const auto& wheel = opt.wheels[wheel_idx++];
            if (wheel.size() == 2048) {
                std::println("    [{:02}] [VARIÁVEL]  Word ID: 0000 -> 2047 (Força Bruta Total)",
                             i);
            } else {
                std::println("    [{:02}] [VARIÁVEL]  Word ID: {} opções restritas", i,
                             wheel.size());
            }
        }
    }

    std::println("\n[=] COMPLEXIDADE MATEMÁTICA");
    std::println("    [+] Eixos Variáveis (Loops): {}", opt.unknown_positions.size());
    std::println("    [+] Total de Combinações   : {:.0f}", opt.total_combinations);
    std::println("    [+] Testes Efetivos        : {:.0f}", opt.valid_combinations);
    
    if (opt.auto_deduce_last_word) {
        std::println("    [!] OTIMIZAÇÃO ATIVA       : Dedução Reversa de Checksum na Última Palavra");
    }
    if (opt.prefix_words > 0) {
        std::println("    [!] OTIMIZAÇÃO ATIVA       : Template de Strings Fixo ({} palavras)", opt.prefix_words);
    }

    if (opt.has_target) {
        std::println("    [!] OTIMIZAÇÃO ATIVA       : Target Reverso! Payload de 20-bytes decodificado em O(1)");
        std::println("    [!] REJEIÇÃO PRECOCE (C1)  : Token de comparação 32-bits gerado: 0x{:08x}", opt.target_fast_hash);
    }

}
