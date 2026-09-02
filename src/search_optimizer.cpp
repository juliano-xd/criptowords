#include "../include/search_optimizer.hpp"
#include "../include/bip39.hpp"
#include <algorithm>
#include <numeric>
#include <print>
#include <string_view>

OptimizedMnemonics SearchOptimizer::build_plan(const AppConfig& cfg) {
    OptimizedMnemonics opt;
    opt.base_mnemonic.resize(cfg.mnemonics.size(), AppConfig::UNKNOWN_WORD);

    for (size_t i = 0; i < cfg.mnemonics.size(); ++i) {
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

    // Fase de Pruning (Filtro antecipado de Checksum)
    if (cfg.only_valids && opt.unknown_positions.size() == 1) {
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

    opt.total_combinations = 1.0;
    for (const auto& w : opt.wheels) {
        opt.total_combinations *= static_cast<double>(w.size());
    }

    opt.valid_combinations = opt.total_combinations;
    if (cfg.only_valids && opt.unknown_positions.size() != 1) {
        opt.valid_combinations = opt.total_combinations / 16.0;
    }

    return opt;
}

void SearchOptimizer::print_report(const OptimizedMnemonics& opt, const AppConfig& cfg) {
    std::println("\n[=] PLANO DE BUSCA OTIMIZADO");

    auto get_word = [&cfg](uint16_t id) -> std::string_view {
        return (cfg.wordlist.begin() + id)->first;
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
                std::print("          -> Válidas: ");
                for (uint16_t id : wheel)
                    std::print("'{}' ", get_word(id));
                std::println();
            }
        }
    }

    std::println("\n[=] COMPLEXIDADE MATEMÁTICA");
    std::println("    [+] Eixos Variáveis (Loops): {}", opt.unknown_positions.size());
    std::println("    [+] Total de Combinações   : {}", opt.total_combinations);
    std::println("    [+] Testes Efetivos        : {}", opt.valid_combinations);
}
