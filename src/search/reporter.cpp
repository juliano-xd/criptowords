#include "../../include/search/reporter.hpp"
#include <print>
#include <string_view>

void SearchReporter::print_plan(const OptimizedMnemonics& opt, const AppConfig& cfg) {
    std::println("\n[=] PLANO DE BUSCA OTIMIZADO");

    auto get_word = [&cfg](uint16_t id) -> std::string_view {
        return cfg.wordlist[id];
    };

    size_t wheel_idx = 0;
    for (size_t i = 0; i < opt.base_mnemonic.size(); ++i) {
        if (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD) {
            std::println("    [{:02}] [FIXO]      Word ID: {:04} ('{}')", i, opt.base_mnemonic[i], get_word(opt.base_mnemonic[i]));
        } else {
            const auto& wheel = opt.wheels[wheel_idx++];
            if (wheel.size() == 2048) {
                std::println("    [{:02}] [VARIÁVEL]  Word ID: 0000 -> 2047 (Força Bruta Total)", i);
            } else {
                std::println("    [{:02}] [VARIÁVEL]  Word ID: {} opções restritas", i, wheel.size());
            }
        }
    }

    std::println("\n[=] COMPLEXIDADE MATEMÁTICA");
    std::println("    [+] Eixos Variáveis (Loops): {}", opt.unknown_positions.size());
    std::println("    [+] Combinações Originais  : {:.0f}", opt.math_combinations);
    std::println("    [+] Base-States (SIMD Loop): {:.0f}", opt.total_combinations);
    std::println("    [+] Hashes Efetivos PBKDF2 : {:.0f}", opt.valid_combinations);

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
