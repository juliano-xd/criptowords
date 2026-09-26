#include "../../include/search/reporter.hpp"

#include <algorithm>
#include <cstdio>
#include <format>
#include <print>
#include <string>
#include <vector>

#include "../../include/cli/ui.hpp"

using namespace cryptowords::ui;

void SearchReporter::print_plan(const OptimizedMnemonics& opt, const AppConfig& cfg) {
    const size_t n_words = opt.base_mnemonic.size();
    const size_t n_unknowns = opt.unknown_positions.size();
    const size_t INNER_WIDTH = DEFAULT_INNER_WIDTH;

    std::print("\n");
    print_box_top("AFUNILAMENTO COMBINATÓRIO & PLANO DE BUSCA", INNER_WIDTH);

    // Mnemônico com badges
    std::string mnem_title =
        std::format("Frase ({} palavras, {} incógnita{}):", n_words, n_unknowns, (n_unknowns == 1 ? "" : "s"));
    print_box_line(std::format("\033[1;37m{}\033[0m", mnem_title), INNER_WIDTH);

    std::string current_line = "";
    size_t current_vis_len = 0;
    for (size_t i = 0; i < n_words; ++i) {
        std::string token;
        size_t token_vis = 0;
        if (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD) {
            token = cfg.wordlist[opt.base_mnemonic[i]];
            token_vis = token.size();
        } else {
            token = std::format("\033[1;93m[?#{:02d}]\033[0m", i + 1);
            token_vis = 7;
        }

        if (current_vis_len + token_vis + (current_vis_len > 0 ? 2 : 0) > INNER_WIDTH) {
            print_box_line(current_line, INNER_WIDTH);
            current_line.clear();
            current_vis_len = 0;
        }
        if (current_vis_len > 0) {
            current_line += "  ";
            current_vis_len += 2;
        }
        current_line += token;
        current_vis_len += token_vis;
    }
    if (!current_line.empty()) {
        print_box_line(current_line, INNER_WIDTH);
    }

    print_box_separator(INNER_WIDTH);

    // Parâmetros e Estratégia
    std::string coin_str = (cfg.coin == CoinTarget::BTC) ? "Bitcoin (BTC)" : "Ethereum (ETH)";
    std::string pass_str = cfg.passphrase.empty() ? "(nenhuma)" : std::format("\"{}\"", cfg.passphrase);
    print_box_line(std::format("Moeda: {:<14} │ Threads: {:<2}  │ Rounds: {:<5} │ Senha: {:<12}", coin_str,
                               cfg.num_threads, cfg.pbkdf2_rounds, pass_str),
                   INNER_WIDTH);

    std::string strat_str;
    if (opt.active_strategies.empty() ||
        (opt.active_strategies.size() == 1 && opt.active_strategies[0] == SearchStrategy::Default)) {
        strat_str = "Padrão (Filtros em F₂ᶜ)";
    } else {
        std::vector<std::string> names;
        for (auto s : opt.active_strategies) {
            if (s == SearchStrategy::HammingGradient)
                names.push_back("Hamming (OTM-29)");
            else if (s == SearchStrategy::Frequency)
                names.push_back("Frequência (Zipf)");
            else if (s == SearchStrategy::Typo)
                names.push_back(std::format("Levenshtein (dist≤{})", cfg.max_distance));
        }
        if (names.size() == 1) {
            if (opt.active_strategies[0] == SearchStrategy::HammingGradient)
                strat_str = "Gradiente de Hamming & Entropia (OTM-29)";
            else if (opt.active_strategies[0] == SearchStrategy::Frequency)
                strat_str = "Frequência Linguística (Zipf)";
            else if (opt.active_strategies[0] == SearchStrategy::Typo)
                strat_str = std::format("Autômatos Levenshtein (Typo, dist≤{})", cfg.max_distance);
        } else {
            strat_str = "Combinada (";
            for (size_t i = 0; i < names.size(); ++i) {
                strat_str += names[i];
                if (i + 1 < names.size())
                    strat_str += " + ";
            }
            strat_str += ")";
        }
    }
    print_box_line(std::format("Estratégia  : \033[1;36m{}\033[0m", strat_str), INNER_WIDTH);

    if (!cfg.target.empty()) {
        print_box_line(std::format("Alvo        : \033[1;32m{:<34}\033[0m \033[90m(Token C1: 0x{:08x})\033[0m",
                                   cfg.target, opt.target_fast_hash),
                       INNER_WIDTH);
    }

    print_box_separator(INNER_WIDTH);

    // Redução Matemática do Espaço
    print_box_line(
        std::format("   Espaço Bruto Total       : {:>14} combinações", format_num(opt.exact_math_combinations)),
        INNER_WIDTH);

    double current_comb = opt.math_combinations;
    double valid_target = opt.valid_combinations;
    double ratio = (valid_target > 0) ? (current_comb / valid_target) : 1.0;

    print_box_line(std::format("   Poda Matemática Checksum : {:>14} chaves válidas  [Redução: {:>5.1f}x]",
                               format_num(opt.exact_valid_combinations), ratio),
                   INNER_WIDTH);
    print_box_line(std::format("   \033[1;32m➔ Chaves Efetivas PBKDF2\033[0m : \033[1;32m{:>14} chaves\033[0m         "
                               "\033[1;33m[PODA: {:>5.1f}x]\033[0m",
                               format_num(opt.exact_valid_combinations), ratio),
                   INNER_WIDTH);

    print_box_separator(INNER_WIDTH);

    // Badges de Otimização Ativas
    print_box_line("\033[1;36mOTIMIZAÇÕES ATIVAS:\033[0m", INNER_WIDTH);

    if (opt.has_valid_triplets) {
        print_box_line(std::format("   [-] OTM-03 / OTM-34 (F₂ᶜ - K=3): {:>6} triplas [Redução: {:>5.1f}x]",
                                   format_num(static_cast<double>(opt.valid_triplets.size())), ratio),
                       INNER_WIDTH);
    } else if (opt.has_valid_pairs) {
        print_box_line(std::format("   [-] OTM-02 (Pruning em F₂ᶜ) : {:>10} pares [Redução: {:>5.1f}x]",
                                   format_num(static_cast<double>(opt.valid_pairs.size())), ratio),
                       INNER_WIDTH);
    } else if (opt.has_streaming_pruning) {
        print_box_line(std::format("   [-] OTM-03 (Poda em F₂ᶜ - K={}): {:>8} chaves [Redução: {:>5.1f}x]",
                                   opt.unknown_positions.size(), format_num(opt.valid_combinations), ratio),
                       INNER_WIDTH);
    } else if (opt.direct_valid_wheels) {
        print_box_line(std::format("   [-] OTM-01 (Dedução Reversa): {:>10} chaves [Bypass Checksum]",
                                   format_num(opt.total_combinations)),
                       INNER_WIDTH);
    } else if (opt.auto_deduce_last_word) {
        print_box_line(std::format("   [-] Dedução Reversa Checksum: {:>10} chaves [Síntese Analítica]",
                                   format_num(opt.total_combinations)),
                       INNER_WIDTH);
    }

    if (!opt.slices.empty()) {
        print_box_line(std::format("   [-] OTM-09 (Fatiamento Mem) : {:>10} fatias [L1 Patching]", opt.slices.size()),
                       INNER_WIDTH);
    }
    print_box_line("   [-] OTM-15 (Salt Pré-comp)  : Ativo | OTM-23 (PBKDF2 Fast-Fwd): Ativo", INNER_WIDTH);

    if (opt.has_hamming_gradient)
        print_box_line("   [-] OTM-29 (Gradiente Hamming): Ativo [Varredura por Entropia]", INNER_WIDTH);
    if (opt.has_frequency)
        print_box_line("   [-] Heurística de Frequência  : Ativo [Lei de Zipf Ponderada]", INNER_WIDTH);
    if (opt.has_typo)
        print_box_line("   [-] Autômatos de Levenshtein  : Ativo [Aproximação de Typos]", INNER_WIDTH);
    if (opt.has_distinct_pruning)
        print_box_line("   [-] Restrição Não-Repetição : Ativo [Poda Combinatória]", INNER_WIDTH);
    if (opt.has_cascade_deduction)
        print_box_line(std::format("   [-] Dedução Cascata (w_N-1) : Ativo [Poda: {:>3.0f}x]", ratio), INNER_WIDTH);
    if (opt.has_gray_code)
        print_box_line("   [-] Agendador Gray-Code     : Ativo [Localidade L1 Hamming=1]", INNER_WIDTH);
    if (opt.has_beam_search)
        print_box_line("   [-] Beam Search / A*        : Ativo [Feixes Probabilísticos]", INNER_WIDTH);

    print_box_bottom(INNER_WIDTH);
    std::print("\n");
    std::fflush(stdout);
}
