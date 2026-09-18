#include "../../include/search/reporter.hpp"
#include "../../include/cli/ui.hpp"
#include <print>
#include <string>
#include <string_view>
#include <format>
#include <algorithm>

using namespace cryptowords::ui;

void SearchReporter::print_plan(const OptimizedMnemonics& opt, const AppConfig& cfg) {
    const size_t n_words = opt.base_mnemonic.size();
    const size_t n_unknowns = opt.unknown_positions.size();
    const size_t INNER_WIDTH = DEFAULT_INNER_WIDTH;

    // =========================================================================
    // CARD 1: CONFIGURAÇÃO DE ENTRADA & MNEMÔNICO
    // =========================================================================
    std::print("\n");
    print_box_top("CriptoWords v2.0", INNER_WIDTH);

    std::string title = std::format("Frase Mnemônica ({} palavras, {} incógnita{}):",
                                    n_words, n_unknowns, (n_unknowns == 1 ? "" : "s"));
    print_box_line(std::format("\033[1;37m{}\033[0m", title), INNER_WIDTH);

    // Formatação do mnemônico com quebra inteligente e badges nas incógnitas
    std::string current_line = "";
    size_t current_vis_len = 0;

    for (size_t i = 0; i < n_words; ++i) {
        std::string token;
        size_t token_vis = 0;

        if (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD) {
            token = cfg.wordlist[opt.base_mnemonic[i]];
            token_vis = token.size();
        } else {
            // Badges legíveis de 1 a N (ex: [?#09]) em amarelo brilhante
            token = std::format("\033[1;93m[?#{:02d}]\033[0m", i + 1);
            token_vis = 7; // "[?#09]" tem 7 caracteres visíveis
        }

        if (current_vis_len + token_vis + (current_vis_len > 0 ? 2 : 0) > INNER_WIDTH) {
            print_box_line(current_line, INNER_WIDTH);
            current_line = "";
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

    std::string coin_str = (cfg.coin == CoinTarget::BTC) ? "Bitcoin (BTC)" : "Ethereum (ETH)";
    std::string pass_str = cfg.passphrase.empty() ? "(nenhuma)" : std::format("\"{}\"", cfg.passphrase);
    std::string params_line = std::format("Moeda: {:<14} │ Threads: {:<2}  │ Rounds: {:<5} │ Senha: {:<12}",
                                          coin_str, cfg.num_threads, cfg.pbkdf2_rounds, pass_str);
    std::string strat_str = "";
    if (opt.active_strategies.empty() ||
        (opt.active_strategies.size() == 1 && opt.active_strategies[0] == SearchStrategy::Default)) {
        strat_str = "Padrão (Filtros em F₂ᶜ)";
    } else {
        std::vector<std::string> names;
        for (auto s : opt.active_strategies) {
            if (s == SearchStrategy::HammingGradient) names.push_back("Hamming (OTM-29)");
            else if (s == SearchStrategy::Frequency) names.push_back("Frequência (Zipf)");
            else if (s == SearchStrategy::Typo) names.push_back(std::format("Levenshtein (dist≤{})", cfg.max_distance));
        }
        if (names.size() == 1) {
            if (opt.active_strategies[0] == SearchStrategy::HammingGradient) strat_str = "Gradiente de Hamming & Entropia (OTM-29)";
            else if (opt.active_strategies[0] == SearchStrategy::Frequency) strat_str = "Frequência Linguística (Zipf)";
            else if (opt.active_strategies[0] == SearchStrategy::Typo) strat_str = std::format("Autômatos Levenshtein (Typo, dist≤{})", cfg.max_distance);
        } else {
            strat_str = "Combinada (";
            for (size_t i = 0; i < names.size(); ++i) {
                strat_str += names[i];
                if (i + 1 < names.size()) strat_str += " + ";
            }
            strat_str += ")";
        }
    }

    std::string strat_line = std::format("Estratégia  : \033[1;36m{}\033[0m", strat_str);
    print_box_line(params_line, INNER_WIDTH);
    print_box_line(strat_line, INNER_WIDTH);

    if (!cfg.target.empty()) {
        std::string target_line = std::format("Alvo : \033[1;32m{:<34}\033[0m \033[90m(Token C1: 0x{:08x})\033[0m",
                                              cfg.target, opt.target_fast_hash);
        print_box_line(target_line, INNER_WIDTH);
    }
    print_box_bottom(INNER_WIDTH);

    // =========================================================================
    // CARD 2: AFUNILAMENTO COMBINATÓRIO & PODA MATEMÁTICA
    // =========================================================================
    print_box_top("AFUNILAMENTO COMBINATÓRIO & PODA MATEMÁTICA", INNER_WIDTH);

    print_box_line("\033[1;36m1. ESPAÇO DE BUSCA & REDUÇÃO MATEMÁTICA\033[0m", INNER_WIDTH);

    std::string bruto_line = std::format("   Espaço Bruto Total       : {:>14} combinações", format_num(opt.math_combinations));
    print_box_line(bruto_line, INNER_WIDTH);

    double current_comb = opt.math_combinations;
    double valid_target = opt.valid_combinations;
    double ratio = (valid_target > 0) ? (current_comb / valid_target) : 1.0;
    double saved_pct = (current_comb > 0) ? (100.0 * (1.0 - (valid_target / current_comb))) : 0.0;

    std::string poda_line = std::format("   Poda Matemática Checksum : {:>14} chaves válidas  [Redução: {:>5.1f}x]",
                                        format_num(valid_target), ratio);
    print_box_line(poda_line, INNER_WIDTH);

    std::string efetivas_line = std::format("   \033[1;32m➔ Chaves Efetivas PBKDF2\033[0m : \033[1;32m{:>14} chaves\033[0m         \033[1;33m[PODA: {:>5.1f}x]\033[0m",
                                            format_num(valid_target), ratio);
    print_box_line(efetivas_line, INNER_WIDTH);

    std::string economia_line = std::format("      \033[90m└─> Economia: {:.1f}% do espaço bruto descartado antes do cálculo pesado!\033[0m", saved_pct);
    print_box_line(economia_line, INNER_WIDTH);

    print_box_separator(INNER_WIDTH);

    print_box_line("\033[1;36m2. OTIMIZAÇÕES & ACELERAÇÕES EM HARDWARE ATIVAS\033[0m", INNER_WIDTH);

    if (opt.has_valid_pairs) {
        std::string l1 = std::format("   [-] OTM-02 (Pruning em F₂ᶜ) : {:>10} pares    [Redução: {:>5.1f}x]",
                                     format_num(static_cast<double>(opt.valid_pairs.size())), ratio);
        print_box_line(l1, INNER_WIDTH);
        std::string l2 = std::format("   [-] Filtro Checksum BIP-39  : {:>10} chaves   [100% válidas - SHA-NI]",
                                     format_num(static_cast<double>(opt.valid_pairs.size())));
        print_box_line(l2, INNER_WIDTH);
    } else if (opt.has_streaming_pruning) {
        std::string l1 = std::format("   [-] OTM-03 (Poda em F₂ᶜ - K={}): {:>8} chaves   [Redução: {:>5.1f}x]",
                                     opt.unknown_positions.size(), format_num(opt.valid_combinations), ratio);
        print_box_line(l1, INNER_WIDTH);
        std::string l2 = std::format("   [-] Filtro Checksum BIP-39  : {:>10} chaves   [100% válidas - Stream]",
                                     format_num(opt.valid_combinations));
        print_box_line(l2, INNER_WIDTH);
    } else if (opt.direct_valid_wheels) {
        std::string l1 = std::format("   [-] OTM-01 (Dedução Reversa): {:>10} chaves   [Redução: {:>5.1f}x]",
                                     format_num(opt.total_combinations), ratio);
        print_box_line(l1, INNER_WIDTH);
        std::string l2 = std::format("   [-] Filtro Checksum BIP-39  : {:>10} chaves   [100% válidas - Bypass]",
                                     format_num(opt.valid_combinations));
        print_box_line(l2, INNER_WIDTH);
    } else if (opt.auto_deduce_last_word) {
        std::string l1 = std::format("   [-] Dedução Reversa Checksum: {:>10} chaves   [Redução: {:>5.1f}x]",
                                     format_num(opt.total_combinations), ratio);
        print_box_line(l1, INNER_WIDTH);
        std::string l2 = std::format("   [-] Filtro Checksum BIP-39  : {:>10} chaves   [100% válidas - Síntese]",
                                     format_num(opt.valid_combinations));
        print_box_line(l2, INNER_WIDTH);
    } else if (cfg.only_valids) {
        std::string l1 = std::format("   [-] Filtro Checksum BIP-39  : {:>10} chaves   [Redução: {:>5.1f}x]",
                                     format_num(opt.valid_combinations), ratio);
        print_box_line(l1, INNER_WIDTH);
    }

    if (!opt.slices.empty()) {
        std::string l3 = std::format("   [-] OTM-09 (Fatiamento Mem) : {:>10} fatias   [Prefixo: {:>3}B em L1]",
                                     opt.slices.size(), opt.slice0_static_len);
        print_box_line(l3, INNER_WIDTH);
    }

    std::string l_salt = std::format("   [-] OTM-15 (Salt Pré-comp)  : {:>10}          [Zero cópias no loop]", "Ativo");
    print_box_line(l_salt, INNER_WIDTH);

    std::string l_ff = std::format("   [-] OTM-23 (PBKDF2 Fast-Fwd): {:>10}          [Colapso Round 1 HMAC]", "Ativo");
    print_box_line(l_ff, INNER_WIDTH);

    std::string l_pin = std::format("   [-] OTM-16 (Core Pinning)   : {:>10}          [Afinidade Física CPU]", "Ativo");
    print_box_line(l_pin, INNER_WIDTH);

    if (opt.has_hamming_gradient) {
        std::string l_hg = std::format("   [-] OTM-29 (Gradiente Hamming): {:>10}          [Varredura por Entropia]", "Ativo");
        print_box_line(l_hg, INNER_WIDTH);
    }
    if (opt.has_frequency) {
        std::string l_fq = std::format("   [-] Heurística de Frequência  : {:>10}          [Lei de Zipf Ponderada]", "Ativo");
        print_box_line(l_fq, INNER_WIDTH);
    }
    if (opt.has_typo) {
        std::string l_tp = std::format("   [-] Autômatos de Levenshtein  : {:>10}          [Aproximação de Typos]", "Ativo");
        print_box_line(l_tp, INNER_WIDTH);
    }
    if (opt.has_midstate_caching) {
        std::string l_mc = std::format("   [-] OTM-18 (Mid-State Caching): {:>10}          [Congela Rodadas SHA-NI]", "Ativo");
        print_box_line(l_mc, INNER_WIDTH);
    }
    if (opt.has_distinct_pruning) {
        size_t per_wheel = opt.wheels.empty() ? 0 : (opt.distinct_pruned_words / opt.wheels.size());
        std::string l_dist = std::format("   [-] Restrição Não-Repetição : {:>10}          [Poda: -{} palavras/roda]", "Ativo", per_wheel);
        print_box_line(l_dist, INNER_WIDTH);
    }
    if (opt.has_cascade_deduction) {
        std::string l_casc = std::format("   [-] Dedução Cascata (w_N-1) : {:>10}          [Poda Analítica: {:>3.0f}x]", "Ativo", ratio);
        print_box_line(l_casc, INNER_WIDTH);
    }
    if (opt.has_gray_code) {
        std::string l_gray = std::format("   [-] Agendador Gray-Code     : {:>10}          [Localidade L1 (Hamming=1)]", "Ativo");
        print_box_line(l_gray, INNER_WIDTH);
    }
    if (opt.has_beam_search) {
        std::string l_beam = std::format("   [-] Beam Search / A*        : {:>10}          [Feixes Probabilísticos]", "Ativo");
        print_box_line(l_beam, INNER_WIDTH);
    }
    std::string l_inv = std::format("   [-] OTM-11 (Inversão de Eixos): {:>10}          [Localidade Máxima L1]", "Ativo");
    print_box_line(l_inv, INNER_WIDTH);

    if (opt.has_target) {
        std::string l4 = std::format("   [-] Rejeição Precoce C1     : Token 0x{:08x}   [Filtra 99.999% secp256k1]",
                                     opt.target_fast_hash);
        print_box_line(l4, INNER_WIDTH);
    }

    print_box_bottom(INNER_WIDTH);
    std::print("\n");
}
