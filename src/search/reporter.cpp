#include "../../include/search/reporter.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <format>
#include <gmpxx.h>
#include <map>
#include <print>
#include <string>
#include <vector>

#include "../../include/cli/ui.hpp"

using namespace cryptowords::ui;
using namespace cryptowords;

namespace {

const char* mode_label(SearchMode m) {
    switch (m) {
        case SearchMode::Mixed:     return "Mixed (mixed-radix)";
        case SearchMode::Streaming: return "Streaming (outer + cascade)";
        case SearchMode::Pairs:     return "Pairs";
        case SearchMode::Triplets:  return "Triplets";
    }
    return "?";
}

const char* checksum_mode_label(ChecksumMode m) {
    switch (m) {
        case ChecksumMode::None:        return "desativado";
        case ChecksumMode::Expected:    return "checksum fixo (última palavra conhecida)";
        case ChecksumMode::AutoDeduce:  return "síntese por cascade";
        case ChecksumMode::UserPattern: return "--checksum";
        case ChecksumMode::SelfVerify:  return "auto-verificação (K=1)";
    }
    return "?";
}

std::string strategy_name(SearchStrategy mask, const AppConfig& cfg) {
    if (mask == SearchStrategy::Default || mask == SearchStrategy::None)
        return "Padrão (Filtros em F₂ᶜ)";

    std::vector<std::string> names;
    if (has_bit(mask, SearchStrategy::HammingGrad)) names.push_back("Gradiente de Hamming");
    if (has_bit(mask, SearchStrategy::Frequency))   names.push_back("Frequência (Zipf)");
    if (has_bit(mask, SearchStrategy::Typo))
        names.push_back(std::format("Levenshtein (dist≤{})", cfg.max_distance));

    if (names.size() == 1) return names[0];
    std::string s = "Combinada (";
    for (size_t i = 0; i < names.size(); ++i) {
        s += names[i];
        if (i + 1 < names.size()) s += " + ";
    }
    s += ")";
    return s;
}

}  // namespace

void SearchReporter::print_plan(const OptimizedMnemonics& opt, const AppConfig& cfg) {
    if (cfg.quiet) return;

    const size_t n_words    = opt.base_mnemonic.size();
    const size_t n_unknown  = opt.unknown_positions.size();
    const size_t W = DEFAULT_INNER_WIDTH;

    std::print("\n");
    print_box_top("AFUNILAMENTO COMBINATÓRIO & PLANO DE BUSCA", W);

    print_box_line(std::format("\033[1;37mFrase ({} palavras, {} incógnita{}):\033[0m",
                               n_words, n_unknown, (n_unknown == 1 ? "" : "s")),
                   W);

    std::string line;
    size_t line_vis = 0;
    for (size_t i = 0; i < n_words; ++i) {
        std::string tok;
        size_t tok_vis = 0;
        if (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD) {
            tok = cfg.wordlist[opt.base_mnemonic[i]];
            tok_vis = tok.size();
        } else {
            tok = std::format("\033[1;93m[?#{:02d}]\033[0m", i + 1);
            tok_vis = 7;
        }
        if (line_vis + tok_vis + (line_vis > 0 ? 2 : 0) > W) {
            print_box_line(line, W);
            line.clear();
            line_vis = 0;
        }
        if (line_vis > 0) { line += "  "; line_vis += 2; }
        line += tok;
        line_vis += tok_vis;
    }
    if (!line.empty()) print_box_line(line, W);

    print_box_separator(W);

    const std::string coin_str = (cfg.coin == CoinTarget::BTC) ? "Bitcoin (BTC)"
                                                               : "Ethereum (ETH)";
    const std::string pass_str = cfg.passphrase.empty()
                                     ? "(nenhuma)"
                                     : std::format("\"{}\"", cfg.passphrase);
    print_box_line(std::format("Moeda: {:<14} │ Threads: {:<2}  │ Rounds: {:<5} │ Senha: {:<12}",
                               coin_str, cfg.num_threads, cfg.pbkdf2_rounds, pass_str),
                   W);

    print_box_line(std::format("Estratégia  : \033[1;36m{}\033[0m",
                               strategy_name(cfg.strategy_mask, cfg)),
                   W);

    print_box_line(std::format("Enumeração  : \033[1;36m{}\033[0m",
                               mode_label(opt.mode)),
                   W);

    print_box_line(std::format("Checksum    : \033[1;36m{}\033[0m",
                               checksum_mode_label(opt.checksum_mode)),
                   W);

    if (opt.has_checksum_filter && !opt.checksum_repr.empty()) {
        print_box_line(std::format("--checksum  : \033[1;33m{}\033[0m",
                                   opt.checksum_repr),
                       W);
    }

    if (!cfg.repeat_ids.empty()) {
        std::string rep;
        for (size_t i = 0; i < cfg.repeat_ids.size(); ++i) {
            if (i > 0) rep += ", ";
            rep += std::format("\033[1;33m{}\033[0m\033[90m×\033[0m{}",
                               cfg.wordlist[cfg.repeat_ids[i].first],
                               static_cast<int>(cfg.repeat_ids[i].second));
        }
        print_box_line(std::format("--repeat    : {}", rep), W);
    }

    if (!cfg.target.empty()) {
        print_box_line(std::format(
            "Alvo        : \033[1;32m{:<34}\033[0m \033[90m(Token C1: 0x{:08x})\033[0m",
            cfg.target, opt.target_fast_hash),
            W);
    }

    print_box_separator(W);

    // --- Funil de contagem ---
    {
        const double pow_2048_k = (opt.raw_unknowns > 0)
                                      ? std::pow(2048.0, static_cast<double>(opt.raw_unknowns))
                                      : 1.0;

        if (opt.raw_unknowns > 0) {
            print_box_line(std::format(
                "   \033[90mEspaço Bruto (2048^{})\033[0m  : \033[90m{}\033[0m",
                opt.raw_unknowns, format_num(opt.exact_math_raw)),
                W);
        }

        if (opt.exact_math_post_wheel < opt.exact_math_raw) {
            const double r = (opt.math_combinations_raw > 0.0)
                                 ? (pow_2048_k / opt.math_combinations_raw) : 1.0;
            print_box_line(std::format(
                "   \033[36mApós --allow/--allow-all\033[0m  : \033[36m{}\033[0m   "
                "\033[33m[↓ {}x]\033[0m",
                format_num(opt.exact_math_post_wheel), format_ratio(r)),
                W);
        }

        if (opt.exact_math_post_distinct < opt.exact_math_post_wheel) {
            const double r = (opt.exact_math_post_distinct != 0)
                                 ? (opt.exact_math_post_wheel.get_d() /
                                    opt.exact_math_post_distinct.get_d()) : 1.0;
            print_box_line(std::format(
                "   \033[36mApós --distinct\033[0m            : \033[36m{}\033[0m   "
                "\033[33m[↓ {}x]\033[0m",
                format_num(opt.exact_math_post_distinct), format_ratio(r)),
                W);
        }

        if (opt.exact_math_post_repeat < opt.exact_math_post_distinct) {
            const double r = (opt.exact_math_post_repeat != 0)
                                 ? (opt.exact_math_post_distinct.get_d() /
                                    opt.exact_math_post_repeat.get_d()) : 1.0;
            print_box_line(std::format(
                "   \033[1;36mApós --repeat\033[0m              : \033[1;36m{}\033[0m   "
                "\033[1;33m[↓ {}x]\033[0m",
                format_num(opt.exact_math_post_repeat), format_ratio(r)),
                W);
        }

        if (opt.has_checksum_filter &&
            opt.exact_math_post_checksum < opt.exact_math_post_repeat) {
            const double r = (opt.exact_math_post_checksum != 0)
                                 ? (opt.exact_math_post_repeat.get_d() /
                                    opt.exact_math_post_checksum.get_d()) : 1.0;
            print_box_line(std::format(
                "   \033[1;36mApós --checksum\033[0m            : \033[1;36m{}\033[0m   "
                "\033[1;33m[↓ {}x]\033[0m",
                format_num(opt.exact_math_post_checksum), format_ratio(r)),
                W);
        }

        const size_t cs_div = size_t{1} << opt.checksum_bits;
        if (cs_div > 1 &&
            opt.checksum_mode != ChecksumMode::None &&
            !opt.has_checksum_filter &&
            opt.exact_math_valid < opt.exact_math_post_repeat) {
            print_box_line(std::format(
                "   \033[35mApós checksum BIP-39 (÷{})\033[0m  : \033[35m{}\033[0m",
                cs_div, format_num(opt.exact_math_valid)),
                W);
        }

        const double total_ratio = (opt.exact_math_total > 0 && opt.raw_unknowns > 0)
                                       ? (pow_2048_k / opt.exact_math_total.get_d()) : 1.0;
        print_box_line(std::format(
            "   \033[1;32m➔ Chaves Efetivas PBKDF2\033[0m   : \033[1;32m{}\033[0m   "
            "\033[1;33m[↓ {}x TOTAL]\033[0m",
            format_num(opt.exact_math_total), format_ratio(total_ratio)),
            W);
    }

    print_box_separator(W);
    print_box_line("\033[1;36mOTIMIZAÇÕES ATIVAS:\033[0m", W);

    // Filtros de checksum
    if (opt.checksum_mode == ChecksumMode::UserPattern) {
        const size_t popcount = opt.allowed_checksum_bits.count();
        const size_t total    = size_t{1} << opt.checksum_bits;
        print_box_line(std::format(
            "   [-] Filtro --checksum        : {}/{} valores aceitos por padrão",
            popcount, total),
            W);
    }
    if (opt.has_cascade_deduction) {
        print_box_line("   [-] Dedução cascata (última): ativa — síntese via SHA-256",
                       W);
    }
    if (opt.checksum_mode == ChecksumMode::Expected) {
        print_box_line(std::format(
            "   [-] Checksum esperado        : 0x{:x}",
            static_cast<unsigned>(opt.expected_checksum)),
            W);
    }

    // Montagem e pré-computação
    if (opt.phrase_n_segments > 0) {
        print_box_line(std::format(
            "   [-] Montagem da frase        : {} segmentos pré-computados",
            opt.phrase_n_segments),
            W);
    }
    print_box_line("   [-] Salt pré-computado       : ativo", W);
    print_box_line("   [-] Fast-forward round 1     : ativo (PBKDF2)", W);

    // Estratégias de reorder
    if (opt.has_hamming_gradient)
        print_box_line("   [-] Gradiente de Hamming     : ativo", W);
    if (opt.has_frequency)
        print_box_line("   [-] Frequência linguística   : ativo (Zipf)", W);
    if (opt.has_typo)
        print_box_line("   [-] Autômatos de Levenshtein : ativo", W);

    // Constraints combinatórias
    if (opt.is_distinct && opt.has_distinct_pruning)
        print_box_line("   [-] Restrição não-repetição  : ativa", W);
    if (!cfg.repeat_ids.empty()) {
        size_t sum = 0;
        for (auto [_, n] : cfg.repeat_ids) sum += n;
        print_box_line(std::format(
            "   [-] Restrição --repeat       : ativa ({} exigência(s), Σ N={})",
            cfg.repeat_ids.size(), sum),
            W);
    }
    if (opt.has_gray_code)
        print_box_line("   [-] Agendador Gray-code      : ativo", W);

    print_box_bottom(W);
    std::print("\n");
    std::fflush(stdout);
}
