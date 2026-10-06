#include "../../include/search/optimizer.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <bitset>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gmpxx.h>
#include <initializer_list>
#include <numeric>
#include <print>
#include <utility>

#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include "../../include/search/plan.hpp"

using namespace cryptowords;

// =========================================================================
// FASE 3 — Otimização da busca.
//
// Transforma AppConfig em OptimizedMnemonics. As operações são puramente
// estruturais: construir wheels, aplicar --distinct/--repeat, montar a
// frase e escolher o modo de enumeração/filtro. Nenhuma filtragem por
// correção acontece aqui — isso é trabalho do runtime (fase 4).
// =========================================================================

namespace {

constexpr size_t COUNT_EXACT_MAX_K = 16;

// Itera todos os subconjuntos de S com cardinalidade em [lo, hi].
template <typename F>
void for_each_subset(uint32_t S, int lo, int hi, F&& fn) {
    if (lo < 0) lo = 0;
    if (lo == 0 && hi == 0) { fn(0u); return; }
    if (lo == 1 && hi == 1) {
        uint32_t bits = S;
        while (bits) {
            const uint32_t b = bits & (~bits + 1u);
            bits ^= b;
            fn(b);
        }
        return;
    }
    if (lo == 0) {
        fn(0u);
        uint32_t sub = S;
        while (sub) {
            if (__builtin_popcount(sub) <= hi) fn(sub);
            sub = (sub - 1) & S;
        }
        return;
    }
    if (lo == hi) {
        const int n = lo;
        if (n > __builtin_popcount(S)) return;
        uint32_t sub = (1u << n) - 1;
        if (sub > S) return;
        while (true) {
            fn(sub);
            const uint32_t u = sub & (~sub + 1u);
            const uint32_t v = sub + u;
            if (v == 0) break;
            sub = v | (((sub ^ v) >> 2) / u);
            if (sub > S) break;
        }
        return;
    }
    uint32_t sub = S;
    while (true) {
        const int pc = __builtin_popcount(sub);
        if (pc >= lo && pc <= hi) fn(sub);
        if (sub == 0) break;
        sub = (sub - 1) & S;
    }
}

// DP de contagem exata por cardinalidade (K ≤ 16).
template <typename Wheels>
mpz_class count_exact(const Wheels& wheels,
                      const std::array<uint8_t, 2048>& min_count,
                      const std::array<uint8_t, 2048>& max_count,
                      size_t wordlist_size) {
    const size_t K = wheels.size();
    if (K == 0) return mpz_class(1);
    if (K > COUNT_EXACT_MAX_K) return mpz_class(0);

    std::vector<uint32_t> word_pos_mask(wordlist_size, 0);
    for (size_t i = 0; i < K; ++i)
        for (uint16_t w : wheels[i])
            if (w < wordlist_size) word_pos_mask[w] |= (1u << i);

    const uint32_t full = (1u << K) - 1;
    std::vector<mpz_class> dp(1u << K, 0), ndp(1u << K, 0);
    dp[0] = 1;

    for (size_t w = 0; w < wordlist_size; ++w) {
        const uint32_t pm = word_pos_mask[w];
        const uint8_t lo_raw = min_count[w];
        const uint8_t hi_raw = max_count[w];
        if (lo_raw == 0 && (pm == 0 || hi_raw == 0)) continue;
        if (pm == 0 && lo_raw > 0) return 0;

        const int lo = lo_raw;
        const int hi = std::min<int>(hi_raw, static_cast<int>(K));

        std::fill(ndp.begin(), ndp.end(), mpz_class(0));
        for (uint32_t mask = 0; mask <= full; ++mask) {
            const mpz_class& v = dp[mask];
            if (v == 0) continue;
            if (lo == 0) ndp[mask] += v;
            const uint32_t free_bits = pm & ~mask;
            if (free_bits == 0) continue;
            for_each_subset(free_bits, lo, hi, [&](uint32_t sub) {
                if (sub == 0) return;
                ndp[mask | sub] += v;
            });
        }
        dp.swap(ndp);
    }
    return dp[full];
}

}  // namespace

namespace cryptowords {
namespace {

// -----------------------------------------------------------------------------
// 3.1  Construção dos wheels a partir de --mnemonics/--allow/--allow-all.
// -----------------------------------------------------------------------------
void init_wheels(const AppConfig& cfg, OptimizedMnemonics& opt) {
    static const std::vector<uint16_t> full = [] {
        std::vector<uint16_t> w(2048);
        std::iota(w.begin(), w.end(), static_cast<uint16_t>(0));
        return w;
    }();

    const size_t n = cfg.mnemonics.size();
    for (size_t i = 0; i < n; ++i) {
        if (std::holds_alternative<uint16_t>(cfg.mnemonics[i])) {
            const uint16_t id = std::get<uint16_t>(cfg.mnemonics[i]);
            opt.base_mnemonic[i] = id;
            if (id == AppConfig::UNKNOWN_WORD) {
                opt.unknown_positions.push_back(i);
                Wheel wheel;
                wheel.words = full;
                wheel.rebuild_mask();
                opt.wheels.push_back(std::move(wheel));
            }
        } else {
            opt.base_mnemonic[i] = AppConfig::UNKNOWN_WORD;
            opt.unknown_positions.push_back(i);
            Wheel wheel;
            wheel.words = std::get<std::vector<uint16_t>>(cfg.mnemonics[i]);
            std::ranges::sort(wheel.words);
            wheel.rebuild_mask();
            opt.wheels.push_back(std::move(wheel));
        }
    }
}

// -----------------------------------------------------------------------------
// 3.2  --distinct: remove palavras já fixas em outras posições.
// -----------------------------------------------------------------------------
void apply_distinct(const AppConfig& cfg, OptimizedMnemonics& opt) {
    opt.is_distinct = cfg.distinct;
    if (!cfg.distinct) return;

    std::bitset<2048> fixed;
    for (uint16_t id : opt.base_mnemonic)
        if (id != AppConfig::UNKNOWN_WORD) fixed.set(id);

    size_t pruned = 0;
    for (auto& w : opt.wheels) {
        const size_t removed = std::erase_if(w.words,
            [&](uint16_t id) { return fixed.test(id); });
        if (removed > 0) w.rebuild_mask();
        pruned += removed;
    }
    if (pruned > 0) opt.has_distinct_pruning = true;
}

// -----------------------------------------------------------------------------
// 3.3  Contagens do funil bruto → pós-wheels → pós-distinct.
// -----------------------------------------------------------------------------
void count_raw_wheel_distinct(const AppConfig& cfg, OptimizedMnemonics& opt) {
    {
        mpz_class raw = 1;
        mpz_class base = 2048;
        mpz_pow_ui(raw.get_mpz_t(), base.get_mpz_t(),
                   static_cast<unsigned long>(opt.raw_unknowns));
        opt.exact_math_raw = raw;
    }
    {
        mpz_class prod = 1;
        for (const auto& w : opt.wheels) prod *= mpz_class(static_cast<unsigned long>(w.size()));
        opt.exact_math_post_wheel = prod;
        opt.math_combinations_raw = prod.get_d();
    }

    const size_t K = opt.wheels.size();
    if (!cfg.distinct) {
        opt.exact_math_post_distinct = opt.exact_math_post_wheel;
    } else if (K == 0) {
        opt.exact_math_post_distinct = 1;
    } else if (K > COUNT_EXACT_MAX_K) {
        bool all_equal = true;
        for (size_t i = 1; i < K && all_equal; ++i)
            if (opt.wheels[i].words != opt.wheels[0].words) all_equal = false;
        if (all_equal) {
            mpz_class s(static_cast<unsigned long>(opt.wheels[0].size()));
            mpz_class ff = 1;
            for (size_t i = 0; i < K; ++i) ff *= (s - i);
            opt.exact_math_post_distinct = ff;
        } else {
            opt.exact_math_post_distinct = opt.exact_math_post_wheel;
        }
    } else {
        std::array<uint8_t, 2048> min_d{}, max_d{};
        for (size_t w = 0; w < 2048; ++w) max_d[w] = 1;
        opt.exact_math_post_distinct =
            count_exact(opt.wheels, min_d, max_d, cfg.wordlist.size());
    }
}

// -----------------------------------------------------------------------------
// 3.4  --repeat: palavras obrigatórias + min/max por palavra.
// -----------------------------------------------------------------------------
void apply_repeat(const AppConfig& cfg, OptimizedMnemonics& opt) {
    std::array<size_t, 2048> fixed_count{};
    for (uint16_t id : opt.base_mnemonic)
        if (id != AppConfig::UNKNOWN_WORD) ++fixed_count[id];

    for (auto [id, n] : cfg.repeat_ids) {
        if (n == 0) continue;
        const size_t already = fixed_count[id];
        if (already > static_cast<size_t>(n)) { opt.impossible = true; return; }
        const size_t remaining = static_cast<size_t>(n) - already;
        if (remaining == 0) continue;
        for (auto& w : opt.wheels)
            if (!w.contains(id)) w.push_back(id);
        opt.repeat_ids_exact.emplace_back(id, static_cast<uint8_t>(remaining));
    }
    opt.repeat_ids_empty_ = opt.repeat_ids_exact.empty();

    const size_t K = opt.wheels.size();
    opt.min_count.fill(0);
    opt.max_count.fill(cfg.distinct ? uint8_t{1} : static_cast<uint8_t>(K));
    for (auto [id, n] : opt.repeat_ids_exact) {
        opt.min_count[id] = n;
        opt.max_count[id] = n;
    }
}

void count_post_repeat(const AppConfig& cfg, OptimizedMnemonics& opt) {
    if (opt.repeat_ids_empty_) {
        opt.exact_math_post_repeat = opt.exact_math_post_distinct;
        return;
    }
    const size_t K = opt.wheels.size();
    if (K == 0) { opt.exact_math_post_repeat = 1; return; }
    if (K > COUNT_EXACT_MAX_K) {
        opt.exact_math_post_repeat = opt.exact_math_post_wheel;
        return;
    }
    const mpz_class exact = count_exact(opt.wheels, opt.min_count, opt.max_count,
                                        cfg.wordlist.size());
    if (exact == 0) { opt.impossible = true; opt.exact_math_post_repeat = 0; }
    else opt.exact_math_post_repeat = exact;
}

// -----------------------------------------------------------------------------
// 3.5  Frase pré-computada (PhraseSegment), wordlist SoA.
// -----------------------------------------------------------------------------
void build_phrase_layout(const AppConfig& cfg, OptimizedMnemonics& opt) {
    const size_t n = opt.base_mnemonic.size();

    struct Run { bool is_var; uint16_t val; };
    std::vector<Run> runs;
    runs.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        if (opt.base_mnemonic[i] == AppConfig::UNKNOWN_WORD) runs.push_back({true, (uint16_t)i});
        else                                                  runs.push_back({false, opt.base_mnemonic[i]});
    }

    std::vector<PhraseSegment> segs;
    std::string sbuf;
    sbuf.reserve(256);

    size_t ri = 0;
    std::string prefix;
    while (ri < runs.size() && !runs[ri].is_var) {
        if (!prefix.empty()) prefix += cfg.separator;
        prefix += cfg.wordlist[runs[ri].val];
        ++ri;
    }
    if (!prefix.empty() && ri < runs.size()) prefix += cfg.separator;

    if (!prefix.empty()) {
        PhraseSegment seg{};
        seg.word_idx   = 0xFFFF;
        seg.static_off = static_cast<uint16_t>(sbuf.size());
        seg.static_len = static_cast<uint16_t>(prefix.size());
        sbuf += prefix;
        segs.push_back(seg);
    }

    while (ri < runs.size()) {
        if (!runs[ri].is_var) { ++ri; continue; }
        PhraseSegment seg{};
        seg.word_idx = runs[ri].val;
        ++ri;
        std::string statics;
        while (ri < runs.size() && !runs[ri].is_var) {
            statics += cfg.separator;
            statics += cfg.wordlist[runs[ri].val];
            ++ri;
        }
        if (ri < runs.size()) statics += cfg.separator;
        seg.static_off = static_cast<uint16_t>(sbuf.size());
        seg.static_len = static_cast<uint16_t>(statics.size());
        sbuf += statics;
        segs.push_back(seg);
    }

    opt.phrase_segments   = std::move(segs);
    opt.phrase_static     = std::move(sbuf);
    opt.phrase_n_segments = opt.phrase_segments.size();
}

void build_word_soa(const AppConfig& cfg, OptimizedMnemonics& opt) {
    opt.word_buf.fill({});
    opt.word_len16.fill(0);
    const size_t n = std::min(cfg.wordlist.size(), OptimizedMnemonics::WORDLIST_SIZE);
    for (size_t i = 0; i < n; ++i) {
        const std::string& w = cfg.wordlist[i];
        const size_t len = std::min(w.size(), OptimizedMnemonics::WORD_SLOT_BYTES);
        std::memcpy(opt.word_buf[i].data(), w.data(), len);
        opt.word_len16[i] = static_cast<uint16_t>(len);
    }
}

// -----------------------------------------------------------------------------
// 3.6  Bloco base SHA-256 (mid-state) + offsets das incógnitas.
// -----------------------------------------------------------------------------
void build_base_block(OptimizedMnemonics& opt) {
    const size_t n = opt.base_mnemonic.size();
    const size_t entropy_bytes = opt.entropy_bytes;

    uint64_t acc = 0; size_t bits = 0; size_t b_pos = 0;
    for (size_t i = 0; i < n; ++i) {
        const uint16_t word = (opt.base_mnemonic[i] == AppConfig::UNKNOWN_WORD)
                                  ? 0 : (opt.base_mnemonic[i] & 0x7FF);
        acc = (acc << 11) | uint64_t(word);
        bits += 11;
        while (bits >= 8 && b_pos < entropy_bytes) {
            bits -= 8;
            opt.base_block64[b_pos++] = static_cast<uint8_t>((acc >> bits) & 0xFF);
        }
        acc &= uint64_t((1ULL << bits) - 1);
    }
    opt.base_block64[entropy_bytes] = 0x80;
    const uint64_t bit_len_be = __builtin_bswap64(opt.entropy_bits);
    std::memcpy(opt.base_block64.data() + 56, &bit_len_be, 8);

    opt.unknown_bit_offsets.clear();
    opt.unknown_bit_offsets.reserve(opt.unknown_positions.size());
    for (size_t u : opt.unknown_positions) opt.unknown_bit_offsets.push_back(u * 11);

    if (opt.base_mnemonic[n - 1] != AppConfig::UNKNOWN_WORD) {
        opt.expected_checksum = static_cast<uint8_t>(
            opt.base_mnemonic[n - 1] & ((1u << opt.checksum_bits) - 1));
    }
}

// -----------------------------------------------------------------------------
// 3.7  Entropy trick — substitui o wheel da última incógnita por {e << C}.
//
// Bijetivo com palavras BIP-39 válidas: só descarta valores que reprovariam
// o checksum. Preserva a lista original em allowed_last_words para o filtro
// AutoDeduce runtime.
// -----------------------------------------------------------------------------
void apply_entropy_trick(OptimizedMnemonics& opt) {
    const size_t K = opt.unknown_positions.size();
    const size_t last_pos = opt.base_mnemonic.size() - 1;

    size_t idx = K;
    for (size_t i = 0; i < K; ++i)
        if (opt.unknown_positions[i] == last_pos) { idx = i; break; }
    if (idx >= K) return;

    for (uint16_t w : opt.wheels[idx]) opt.allowed_last_words.set(w);

    const size_t ebits = 11 - opt.checksum_bits;
    const size_t count = size_t{1} << ebits;
    auto& wheel = opt.wheels[idx];
    wheel.words.clear();
    wheel.words.reserve(count);
    wheel.mask.fill(0);
    for (size_t e = 0; e < count; ++e)
        wheel.push_back(static_cast<uint16_t>(e << opt.checksum_bits));

    opt.has_cascade_deduction = true;
}

// Reorder por tamanho crescente. Wheels menores primeiro: em mixed-radix,
// o wheel no índice 0 muda mais devagar, então wheels pequenos no "slow
// path" e wheels grandes no "fast path" (menos carry propagation).
//
// Quando has_cascade_deduction está ativo, a última incógnita é preservada
// intacta: seu wheel é o de síntese {e<<C}, e unknown_positions.back()
// precisa continuar apontando para ela.
void reorder_by_size(OptimizedMnemonics& opt) {
    const size_t K = opt.wheels.size();
    if (K <= 1) return;

    const bool preserve_last = opt.has_cascade_deduction;
    const size_t n = preserve_last ? (K - 1) : K;
    if (n <= 1) return;

    std::array<size_t, 32> order{};
    std::iota(order.begin(), order.begin() + n, 0);
    std::stable_sort(order.begin(), order.begin() + n, [&](size_t a, size_t b) {
        return opt.wheels[a].size() < opt.wheels[b].size();
    });

    bool sorted = true;
    for (size_t i = 0; i < n; ++i) if (order[i] != i) { sorted = false; break; }
    if (sorted) return;

    auto permute = [&]<typename T>(std::vector<T>& v) {
        std::vector<T> tmp(v.size());
        for (size_t i = 0; i < n; ++i) tmp[i] = std::move(v[order[i]]);
        for (size_t i = n; i < v.size(); ++i) tmp[i] = std::move(v[i]);
        v = std::move(tmp);
    };

    permute(opt.unknown_positions);
    permute(opt.wheels);
    permute(opt.unknown_bit_offsets);
    if (!opt.original_wheels.empty()) permute(opt.original_wheels);
}

// -----------------------------------------------------------------------------
// 3.9  Estratégias de reorder por heurística (Hamming / frequência / typo).
// -----------------------------------------------------------------------------
void apply_strategy_reorder(const AppConfig& cfg, OptimizedMnemonics& opt) {
    if (!opt.has_hamming_gradient && !opt.has_frequency && !opt.has_typo) return;

    const size_t n = opt.base_mnemonic.size();

    auto score_of = [&](size_t u_pos, uint16_t w) -> double {
        double score = 0.0;
        std::string ref;
        if (opt.has_typo) {
            if (u_pos > 0 && opt.base_mnemonic[u_pos - 1] != AppConfig::UNKNOWN_WORD)
                ref = cfg.wordlist[opt.base_mnemonic[u_pos - 1]];
            else if (u_pos + 1 < n && opt.base_mnemonic[u_pos + 1] != AppConfig::UNKNOWN_WORD)
                ref = cfg.wordlist[opt.base_mnemonic[u_pos + 1]];
        }
        if (opt.has_hamming_gradient) {
            int h = 0;
            const int pc = std::popcount(static_cast<unsigned int>(w & 0x7FF));
            h += std::abs(2 * pc - 11);
            const uint16_t transitions = (w ^ (w >> 1)) & 0x3FF;
            h += std::abs(static_cast<int>(std::popcount(
                static_cast<unsigned int>(transitions))) - 5);
            if (u_pos > 0 && opt.base_mnemonic[u_pos - 1] != AppConfig::UNKNOWN_WORD) {
                const uint16_t prev = opt.base_mnemonic[u_pos - 1];
                const size_t bit_pos = (u_pos * 11) % 8;
                const uint8_t cross = static_cast<uint8_t>(
                    ((prev << (8 - bit_pos)) | (w >> (11 - (8 - bit_pos)))) & 0xFF);
                h += std::abs(static_cast<int>(std::popcount(
                    static_cast<unsigned int>(cross))) - 4);
            }
            score += static_cast<double>(h) * 10.0;
        }
        if (opt.has_frequency) score += static_cast<double>(cfg.wordlist[w].size()) * 2.0;
        if (opt.has_typo && !ref.empty()) {
            const auto& cand = cfg.wordlist[w];
            int match = 0;
            for (char c : cand) if (ref.find(c) != std::string::npos) ++match;
            score -= static_cast<double>(match) * 5.0;
        }
        return score;
    };

    for (size_t k = 0; k < opt.wheels.size(); ++k) {
        auto& wheel = opt.wheels[k].words;
        std::vector<std::pair<double, uint16_t>> scored;
        scored.reserve(wheel.size());
        for (uint16_t w : wheel)
            scored.emplace_back(score_of(opt.unknown_positions[k], w), w);
        std::stable_sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first < b.first;
            return a.second < b.second;
        });
        for (size_t j = 0; j < wheel.size(); ++j) wheel[j] = scored[j].second;
    }
}

// -----------------------------------------------------------------------------
// 3.10  --repeat: move palavras obrigatórias para o início de cada wheel.
// -----------------------------------------------------------------------------
void reorder_for_repeat(OptimizedMnemonics& opt) {
    if (opt.repeat_ids_empty_ || opt.impossible) return;

    const size_t R = opt.repeat_ids_exact.size();
    const size_t M = opt.is_streaming() ? (opt.unknown_positions.size() - 1)
                                        : opt.wheels.size();
    const size_t n = std::min(R, M);

    for (size_t k = 0; k < n; ++k) {
        const uint16_t id = opt.repeat_ids_exact[k].first;
        auto& w = opt.wheels[k].words;
        auto it = std::find(w.begin(), w.end(), id);
        if (it != w.end() && it != w.begin()) std::rotate(w.begin(), it, it + 1);
    }
}

// -----------------------------------------------------------------------------
// 3.11  Funil final (contagens efetivas) e alvo.
// -----------------------------------------------------------------------------
void finalize_spaces(const AppConfig& cfg, OptimizedMnemonics& opt,
                     bool entropy_trick_applied) {
    mpz_class cs_div = 1;
    mpz_mul_2exp(cs_div.get_mpz_t(), cs_div.get_mpz_t(),
                 static_cast<unsigned long>(opt.checksum_bits));

    // Post --checksum: assume distribuição uniforme sobre os 2^C valores.
    if (cfg.has_checksum_filter) {
        const size_t total_cs = size_t{1} << opt.checksum_bits;
        const size_t allowed = opt.allowed_checksum_bits.count();
        mpz_class r_total(static_cast<unsigned long>(total_cs));
        mpz_class r_allowed(static_cast<unsigned long>(allowed > 0 ? allowed : 1));
        opt.exact_math_post_checksum = (opt.exact_math_post_repeat * r_allowed) / r_total;
        if (opt.exact_math_post_checksum == 0 && opt.exact_math_post_repeat > 0)
            opt.exact_math_post_checksum = 1;
    } else {
        opt.exact_math_post_checksum = opt.exact_math_post_repeat;
    }

    // Enumeração: o que o odômetro itera. Sem trick = espaço total; com
    // trick = espaço já reduzido por 2^C.
    if (entropy_trick_applied && !cfg.has_checksum_filter) {
        opt.exact_math_total = opt.exact_math_post_repeat / cs_div;
    } else if (cfg.has_checksum_filter) {
        opt.exact_math_total = opt.exact_math_post_checksum;
    } else {
        opt.exact_math_total = opt.exact_math_post_repeat;
    }

    // Chaves efetivamente entregues ao PBKDF2.
    if (cfg.has_checksum_filter) {
        opt.exact_math_valid = opt.exact_math_post_checksum;
    } else if (cfg.only_valids) {
        opt.exact_math_valid = opt.exact_math_post_repeat / cs_div;
        if (opt.exact_math_valid == 0) opt.exact_math_valid = 1;
    } else {
        opt.exact_math_valid = opt.exact_math_post_repeat;
    }

    opt.total_combinations = opt.exact_math_total.get_d();
    opt.valid_combinations = opt.exact_math_valid.get_d();
    opt.math_combinations  = opt.exact_math_post_repeat.get_d();
}

void build_target(const AppConfig& cfg, OptimizedMnemonics& opt) {
    if (cfg.target.empty()) return;
    opt.has_target = true;
    if (cfg.coin == CoinTarget::BTC) {
        cryptowords::Bip39Deriver::decode_base58_btc_address(cfg.target, opt.target_bytes.data());
    } else {
        cryptowords::Bip39Deriver::decode_hex_eth_address(cfg.target, opt.target_bytes.data());
    }
    std::memcpy(&opt.target_fast_hash,   opt.target_bytes.data(), 4);
    std::memcpy(&opt.target_fast_hash64, opt.target_bytes.data(), 8);
}

// -----------------------------------------------------------------------------
// 3.12  Resolução dos modos.
// -----------------------------------------------------------------------------
bool use_streaming(const AppConfig& cfg, size_t K) {
    // Random desliga cascade: a otimização de outer-state estável não se
    // aplica em ordem permutada.
    if (cfg.random) return false;
    return cfg.only_valids && !cfg.has_checksum_filter && K >= 3;
}

ChecksumMode choose_checksum_mode(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                  bool streaming) {
    if (streaming) return ChecksumMode::None;
    if (cfg.has_checksum_filter) return ChecksumMode::UserPattern;
    if (!cfg.only_valids) return ChecksumMode::None;

    const size_t K = opt.unknown_positions.size();
    if (K == 0) return ChecksumMode::None;
    const bool last_known = opt.base_mnemonic.back() != AppConfig::UNKNOWN_WORD;

    if (K == 1) {
        return last_known ? ChecksumMode::Expected : ChecksumMode::SelfVerify;
    }
    if (last_known) return ChecksumMode::Expected;
    // Random sem entropy trick: a última palavra declara seu próprio
    // checksum nos bits baixos. Filtro puramente local.
    if (cfg.random) return ChecksumMode::SelfVerify;
    return ChecksumMode::AutoDeduce;
}

}  // namespace
}  // namespace cryptowords

// =========================================================================
// Ponto de entrada da fase 3.
// =========================================================================
OptimizedMnemonics SearchOptimizer::build_plan(const AppConfig& cfg) {
    using namespace cryptowords;

    OptimizedMnemonics opt;
    opt.raw_unknowns = cfg.raw_unknowns;
    opt.base_mnemonic.resize(cfg.mnemonics.size(), AppConfig::UNKNOWN_WORD);
    opt.count_eliminations = cfg.only_valids || cfg.has_checksum_filter;

    // --- 1. Espaço de busca ---
    init_wheels(cfg, opt);
    apply_distinct(cfg, opt);
    count_raw_wheel_distinct(cfg, opt);
    apply_repeat(cfg, opt);
    count_post_repeat(cfg, opt);

    // --- 2. Metadados derivados do tamanho ---
    const size_t mnemonic_len = opt.base_mnemonic.size();
    opt.checksum_bits = mnemonic_len * 11 / 33;
    opt.entropy_bits  = mnemonic_len * 11 - opt.checksum_bits;
    opt.entropy_bytes = opt.entropy_bits / 8;

    while (opt.prefix_words < mnemonic_len &&
           opt.base_mnemonic[opt.prefix_words] != AppConfig::UNKNOWN_WORD)
        opt.prefix_words++;

    build_phrase_layout(cfg, opt);
    build_word_soa(cfg, opt);

    {
        size_t max_word = 0;
        for (const auto& w : cfg.wordlist) max_word = std::max(max_word, w.size());
        const size_t worst = mnemonic_len * max_word +
                             (mnemonic_len - 1) * cfg.separator.size() + 16;
        opt.phrase_fits = (worst <= 512);
    }

    build_base_block(opt);

    // --- 3. --checksum: bitset dos valores permitidos ---
    if (cfg.has_checksum_filter) {
        opt.has_checksum_filter = true;
        opt.checksum_repr = cfg.checksum_repr;
        for (const auto& p : cfg.checksum_patterns) {
            const uint16_t max_val = static_cast<uint16_t>(1u << opt.checksum_bits);
            for (uint16_t v = 0; v < max_val; ++v)
                if ((v & p.mask) == p.value) opt.allowed_checksum_bits.set(v);
        }

        const bool last_known = opt.base_mnemonic.back() != AppConfig::UNKNOWN_WORD;
        const size_t K = opt.unknown_positions.size();
        const bool last_unknown_is_last = (K > 0) && (opt.unknown_positions.back() == mnemonic_len - 1);
        if (cfg.only_valids && last_known && !last_unknown_is_last) {
            if (!opt.allowed_checksum_bits.test(opt.expected_checksum)) {
                opt.impossible = true;
                return opt;
            }
        }
        if (opt.allowed_checksum_bits.none()) {
            opt.impossible = true;
            std::println(std::cerr,
                         "\n[\033[1;31m✗\033[0m] --checksum '{}' não deixa nenhum valor "
                         "possível para checksum de {} bits.",
                         cfg.checksum_repr, opt.checksum_bits);
            return opt;
        }
    }

    // --- 4. Snapshot pré-trick para cobertura ---
    opt.original_wheels = opt.wheels;

    // --- 5. Modo + entropy trick + checksum mode ---
    const size_t K = opt.unknown_positions.size();
    const bool streaming = use_streaming(cfg, K);
    opt.mode = streaming ? SearchMode::Streaming : SearchMode::Mixed;

    const bool last_unknown_is_last =
        (K > 0) && (opt.base_mnemonic.back() == AppConfig::UNKNOWN_WORD);
        const bool apply_trick = cfg.only_valids && !cfg.random && K >= 2 && last_unknown_is_last;
    if (apply_trick) apply_entropy_trick(opt);

    opt.random      = cfg.random;
    opt.random_seed = cfg.random_seed;
    opt.checksum_mode = choose_checksum_mode(cfg, opt, streaming);

    reorder_by_size(opt);

    // --- 6. Reorder por estratégia + --repeat ---
    opt.strategy_mask        = cfg.strategy_mask;
    opt.has_midstate_caching = (opt.prefix_words >= 3);
    opt.has_hamming_gradient = cfg.has_strategy(SearchStrategy::HammingGrad);
    opt.has_frequency        = cfg.has_strategy(SearchStrategy::Frequency);
    opt.has_typo             = cfg.has_strategy(SearchStrategy::Typo);
    opt.has_gray_code        = true;
    apply_strategy_reorder(cfg, opt);
    reorder_for_repeat(opt);

    // --- 7. Funil final + target ---
    finalize_spaces(cfg, opt, apply_trick);
    build_target(cfg, opt);

    return opt;
}
