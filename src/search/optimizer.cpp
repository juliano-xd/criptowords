#include "../../include/search/optimizer.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include <algorithm>
#include <numeric>
#include <bitset>
#include <cstring>
#include <cmath>
#include <bit>

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
                static const auto full_wheel_static = [] {
                    std::array<uint16_t, 2048> w;
                    std::iota(w.begin(), w.end(), static_cast<uint16_t>(0));
                    return w;
                }();
                opt.wheels.push_back(std::vector<uint16_t>(full_wheel_static.begin(), full_wheel_static.end()));
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
    // OTIMIZAÇÃO 30: Restrição de Não-Repetição (--distinct)
    // ==========================================
    if (cfg.distinct) {
        std::bitset<2048> is_known;
        for (size_t i = 0; i < mnemonic_len; ++i) {
            if (opt.base_mnemonic[i] != AppConfig::UNKNOWN_WORD) {
                is_known.set(opt.base_mnemonic[i]);
            }
        }
        size_t pruned = 0;
        for (auto& w : opt.wheels) {
            size_t before = w.size();
            std::erase_if(w, [&](uint16_t id) { return is_known.test(id); });
            pruned += (before - w.size());
        }
        if (pruned > 0) {
            opt.has_distinct_pruning = true;
            opt.distinct_pruned_words = pruned;
        }
    }

    // Cálculo do Espaço Matemático Bruto Inicial (antes de qualquer poda ou dedução de checksum)
    opt.math_combinations = 1.0;
    opt.exact_math_combinations = 1;
    for (const auto& w : opt.wheels) {
        opt.math_combinations *= static_cast<double>(w.size());
        opt.exact_math_combinations *= static_cast<uint64_t>(w.size());
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

    // ==========================================
    // OTIMIZAÇÃO 09: Fatiamento em N-Slices (Two-Sided Memory Patching)
    // ==========================================
    {
        std::vector<MnemonicSlice> raw_slices;
        size_t idx = 0;
        while (idx < mnemonic_len) {
            if (opt.base_mnemonic[idx] == AppConfig::UNKNOWN_WORD) {
                MnemonicSlice s;
                s.is_variable = true;
                s.word_idx = idx;
                raw_slices.push_back(std::move(s));
                ++idx;
            } else {
                MnemonicSlice s;
                s.is_variable = false;
                if (idx > 0) {
                    s.text += cfg.separator;
                }
                while (idx < mnemonic_len && opt.base_mnemonic[idx] != AppConfig::UNKNOWN_WORD) {
                    s.text += cfg.wordlist[opt.base_mnemonic[idx]];
                    if (idx + 1 < mnemonic_len && opt.base_mnemonic[idx + 1] != AppConfig::UNKNOWN_WORD) {
                        s.text += cfg.separator;
                    }
                    ++idx;
                }
                if (idx < mnemonic_len && opt.base_mnemonic[idx] == AppConfig::UNKNOWN_WORD) {
                    s.text += cfg.separator;
                }
                raw_slices.push_back(std::move(s));
            }
        }

        for (size_t k = 0; k < raw_slices.size(); ++k) {
            opt.slices.push_back(raw_slices[k]);
            if (k + 1 < raw_slices.size() && raw_slices[k].is_variable && raw_slices[k + 1].is_variable) {
                MnemonicSlice sep_slice;
                sep_slice.is_variable = false;
                sep_slice.text = cfg.separator;
                opt.slices.push_back(std::move(sep_slice));
            }
        }

        if (!opt.slices.empty() && !opt.slices[0].is_variable) {
            opt.slice0_static_len = opt.slices[0].text.size();
        }
    }

    opt.checksum_bits = mnemonic_len * 11 / 33;
    opt.entropy_bits = mnemonic_len * 11 - opt.checksum_bits;
    opt.entropy_bytes = opt.entropy_bits / 8;
    const size_t checksum_bits = opt.checksum_bits;
    const size_t entropy_bytes = opt.entropy_bytes;

    for (size_t i = 0; i < opt.prefix_words; ++i) {
        opt.base_acc = (opt.base_acc << 11) | (opt.base_mnemonic[i] & 0x7FF);
        opt.base_bits += 11;
        while (opt.base_bits >= 8 && opt.base_b_pos < entropy_bytes) {
            opt.base_bits -= 8;
            opt.base_entropy[opt.base_b_pos++] = (opt.base_acc >> opt.base_bits) & 0xFF;
        }
        opt.base_acc &= (1ULL << opt.base_bits) - 1;
    }

    // Preparação do Bloco Base SHA-256 (N-Slices no Bloco Criptográfico / Two-Sided Memory Patching)
    {
        uint64_t acc = 0;
        size_t bits = 0;
        size_t b_pos = 0;
        for (size_t i = 0; i < mnemonic_len; ++i) {
            uint16_t word_val = (opt.base_mnemonic[i] == AppConfig::UNKNOWN_WORD) ? 0 : (opt.base_mnemonic[i] & 0x7FF);
            acc = (acc << 11) | uint64_t(word_val);
            bits += 11;
            while (bits >= 8 && b_pos < entropy_bytes) {
                bits -= 8;
                opt.base_block64[b_pos++] = static_cast<uint8_t>(((acc >> bits) & uint64_t(0xFF)));
            }
            acc &= uint64_t((1ULL << bits) - 1);
        }
        opt.base_block64[entropy_bytes] = 0x80;
        uint64_t bit_len_be = __builtin_bswap64(static_cast<uint64_t>(opt.entropy_bits));
        std::memcpy(opt.base_block64 + 56, &bit_len_be, 8);

        opt.unknown_bit_offsets.clear();
        for (size_t u : opt.unknown_positions) {
            opt.unknown_bit_offsets.push_back(u * 11);
        }

        if (opt.base_mnemonic[mnemonic_len - 1] != AppConfig::UNKNOWN_WORD) {
            opt.expected_checksum = static_cast<uint8_t>(opt.base_mnemonic[mnemonic_len - 1] & ((1 << checksum_bits) - 1));
        }
    }

    // ==========================================
    // OTIMIZAÇÃO 1: Dedução Reversa Direta (1 Incógnita - Zero Overhead)
    // ==========================================
    if (cfg.only_valids && opt.unknown_positions.size() == 1) {
        size_t var_idx = opt.unknown_positions[0];
        std::vector<uint16_t> filtered_wheel;
        filtered_wheel.reserve(opt.wheels[0].size() / 16 + 1);
        std::vector<uint16_t> test_mn = opt.base_mnemonic;
        for (uint16_t candidate_id : opt.wheels[0]) {
            test_mn[var_idx] = candidate_id;
            if (cryptowords::Bip39Deriver::verify_checksum(test_mn)) {
                filtered_wheel.push_back(candidate_id);
            }
        }
        opt.wheels[0] = std::move(filtered_wheel);
        opt.auto_deduce_last_word = false;
        opt.direct_valid_wheels   = true;
    }
    // ==========================================
    // OTIMIZAÇÃO 33: Dedução Cascata de Checksum em Par (2 incógnitas com última incógnita w_{N-1} = ?)
    // ==========================================
    else if (cfg.only_valids && opt.unknown_positions.size() == 2 && opt.unknown_positions.back() == mnemonic_len - 1) {
        opt.has_cascade_deduction = true;

        const size_t u0 = opt.unknown_positions[0];
        const size_t u1 = opt.unknown_positions[1];
        const size_t u0_bit = u0 * 11;
        const size_t u1_bit = u1 * 11;

        for (uint16_t id : opt.wheels[1]) {
            opt.allowed_last_words[id] = true;
        }

        size_t entropy_bits_in_last_word = 11 - checksum_bits;
        size_t num_base_states = 1ULL << entropy_bits_in_last_word;

        alignas(64) uint8_t base_block[64] = {};
        uint64_t acc = 0;
        size_t bits = 0;
        size_t b_pos = 0;
        for (size_t i = 0; i < mnemonic_len; ++i) {
            uint16_t word_val = (i == u0 || i == u1) ? 0 : opt.base_mnemonic[i];
            acc = (acc << 11) | uint64_t(word_val & 0x7FF);
            bits += 11;
            while (bits >= 8) {
                bits -= 8;
                if (b_pos < entropy_bytes) {
                    base_block[b_pos++] = static_cast<uint8_t>(((acc >> bits) & uint64_t(0xFF)));
                }
            }
            acc &= uint64_t((1ULL << bits) - 1);
        }
        base_block[entropy_bytes] = 0x80;
        uint64_t bit_len_be = __builtin_bswap64(opt.entropy_bits);
        std::memcpy(base_block + 56, &bit_len_be, 8);

        alignas(64) uint8_t block[64];
        std::memcpy(block, base_block, 64);

        opt.valid_pairs.reserve(131072);

        for (uint16_t w0 : opt.wheels[0]) {
            cryptowords::detail::set_11bits(block, u0_bit, w0);
            for (size_t e = 0; e < num_base_states; ++e) {
                uint16_t val = static_cast<uint16_t>(e << checksum_bits);
                cryptowords::detail::set_11bits(block, u1_bit, val);
                block[entropy_bytes] = 0x80;
#if defined(__SHA__)
                uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(block);
#else
                uint8_t hash[32];
                crypto::SHA256::hash(block, entropy_bytes, hash);
                uint8_t h = hash[0];
#endif
                uint16_t syn = val | (h >> (8 - checksum_bits));
                if (opt.allowed_last_words[syn]) {
                    if (!cfg.distinct || w0 != syn) {
                        opt.valid_pairs.emplace_back(w0, syn);
                    }
                }
            }
        }

        opt.has_valid_pairs       = true;
        opt.direct_valid_wheels   = true;
        opt.auto_deduce_last_word = false;
    }
    // ==========================================
    // OTIMIZAÇÃO 33: Dedução Cascata de Checksum Streaming (K >= 3 com última incógnita w_{N-1} = ?)
    // ==========================================
    else if (cfg.only_valids && opt.unknown_positions.size() >= 3 && opt.unknown_positions.back() == mnemonic_len - 1) {
        opt.has_cascade_deduction = true;
        opt.has_streaming_pruning = true;
        opt.has_k3_pruning        = (opt.unknown_positions.size() == 3);
        opt.direct_valid_wheels   = true;
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
    // OTIMIZAÇÃO OTM-02: Pruning Analítico de Pares em F_2^C (2 incógnitas com última fixa)
    // ==========================================
    else if (cfg.only_valids && opt.unknown_positions.size() == 2) {
        const size_t u0 = opt.unknown_positions[0];
        const size_t u1 = opt.unknown_positions[1];
        const size_t u0_bit = u0 * 11;
        const size_t u1_bit = u1 * 11;
        const uint8_t expected_cs = opt.base_mnemonic[mnemonic_len - 1] & ((1 << checksum_bits) - 1);

        alignas(64) uint8_t base_block[64] = {};
        uint64_t acc = 0;
        size_t bits = 0;
        size_t b_pos = 0;
        for (size_t i = 0; i < mnemonic_len; ++i) {
            uint16_t word_val = (i == u0 || i == u1) ? 0 : opt.base_mnemonic[i];
            acc = (acc << 11) | uint64_t(word_val & 0x7FF);
            bits += 11;
            while (bits >= 8) {
                bits -= 8;
                if (b_pos < entropy_bytes) {
                    base_block[b_pos++] = static_cast<uint8_t>(((acc >> bits) & uint64_t(0xFF)));
                }
            }
            acc &= uint64_t((1ULL << bits) - 1);
        }
        base_block[entropy_bytes] = 0x80;
        uint64_t bit_len_be = __builtin_bswap64(opt.entropy_bits);
        std::memcpy(base_block + 56, &bit_len_be, 8);

        alignas(64) uint8_t block[64];
        std::memcpy(block, base_block, 64);

        opt.valid_pairs.reserve(131072);

        for (uint16_t w0 : opt.wheels[0]) {
            cryptowords::detail::set_11bits(block, u0_bit, w0);
            for (uint16_t w1 : opt.wheels[1]) {
                cryptowords::detail::set_11bits(block, u1_bit, w1);
#if defined(__SHA__)
                uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(block);
#else
                uint8_t hash[32];
                crypto::SHA256::hash(block, entropy_bytes, hash);
                uint8_t h = hash[0];
#endif
                if ((h >> (8 - checksum_bits)) == expected_cs) {
                    if (!cfg.distinct || w0 != w1) {
                        opt.valid_pairs.emplace_back(w0, w1);
                    }
                }
            }
        }

        opt.has_valid_pairs     = true;
        opt.direct_valid_wheels = true;
    }
    // ==========================================
    // OTIMIZAÇÃO OTM-03: Poda Streaming em F_2^C (K >= 3 incógnitas com última fixa)
    // ==========================================
    else if (cfg.only_valids && opt.unknown_positions.size() >= 3) {
        opt.has_streaming_pruning = true;
        opt.has_k3_pruning        = (opt.unknown_positions.size() == 3);
        opt.direct_valid_wheels   = true;
    }

    // ==========================================
    // OTIMIZAÇÃO OTM-29: Priorização por Gradiente de Hamming & Estratégias
    // ==========================================
    opt.active_strategies    = cfg.strategies;
    opt.active_strategy      = cfg.strategies.empty() ? SearchStrategy::Default : cfg.strategies[0];
    opt.has_midstate_caching = (opt.prefix_words >= 3);
    opt.has_hamming_gradient = cfg.has_strategy(SearchStrategy::HammingGradient);
    opt.has_frequency        = cfg.has_strategy(SearchStrategy::Frequency);
    opt.has_typo             = cfg.has_strategy(SearchStrategy::Typo);
    opt.has_gray_code        = true;

    const bool has_any_strategy = opt.has_hamming_gradient || opt.has_frequency || opt.has_typo;

    if (has_any_strategy) {
        opt.has_beam_search  = true;
        opt.beam_shell_count = 3;

        auto score_word_fn = [&](size_t u_pos, uint16_t w) -> double {
            double score = 0.0;

            std::string ref_word = "";
            if (opt.has_typo) {
                if (u_pos > 0 && opt.base_mnemonic[u_pos - 1] != AppConfig::UNKNOWN_WORD) {
                    ref_word = cfg.wordlist[opt.base_mnemonic[u_pos - 1]];
                } else if (u_pos + 1 < mnemonic_len && opt.base_mnemonic[u_pos + 1] != AppConfig::UNKNOWN_WORD) {
                    ref_word = cfg.wordlist[opt.base_mnemonic[u_pos + 1]];
                }
            }

            // 1. Componente Hamming & Entropia de Borda (OTM-29)
            if (opt.has_hamming_gradient) {
                int h_score = 0;
                int pc = std::popcount(static_cast<unsigned int>(w & 0x7FF));
                h_score += std::abs(2 * pc - 11);
                uint16_t transitions = (w ^ (w >> 1)) & 0x3FF;
                h_score += std::abs(static_cast<int>(std::popcount(static_cast<unsigned int>(transitions))) - 5);
                if (u_pos > 0 && opt.base_mnemonic[u_pos - 1] != AppConfig::UNKNOWN_WORD) {
                    uint16_t prev = opt.base_mnemonic[u_pos - 1];
                    size_t bit_pos = (u_pos * 11) % 8;
                    uint8_t cross = static_cast<uint8_t>(((prev << (8 - bit_pos)) | (w >> (11 - (8 - bit_pos)))) & 0xFF);
                    h_score += std::abs(static_cast<int>(std::popcount(static_cast<unsigned int>(cross))) - 4);
                }
                score += static_cast<double>(h_score) * 10.0;
            }

            // 2. Componente Frequência Linguística (Zipf / Word length)
            if (opt.has_frequency) {
                const auto& word = cfg.wordlist[w];
                score += static_cast<double>(word.size()) * 2.0;
            }

            // 3. Componente Typo / Edit Distance
            if (opt.has_typo && !ref_word.empty()) {
                const auto& cand = cfg.wordlist[w];
                int match = 0;
                for (char c : cand) {
                    if (ref_word.find(c) != std::string::npos) match++;
                }
                score -= static_cast<double>(match) * 5.0;
            }

            return score;
        };

        for (size_t k = 0; k < opt.wheels.size(); ++k) {
            size_t u_pos = opt.unknown_positions[k];
            std::stable_sort(opt.wheels[k].begin(), opt.wheels[k].end(), [&](uint16_t a, uint16_t b) {
                double sa = score_word_fn(u_pos, a);
                double sb = score_word_fn(u_pos, b);
                if (sa != sb) return sa < sb;
                return a < b;
            });
        }

        if (opt.has_valid_pairs) {
            const size_t u0 = opt.unknown_positions[0];
            const size_t u1 = opt.unknown_positions[1];
            std::stable_sort(opt.valid_pairs.begin(), opt.valid_pairs.end(), [&](const auto& a, const auto& b) {
                double sa = score_word_fn(u0, a.first) + score_word_fn(u1, a.second);
                double sb = score_word_fn(u0, b.first) + score_word_fn(u1, b.second);
                if (sa != sb) return sa < sb;
                return a < b;
            });
        }
    }

    // Cálculo de Combinações Efetivas
    opt.total_combinations = 1.0;
    opt.exact_total_combinations = 1;
    if (opt.has_valid_pairs) {
        opt.total_combinations = static_cast<double>(opt.valid_pairs.size());
        opt.exact_total_combinations = UInt<4>(opt.valid_pairs.size());
    } else if (opt.has_streaming_pruning) {
        if (opt.has_cascade_deduction) {
            opt.total_combinations = 1.0;
            opt.exact_total_combinations = 1;
            for (const auto& w : opt.wheels) {
                opt.total_combinations *= static_cast<double>(w.size());
                opt.exact_total_combinations *= static_cast<uint64_t>(w.size());
            }
        } else {
            opt.total_combinations = std::max(1.0, std::round(opt.math_combinations / static_cast<double>(1ULL << checksum_bits)));
            opt.exact_total_combinations = opt.exact_math_combinations >> static_cast<uint16_t>(checksum_bits);
            if (opt.exact_total_combinations.eqz()) opt.exact_total_combinations = 1;
        }
    } else {
        opt.exact_total_combinations = 1;
        for (const auto& w : opt.wheels) {
            opt.total_combinations *= static_cast<double>(w.size());
            opt.exact_total_combinations *= static_cast<uint64_t>(w.size());
        }
    }

    opt.valid_combinations = opt.total_combinations;
    opt.exact_valid_combinations = opt.exact_total_combinations;
    if (cfg.only_valids && !opt.direct_valid_wheels && !opt.auto_deduce_last_word) {
        opt.valid_combinations = std::max(1.0, std::round(opt.total_combinations / static_cast<double>(1ULL << checksum_bits)));
        opt.exact_valid_combinations = opt.exact_total_combinations >> static_cast<uint16_t>(checksum_bits);
        if (opt.exact_valid_combinations.eqz()) opt.exact_valid_combinations = 1;
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
        std::memcpy(&opt.target_fast_hash64, opt.target_bytes, 8);
    }

    return opt;
}
