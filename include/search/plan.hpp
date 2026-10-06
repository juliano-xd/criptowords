#pragma once
#include "../config.hpp"

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <gmpxx.h>
#include <string>
#include <vector>

namespace cryptowords {

enum class SearchMode : uint8_t {
    Mixed,
    Pairs,
    Triplets,
    Streaming,
};

enum class ChecksumMode : uint8_t {
    None,
    Expected,
    AutoDeduce,
    UserPattern,
    SelfVerify,
};

// Wheel: lista ordenada de palavras + bitmask de pertinência.
struct Wheel {
    std::vector<uint16_t> words;
    std::array<uint64_t, 32> mask{};

    [[nodiscard]] bool contains(uint16_t w) const noexcept {
        return (mask[w >> 6] >> (w & 63)) & 1ULL;
    }
    void mark(uint16_t w) noexcept {
        mask[w >> 6] |= 1ULL << (w & 63);
    }
    void rebuild_mask() noexcept {
        mask.fill(0);
        for (uint16_t w : words) mark(w);
    }
    void push_back(uint16_t w) {
        words.push_back(w);
        mark(w);
    }

    [[nodiscard]] size_t   size()  const noexcept { return words.size(); }
    [[nodiscard]] bool     empty() const noexcept { return words.empty(); }
    [[nodiscard]] uint16_t operator[](size_t i) const noexcept { return words[i]; }
    [[nodiscard]] auto begin() const noexcept { return words.begin(); }
    [[nodiscard]] auto end()   const noexcept { return words.end(); }
};

struct PhraseSegment {
    uint16_t word_idx;
    uint16_t static_off;
    uint16_t static_len;
    uint16_t _pad;
};
static_assert(sizeof(PhraseSegment) == 8);

struct OptimizedMnemonics {
    std::vector<uint16_t> base_mnemonic;
    std::vector<size_t>   unknown_positions;
    std::vector<Wheel>    wheels;

    // Cópia pré-entropy-trick para snapshots de cobertura.
    std::vector<Wheel>    original_wheels;

    static constexpr size_t WORD_SLOT_BYTES = 16;
    static constexpr size_t WORDLIST_SIZE   = 2048;
    alignas(64) std::array<std::array<char, WORD_SLOT_BYTES>, WORDLIST_SIZE> word_buf;
    std::array<uint16_t, WORDLIST_SIZE> word_len16;

    mpz_class exact_math_raw;
    mpz_class exact_math_post_wheel;
    mpz_class exact_math_post_distinct;
    mpz_class exact_math_post_repeat;
    mpz_class exact_math_post_checksum;
    mpz_class exact_math_valid;
    mpz_class exact_math_total;

    double math_combinations_raw = 0.0;
    double math_combinations     = 0.0;
    double total_combinations    = 0.0;
    double valid_combinations    = 0.0;

    std::array<uint8_t, 2048> min_count{};
    std::array<uint8_t, 2048> max_count{};

    bool impossible         = false;
    bool count_eliminations = true;

    // Modo pseudoaleatório (--random).
    bool     random      = false;
    uint64_t random_seed = 0;

    std::vector<PhraseSegment> phrase_segments;
    std::string phrase_static;
    size_t phrase_n_segments = 0;
    size_t prefix_words      = 0;
    bool   phrase_fits       = true;

    size_t entropy_bits  = 0;
    size_t entropy_bytes = 0;
    size_t checksum_bits = 0;
    size_t raw_unknowns  = 0;

    SearchMode mode = SearchMode::Mixed;
    bool has_cascade_deduction = false;
    bool has_gray_code         = true;

    ChecksumMode checksum_mode = ChecksumMode::None;
    bool has_checksum_filter   = false;
    std::string checksum_repr;
    std::bitset<2048> allowed_last_words;
    std::bitset<256>  allowed_checksum_bits;
    uint8_t expected_checksum = 0;

    std::vector<std::pair<uint16_t, uint16_t>> valid_pairs;
    struct Triplet { uint16_t w0, w1, w2; };
    std::vector<Triplet> valid_triplets;

    alignas(64) std::array<uint8_t, 64> base_block64{};
    std::vector<size_t> unknown_bit_offsets;

    SearchStrategy strategy_mask = SearchStrategy::None;
    bool has_hamming_gradient = false;
    bool has_frequency        = false;
    bool has_typo             = false;
    bool has_midstate_caching = false;

    // --- --distinct ---
    bool   is_distinct           = false;
    bool   has_distinct_pruning  = false;
    size_t distinct_pruned_words = 0;

    std::array<uint8_t, 20> target_bytes{};
    uint32_t target_fast_hash   = 0;
    uint64_t target_fast_hash64 = 0;
    bool     has_target         = false;

    bool repeat_ids_empty_ = true;
    std::vector<std::pair<uint16_t, uint8_t>> repeat_ids_exact;

    // --- Helpers ---
    [[nodiscard]] bool has_strategy(SearchStrategy s) const noexcept {
        return has_bit(strategy_mask, s);
    }
    [[nodiscard]] bool is_pairs()    const noexcept { return mode == SearchMode::Pairs; }
    [[nodiscard]] bool is_triplets() const noexcept { return mode == SearchMode::Triplets; }
    [[nodiscard]] bool is_streaming() const noexcept { return mode == SearchMode::Streaming; }
    [[nodiscard]] size_t num_unknowns() const noexcept { return unknown_positions.size(); }
};

}  // namespace cryptowords
