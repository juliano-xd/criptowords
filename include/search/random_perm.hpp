#pragma once
#include <bit>
#include <cstdint>

namespace cryptowords {

// Permutação determinística sobre [0, N). Feistel de 4 rounds + cycle-walking.
// Bijection: qualquer seed produz uma ordem diferente, mas o conjunto
// percorrido é sempre [0, N).
//
// Custo: ~2 aplicações de Feistel por permute (cycle-walking amortizado).
// Uma aplicação = 4 rounds × 1 splitsmix64 ≈ 20 ns em CPU moderna.
class Permuter {
   public:
    Permuter(uint64_t N, uint64_t seed) noexcept : N_(N) {
        uint64_t s = seed ? seed : 1;
        for (int i = 0; i < 4; ++i) {
            s = splitsmix64(s);
            keys_[i] = s;
        }
        bits_  = (N <= 1) ? 0 : (64 - static_cast<uint32_t>(std::countl_zero(N - 1)));
        half_  = bits_ / 2;
        right_ = bits_ - half_;
    }

    [[nodiscard]] uint64_t permute(uint64_t i) const noexcept {
        if (N_ <= 1) return 0;
        uint64_t x = i;
        do {
            x = feistel(x);
        } while (x >= N_);
        return x;
    }

   private:
    uint64_t N_;
    uint64_t keys_[4] = {};
    uint32_t bits_  = 0;
    uint32_t half_  = 0;
    uint32_t right_ = 0;

    static uint64_t splitsmix64(uint64_t x) noexcept {
        x += 0x9E3779B97F4A7C15ULL;
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
        return x ^ (x >> 31);
    }

    uint64_t feistel(uint64_t input) const noexcept {
        const uint64_t half_mask  = (uint64_t{1} << half_) - 1;
        const uint64_t right_mask = (uint64_t{1} << right_) - 1;
        uint64_t L = (input >> right_) & half_mask;
        uint64_t R = input & right_mask;
        for (int i = 0; i < 4; ++i) {
            const uint64_t newR = L ^ (splitsmix64(R ^ keys_[i]) & half_mask);
            L = R;
            R = newR;
        }
        return (L << right_) | R;
    }
};

}  // namespace cryptowords
