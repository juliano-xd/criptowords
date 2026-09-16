#pragma once
#include <cstddef>

namespace cryptowords {

enum class SimdArch { SSE, AVX2, AVX512 };

SimdArch detect_best_simd();

template <SimdArch> struct ArchTraits;

template <> struct ArchTraits<SimdArch::SSE> {
    static constexpr size_t BATCH_SIZE   = 4;
    static constexpr size_t C_BATCH_SIZE = 8;
};
template <> struct ArchTraits<SimdArch::AVX2> {
    static constexpr size_t BATCH_SIZE   = 8;
    static constexpr size_t C_BATCH_SIZE = 16;
};
template <> struct ArchTraits<SimdArch::AVX512> {
    static constexpr size_t BATCH_SIZE   = 16;
    static constexpr size_t C_BATCH_SIZE = 32;
};

} // namespace cryptowords
