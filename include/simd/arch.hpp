#pragma once
#include <cstddef>

namespace cryptowords {

enum class SimdArch { SCALAR, SSE, AVX2, AVX512, ARM_NEON, ARM_SHA512 };

SimdArch detect_best_simd();

template <SimdArch>
struct ArchTraits;

template <>
struct ArchTraits<SimdArch::SCALAR> {
    static constexpr size_t BATCH_SIZE = 1;
    static constexpr size_t C_BATCH_SIZE = 1;
};
template <>
struct ArchTraits<SimdArch::SSE> {
    static constexpr size_t BATCH_SIZE = 4;
    static constexpr size_t C_BATCH_SIZE = 8;
};
template <>
struct ArchTraits<SimdArch::AVX2> {
    static constexpr size_t BATCH_SIZE = 8;
    static constexpr size_t C_BATCH_SIZE = 16;
};
template <>
struct ArchTraits<SimdArch::AVX512> {
    static constexpr size_t BATCH_SIZE = 16;
    static constexpr size_t C_BATCH_SIZE = 32;
};
template <>
struct ArchTraits<SimdArch::ARM_NEON> {
    static constexpr size_t BATCH_SIZE = 4;
    static constexpr size_t C_BATCH_SIZE = 8;
};
template <>
struct ArchTraits<SimdArch::ARM_SHA512> {
    static constexpr size_t BATCH_SIZE = 4;
    static constexpr size_t C_BATCH_SIZE = 8;
};

}  // namespace cryptowords
