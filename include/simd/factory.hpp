#pragma once
#include <memory>

#include "../search/processor.hpp"
#include "arch.hpp"
#include "cpu_features.hpp"

namespace cryptowords {

// detect_best_simd() declarada em arch.hpp — sem duplicata.

std::unique_ptr<IBatchProcessor> make_simd_processor(const AppConfig& cfg,
                                                     const OptimizedMnemonics& opt,
                                                     SimdArch arch);

namespace detail {
std::unique_ptr<IBatchProcessor> make_simd_processor_sse(const AppConfig&, const OptimizedMnemonics&);
std::unique_ptr<IBatchProcessor> make_simd_processor_avx2(const AppConfig&, const OptimizedMnemonics&);
std::unique_ptr<IBatchProcessor> make_simd_processor_avx512(const AppConfig&, const OptimizedMnemonics&);
}  // namespace detail

}  // namespace cryptowords
