#pragma once
#include "../search/processor.hpp"
#include "arch.hpp"

#include <memory>

namespace cryptowords {

// Detecção de runtime (implementada em src/simd/factory.cpp)
SimdArch detect_best_simd();

// Fachada pública — dispatch runtime baseado na CPU.
std::unique_ptr<IBatchProcessor> make_simd_processor(const AppConfig& cfg, const OptimizedMnemonics& opt, SimdArch arch);
    // Símbolos definidos por TU. Só existem se o bloco SIMD correspondente foi
    // compilado — o dispatcher usa CRYPTOWORDS_HAVE_* para saber.
    namespace detail {
        #ifdef CRYPTOWORDS_HAVE_SSE41
            std::unique_ptr<IBatchProcessor>
            make_simd_processor_sse(const AppConfig&, const OptimizedMnemonics&);
        #endif
        #ifdef CRYPTOWORDS_HAVE_AVX2
            std::unique_ptr<IBatchProcessor>
            make_simd_processor_avx2(const AppConfig&, const OptimizedMnemonics&);
        #endif
        #ifdef CRYPTOWORDS_HAVE_AVX512
            std::unique_ptr<IBatchProcessor>
            make_simd_processor_avx512(const AppConfig&, const OptimizedMnemonics&);
        #endif
    } // namespace detail
} // namespace cryptowords
