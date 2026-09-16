#include "../../include/simd/factory.hpp"

#include <memory>

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

namespace cryptowords {

SimdArch detect_best_simd() {
#if defined(__x86_64__) || defined(_M_X64)
    unsigned eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    const bool has_sse41 = (ecx & bit_SSE4_1) != 0;

    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    const bool has_avx2   = (ebx & bit_AVX2)   != 0;
    const bool has_avx512 = (ebx & bit_AVX512F) != 0;

    if (has_avx512) return SimdArch::AVX512;
    if (has_avx2)   return SimdArch::AVX2;
    if (has_sse41)  return SimdArch::SSE;
#endif
    return SimdArch::SSE;
}

std::unique_ptr<IBatchProcessor>
make_simd_processor(const AppConfig& cfg, const OptimizedMnemonics& opt, SimdArch arch) {
#ifdef CRYPTOWORDS_HAVE_AVX512
    if (arch == SimdArch::AVX512) return detail::make_simd_processor_avx512(cfg, opt);
#endif
#ifdef CRYPTOWORDS_HAVE_AVX2
    if (arch == SimdArch::AVX2) return detail::make_simd_processor_avx2(cfg, opt);
#endif
#ifdef CRYPTOWORDS_HAVE_SSE41
    if (arch == SimdArch::SSE) return detail::make_simd_processor_sse(cfg, opt);
    return detail::make_simd_processor_sse(cfg, opt);
#else
    (void)cfg; (void)opt; (void)arch;
    return nullptr;
#endif
}

} // namespace cryptowords
