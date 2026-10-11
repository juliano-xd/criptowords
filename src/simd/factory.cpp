#include "../../include/simd/factory.hpp"

#include <iostream>
#include <memory>
#include <print>
#include <stdexcept>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include "../../include/hardware/cw_cpuid.hpp"
#endif

namespace cryptowords {

namespace {

constexpr SimdArch compiled_best() noexcept {
#if defined(CRYPTOWORDS_HAVE_AVX512)
    return SimdArch::AVX512;
#elif defined(CRYPTOWORDS_HAVE_AVX2)
    return SimdArch::AVX2;
#elif defined(CRYPTOWORDS_HAVE_SSE41)
    return SimdArch::SSE;
#elif defined(CRYPTOWORDS_HAVE_ARM_SHA512)
    return SimdArch::ARM_SHA512;
#elif defined(CRYPTOWORDS_HAVE_ARM_NEON)
    return SimdArch::ARM_NEON;
#else
    return SimdArch::SCALAR;
#endif
}

constexpr const char* arch_name(SimdArch a) noexcept {
    switch (a) {
        case SimdArch::AVX512:     return "AVX512";
        case SimdArch::AVX2:       return "AVX2";
        case SimdArch::SSE:        return "SSE4.1";
        case SimdArch::ARM_SHA512: return "ARMv8.2 SHA-512";
        case SimdArch::ARM_NEON:   return "ARM NEON";
        case SimdArch::SCALAR:     return "Scalar";
    }
    return "?";
}

}  // namespace

SimdArch detect_best_simd() {
    SimdArch cpu_best = SimdArch::SCALAR;

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    unsigned eax, ebx, ecx, edx;
    cw_cpuid(1, eax, ebx, ecx, edx);

    const bool has_sse41 = (ecx & bit_SSE4_1) != 0;
    const bool osxsave   = (ecx & bit_OSXSAVE) != 0;
    const bool avx_cpu   = (ecx & bit_AVX) != 0;

    const bool ymm_ok = osxsave && cpu::avx_ymm_enabled();
    const bool zmm_ok = osxsave && cpu::avx512_zmm_enabled();

    cw_cpuid_count(7, 0, eax, ebx, ecx, edx);
    const bool has_avx2   = avx_cpu && ymm_ok && (ebx & bit_AVX2);
    const bool has_avx512 = avx_cpu && zmm_ok &&
                            (ebx & bit_AVX512F) && (ebx & bit_AVX512VL) && (ebx & bit_AVX512BW);

    if (has_avx512)     cpu_best = SimdArch::AVX512;
    else if (has_avx2)  cpu_best = SimdArch::AVX2;
    else if (has_sse41) cpu_best = SimdArch::SSE;
#elif defined(__aarch64__) || defined(__arm__)
    cpu_best = SimdArch::ARM_NEON;
    if (cpu::has_intel_sha512()) { // No ARM, esta função avalia o HWCAP_SHA512 via getauxval
        cpu_best = SimdArch::ARM_SHA512;
    }
#endif

    const SimdArch compiled  = compiled_best();
    SimdArch effective = compiled;

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    if (cpu_best < compiled) effective = cpu_best;
#elif defined(__aarch64__) || defined(__arm__)
    if (compiled == SimdArch::ARM_SHA512 && cpu_best == SimdArch::ARM_NEON) {
        effective = SimdArch::ARM_NEON;
    }
#endif

    if (effective != cpu_best && effective != compiled) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            std::println(std::cerr,
                         "[i] CPU suporta \033[1;36m{}\033[0m mas o binário foi compilado apenas com "
                         "\033[1;33m{}\033[0m. Usando \033[1;33m{}\033[0m.",
                         arch_name(cpu_best), arch_name(compiled), arch_name(effective));
        }
    }
    return effective;
}

std::unique_ptr<IBatchProcessor> make_simd_processor(const AppConfig& cfg,
                                                     const OptimizedMnemonics& opt,
                                                     SimdArch arch) {
#ifdef CRYPTOWORDS_HAVE_AVX512
    if (arch == SimdArch::AVX512) return detail::make_simd_processor_avx512(cfg, opt);
#endif
#ifdef CRYPTOWORDS_HAVE_AVX2
    if (arch == SimdArch::AVX2)   return detail::make_simd_processor_avx2(cfg, opt);
#endif
#ifdef CRYPTOWORDS_HAVE_SSE41
    if (arch == SimdArch::SSE)    return detail::make_simd_processor_sse(cfg, opt);
#endif
#ifdef CRYPTOWORDS_HAVE_ARM_SHA512
    if (arch == SimdArch::ARM_SHA512) return detail::make_simd_processor_arm_sha512(cfg, opt);
#endif
#ifdef CRYPTOWORDS_HAVE_ARM_NEON
    if (arch == SimdArch::ARM_NEON) return detail::make_simd_processor_arm_neon(cfg, opt);
#endif

    (void)cfg; (void)opt; (void)arch;
    throw std::runtime_error(
        "Nenhum backend SIMD compilado. Verifique as macros do CMake.");
}

}  // namespace cryptowords
