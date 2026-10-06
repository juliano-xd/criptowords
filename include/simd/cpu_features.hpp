#pragma once
#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include "../hardware/cw_cpuid.hpp"
#endif

namespace cryptowords::cpu {

// XCR0 — leitura via inline asm (evita exigir -mxsave no build).
[[gnu::always_inline]] inline uint64_t read_xcr0() noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(_MSC_VER)
    return _xgetbv(0);
#else
    uint32_t lo, hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(lo), "=d"(hi) : "c"(0));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#endif
#else
    return 0;
#endif
}

[[gnu::always_inline]] inline bool avx_ymm_enabled() noexcept {
    return (read_xcr0() & 0x06ULL) == 0x06ULL;
}
[[gnu::always_inline]] inline bool avx512_zmm_enabled() noexcept {
    return (read_xcr0() & 0xE6ULL) == 0xE6ULL;
}

// Detecções CPUID — cacheadas na primeira chamada (cada cpuid ~50-200 ns;
// o custo aparece em hot paths que consultam por candidato).

// SHA-256 silício (SHA-NI): CPUID.7.0:EBX[29].
inline bool has_sha_ni() noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    static const bool cached = []() noexcept {
        unsigned eax, ebx, ecx, edx;
        cw_cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1u << 29)) != 0;
    }();
    return cached;
#else
    return false;
#endif
}

// SHA-512 silício: CPUID.7.1:EAX[0] (Intel Arrow Lake+ / AMD Zen 5+).
inline bool has_intel_sha512() noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    static const bool cached = []() noexcept {
        unsigned eax, ebx, ecx, edx;
        cw_cpuid_count(7, 1, eax, ebx, ecx, edx);
        return (eax & (1u << 0)) != 0;
    }();
    return cached;
#else
    return false;
#endif
}

// AVX10: CPUID.7.1:EDX[19]. Sem uso direto — reportado em host_probe.
inline bool has_avx10() noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    static const bool cached = []() noexcept {
        unsigned eax, ebx, ecx, edx;
        cw_cpuid_count(7, 1, eax, ebx, ecx, edx);
        return (edx & (1u << 19)) != 0;
    }();
    return cached;
#else
    return false;
#endif
}

}  // namespace cryptowords::cpu
