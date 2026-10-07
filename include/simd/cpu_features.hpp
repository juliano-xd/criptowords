#pragma once
#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include "../hardware/cw_cpuid.hpp"
#endif

#if defined(__linux__) && (defined(__aarch64__) || defined(__arm__))
#include <sys/auxv.h>
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1 << 6)
#endif
#ifndef HWCAP_SHA512
#define HWCAP_SHA512 (1 << 21)
#endif
#ifndef HWCAP_SHA3
#define HWCAP_SHA3 (1 << 17)
#endif
#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1 << 1)
#endif
#endif

namespace cryptowords::cpu {

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

// SHA-256 em silício (x86 SHA-NI ou ARM SHA2 extension).
inline bool has_sha_ni() noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    static const bool cached = []() noexcept {
        unsigned eax, ebx, ecx, edx;
        cw_cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1u << 29)) != 0;
    }();
    return cached;
#elif defined(__linux__) && defined(__aarch64__)
    static const bool cached = (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
    return cached;
#else
    return false;
#endif
}

// SHA-512 em silício (x86 SHA-512 ext ou ARM SHA512 ext).
inline bool has_intel_sha512() noexcept {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    static const bool cached = []() noexcept {
        unsigned eax, ebx, ecx, edx;
        cw_cpuid_count(7, 1, eax, ebx, ecx, edx);
        return (eax & (1u << 0)) != 0;
    }();
    return cached;
#elif defined(__linux__) && defined(__aarch64__)
    static const bool cached = (getauxval(AT_HWCAP) & HWCAP_SHA512) != 0;
    return cached;
#else
    return false;
#endif
}

// SHA-3 em silício (x86 SHA3 ext não existe; útil só em ARMv8.4+).
inline bool has_sha3() noexcept {
#if defined(__linux__) && defined(__aarch64__)
    static const bool cached = (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
    return cached;
#else
    return false;
#endif
}

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
