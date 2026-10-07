#pragma once

#if defined(_WIN32)

#include <intrin.h>

static inline void cw_cpuid(unsigned leaf, unsigned& a, unsigned& b, unsigned& c, unsigned& d) noexcept {
    int r[4];
    __cpuid(r, static_cast<int>(leaf));
    a = static_cast<unsigned>(r[0]);
    b = static_cast<unsigned>(r[1]);
    c = static_cast<unsigned>(r[2]);
    d = static_cast<unsigned>(r[3]);
}

static inline void cw_cpuid_count(unsigned leaf, unsigned sub, unsigned& a, unsigned& b, unsigned& c,
                                  unsigned& d) noexcept {
    int r[4];
    __cpuidex(r, static_cast<int>(leaf), static_cast<int>(sub));
    a = static_cast<unsigned>(r[0]);
    b = static_cast<unsigned>(r[1]);
    c = static_cast<unsigned>(r[2]);
    d = static_cast<unsigned>(r[3]);
}

#elif defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)

#include <cpuid.h>

static inline void cw_cpuid(unsigned leaf, unsigned& a, unsigned& b, unsigned& c, unsigned& d) noexcept {
    __cpuid(leaf, a, b, c, d);
}

static inline void cw_cpuid_count(unsigned leaf, unsigned sub, unsigned& a, unsigned& b, unsigned& c,
                                  unsigned& d) noexcept {
    __cpuid_count(leaf, sub, a, b, c, d);
}

#else
// =========================================================================
// ARM64 (aarch64) / outras arquiteturas: CPUID x86 não existe.
// As detecções de feature são feitas via HWCAP (cpu_features.hpp).
// Este stub mantém a compilação de qualquer código que ainda inclua o header.
// =========================================================================

static inline void cw_cpuid(unsigned, unsigned& a, unsigned& b, unsigned& c, unsigned& d) noexcept {
    a = b = c = d = 0;
}
static inline void cw_cpuid_count(unsigned, unsigned, unsigned& a, unsigned& b, unsigned& c, unsigned& d) noexcept {
    a = b = c = d = 0;
}

#endif
