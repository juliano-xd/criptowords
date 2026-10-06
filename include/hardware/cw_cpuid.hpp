#pragma once

// Wrapper de CPUID que funciona nos dois mundos.
//
// No GCC/Clang o <cpuid.h> define __cpuid como MACRO de 5 argumentos:
//     __cpuid(leaf, eax, ebx, ecx, edx)
// No Windows o <intrin.h> declara uma FUNCAO com o mesmo nome e 2 argumentos:
//     void __cpuid(int cpuInfo[4], int function_id)
//
// Se o <cpuid.h> for incluido no mingw, a macro de 5 argumentos passa por cima
// da declaracao do <intrin.h> e o erro sai dentro do proprio header do sistema
// (psdk_inc/intrin-impl.h), o que confunde bastante na hora de debugar.

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

#else

#include <cpuid.h>

static inline void cw_cpuid(unsigned leaf, unsigned& a, unsigned& b, unsigned& c, unsigned& d) noexcept {
    __cpuid(leaf, a, b, c, d);
}

static inline void cw_cpuid_count(unsigned leaf, unsigned sub, unsigned& a, unsigned& b, unsigned& c,
                                  unsigned& d) noexcept {
    __cpuid_count(leaf, sub, a, b, c, d);
}

#endif
