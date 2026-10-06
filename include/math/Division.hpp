#pragma once

#include <immintrin.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "Multiplication.hpp"

namespace Division {

using u64 = unsigned long long;

// __int128 é extensão GCC/Clang; silencia -Wpedantic localmente.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
using u128 = unsigned __int128;
#pragma GCC diagnostic pop

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif
#define BUILTIN_EXPECT(x, y) (__builtin_expect(!!(x), y))

// Compara a > b → 1, a < b → -1, a == b → 0.
inline int cmp_n(const u64* a, const u64* b, size_t n) {
    for (size_t i = n; i-- > 0;) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

// res = a + b, retorna carry.
inline u64 add_n(u64* res, const u64* a, const u64* b, size_t n) {
    unsigned char carry = 0;
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        carry = _addcarry_u64(carry, a[i], b[i], &res[i]);
        carry = _addcarry_u64(carry, a[i + 1], b[i + 1], &res[i + 1]);
        carry = _addcarry_u64(carry, a[i + 2], b[i + 2], &res[i + 2]);
        carry = _addcarry_u64(carry, a[i + 3], b[i + 3], &res[i + 3]);
    }
    for (; i < n; ++i) carry = _addcarry_u64(carry, a[i], b[i], &res[i]);
    return carry;
}

// res = a - b, retorna borrow.
inline u64 sub_n(u64* res, const u64* a, const u64* b, size_t n) {
    unsigned char borrow = 0;
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        borrow = _subborrow_u64(borrow, a[i], b[i], &res[i]);
        borrow = _subborrow_u64(borrow, a[i + 1], b[i + 1], &res[i + 1]);
        borrow = _subborrow_u64(borrow, a[i + 2], b[i + 2], &res[i + 2]);
        borrow = _subborrow_u64(borrow, a[i + 3], b[i + 3], &res[i + 3]);
    }
    for (; i < n; ++i) borrow = _subborrow_u64(borrow, a[i], b[i], &res[i]);
    return borrow;
}

// res = a << shift (shift ∈ [0,63]). Retorna carry out.
inline u64 shl_n(u64* res, const u64* a, size_t n, int shift) {
    if (shift == 0) {
        if (res != a) std::copy_n(a, n, res);
        return 0;
    }
    u64 carry = 0;
    for (size_t i = 0; i < n; ++i) {
        u64 next_carry = a[i] >> (64 - shift);
        res[i] = (a[i] << shift) | carry;
        carry = next_carry;
    }
    return carry;
}

// res = a >> shift (shift ∈ [0,63]). Retorna bits deslocados out.
inline u64 shr_n(u64* res, const u64* a, size_t n, int shift) {
    if (shift == 0) {
        if (res != a) std::copy_n(a, n, res);
        return 0;
    }
    u64 carry = 0;
    for (size_t i = n; i-- > 0;) {
        u64 next_carry = a[i] << (64 - shift);
        res[i] = (a[i] >> shift) | carry;
        carry = next_carry;
    }
    return carry;
}

// Knuth Algorithm D para M-limb / N-limb (M >= N). q = u/v, r = u%v.
// u: dividendo (u_len), v: divisor (v_len).
template <size_t MaxBlocks = 64>
inline void div_knuth_impl(u64* q, u64* r, const u64* u, int u_len, const u64* v, int v_len) {
    if (v_len == 0) throw std::domain_error("Division by zero in div_knuth_impl");

    if (u_len < v_len) {
        std::fill_n(q, u_len - v_len + 1, 0);
        std::copy_n(u, u_len, r);
        std::fill_n(r + u_len, v_len - u_len, 0);
        return;
    }

    const int shift = __builtin_clzll(v[v_len - 1]);
    const int an = u_len;
    const int bn = v_len;

    u64 u_norm[MaxBlocks + 2];
    u64 v_norm_storage[MaxBlocks + 1];
    const u64* v_ptr;

    if (shift > 0) {
        shl_n(v_norm_storage, v, bn, shift);
        v_ptr = v_norm_storage;
    } else {
        v_ptr = v;
    }

    if (shift > 0) {
        u_norm[an] = shl_n(u_norm, u, an, shift);
    } else {
        std::copy_n(u, an, u_norm);
        u_norm[an] = 0;
    }

    const u64 v_high = v_ptr[bn - 1];
    const u64 v_next = (bn > 1) ? v_ptr[bn - 2] : 0;

    for (int j = an - bn; j >= 0; --j) {
        u64 u_high = u_norm[j + bn];
        u64 u_mid  = u_norm[j + bn - 1];
        u64 q_hat;
        u128 current_dividend_top_two_limbs = ((u128)u_high << 64) | u_mid;

        if (u_high == v_high) [[unlikely]] {
            q_hat = ~0ULL;
        } else {
            q_hat = current_dividend_top_two_limbs / v_high;
        }

        // D3: refina q_hat enquanto r_hat < v_high (Knuth D3). Sem esse
        // bound o loop pode girar indefinidamente para casos degenerados.
        u128 r_hat_val_for_check = current_dividend_top_two_limbs - (u128)q_hat * v_high;
        u128 lhs_compare = (u128)q_hat * v_next;
        u64  u_low       = (j + bn >= 2) ? u_norm[j + bn - 2] : 0;
        u128 rhs_compare = (r_hat_val_for_check << 64) | u_low;

        if (lhs_compare > rhs_compare) [[unlikely]] {
            q_hat--;
            r_hat_val_for_check += v_high;
            if (r_hat_val_for_check < v_high) {
                lhs_compare = (u128)q_hat * v_next;
                rhs_compare = (r_hat_val_for_check << 64) | u_low;
                if (lhs_compare > rhs_compare) [[unlikely]] q_hat--;
            }
        }

        // D4: multiplica e subtrai.
        u64 mult_carry = 0;
        unsigned char sub_borrow = 0;

        size_t i = 0;
        for (; i + 4 <= (size_t)bn; i += 4) {
            u64 lo;
            u128 prod0 = (u128)q_hat * v_ptr[i]     + mult_carry; lo = (u64)prod0; mult_carry = prod0 >> 64;
            u128 prod1 = (u128)q_hat * v_ptr[i + 1] + mult_carry; u64 lo1 = (u64)prod1; mult_carry = prod1 >> 64;
            u128 prod2 = (u128)q_hat * v_ptr[i + 2] + mult_carry; u64 lo2 = (u64)prod2; mult_carry = prod2 >> 64;
            u128 prod3 = (u128)q_hat * v_ptr[i + 3] + mult_carry; u64 lo3 = (u64)prod3; mult_carry = prod3 >> 64;

            sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + i],     lo,  &u_norm[j + i]);
            sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + i + 1], lo1, &u_norm[j + i + 1]);
            sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + i + 2], lo2, &u_norm[j + i + 2]);
            sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + i + 3], lo3, &u_norm[j + i + 3]);
        }

        for (; i < (size_t)bn; ++i) {
            u128 prod = (u128)q_hat * v_ptr[i] + mult_carry;
            u64 lo = (u64)prod;
            mult_carry = prod >> 64;
            sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + i], lo, &u_norm[j + i]);
        }

        sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + bn], mult_carry, &u_norm[j + bn]);

        if (sub_borrow) {
            q_hat--;
            unsigned char add_carry = 0;
            for (size_t k = 0; k < (size_t)bn; ++k)
                add_carry = _addcarry_u64(add_carry, u_norm[j + k], v_ptr[k], &u_norm[j + k]);
            u_norm[j + bn] += add_carry;
        }

        q[j] = q_hat;
    }

    // D8: desnormaliza o resto.
    if (shift > 0) shr_n(r, u_norm, bn, shift);
    else           std::copy_n(u_norm, bn, r);
}

// Divisão Knuth com tamanho fixo N (para N pequeno, sem loops externos).
template <size_t N>
struct DivisionFixed {
    static FORCE_INLINE u64 add_n(u64* res, const u64* a, const u64* b) {
        unsigned char carry = 0;
        for (size_t i = 0; i < N; ++i) carry = _addcarry_u64(carry, a[i], b[i], &res[i]);
        return carry;
    }

    static FORCE_INLINE u64 sub_n(u64* res, const u64* a, const u64* b) {
        unsigned char borrow = 0;
        for (size_t i = 0; i < N; ++i) borrow = _subborrow_u64(borrow, a[i], b[i], &res[i]);
        return borrow;
    }

    static void div(u64* q, u64* r, const u64* u, const u64* v) {
        int n_limbs = 0;
        for (int i = N - 1; i >= 0; --i) {
            if (v[i] != 0) { n_limbs = i + 1; break; }
        }
        if (n_limbs == 0) throw std::domain_error("Division by zero");

        if (n_limbs < (int)N) {
            div_knuth_impl<N>(q, r, u, N, v, n_limbs);
            return;
        }

        int shift = __builtin_clzll(v[N - 1]);

        u64 v_norm_storage[N];
        const u64* v_ptr;
        u64 u_norm[N + 2];

        if (shift == 0) {
            v_ptr = v;
        } else {
            u64 c = 0;
#pragma GCC unroll 8
            for (size_t i = 0; i < N; ++i) {
                u64 val = v[i];
                v_norm_storage[i] = (val << shift) | c;
                c = val >> (64 - shift);
            }
            v_ptr = v_norm_storage;
        }

        if (shift == 0) {
#pragma GCC unroll 8
            for (size_t i = 0; i < N; ++i) u_norm[i] = u[i];
            u_norm[N] = 0;
            u_norm[N + 1] = 0;
        } else {
            u64 c = 0;
#pragma GCC unroll 8
            for (size_t i = 0; i < N; ++i) {
                u64 val = u[i];
                u_norm[i] = (val << shift) | c;
                c = val >> (64 - shift);
            }
            u_norm[N] = c;
            u_norm[N + 1] = 0;
        }

        const u64 v_high = v_ptr[N - 1];
        const u64 v_next = (N > 1) ? v_ptr[N - 2] : 0;

        for (int j = 1; j >= 0; --j) {
            u64 u_high = u_norm[j + N];
            u64 u_mid = u_norm[j + N - 1];

            if (u_high == 0 && u_mid < v_high) {
                q[j] = 0;
                continue;
            }

            u64 q_hat;
            if (u_high == v_high) {
                q_hat = ~0ULL;
            } else {
                u128 num = ((u128)u_high << 64) | u_mid;
                q_hat = num / v_high;
            }

            u128 r_hat = ((u128)u_high << 64) | u_mid;
            r_hat -= (u128)q_hat * v_high;

            if ((u128)q_hat * v_next > ((r_hat << 64) | u_norm[j + N - 2])) {
                q_hat--;
                r_hat += v_high;
                if (r_hat < v_high && ((u128)q_hat * v_next > ((r_hat << 64) | u_norm[j + N - 2]))) {
                    q_hat--;
                }
            }

            u64 mul_carry = 0;
            unsigned char sub_borrow = 0;
#pragma GCC unroll 8
            for (size_t i = 0; i < N; ++i) {
                u128 prod = (u128)q_hat * v_ptr[i] + mul_carry;
                mul_carry = prod >> 64;
                sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + i], (u64)prod, &u_norm[j + i]);
            }
            sub_borrow = _subborrow_u64(sub_borrow, u_norm[j + N], mul_carry, &u_norm[j + N]);

            if (sub_borrow) {
                q_hat--;
                add_n(&u_norm[j], &u_norm[j], v_ptr);
            }
            q[j] = q_hat;
        }

        if (shift == 0) {
#pragma GCC unroll 8
            for (size_t i = 0; i < N; ++i) r[i] = u_norm[i];
        } else {
#pragma GCC unroll 8
            for (int i = N - 1; i >= 0; --i) {
                u64 val = u_norm[i];
                u64 val_high = u_norm[i + 1];
                r[i] = (val >> shift) | (val_high << (64 - shift));
            }
        }
    }
};

}  // namespace Division
