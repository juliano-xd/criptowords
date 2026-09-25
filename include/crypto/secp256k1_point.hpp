#pragma once

#include <array>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "../math/UInt.hpp"
#pragma GCC diagnostic pop

#include "secp256k1_scalar.hpp"
#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace crypto {

// Primo do corpo de Koblitz SECP256K1: p = 2^256 - 2^32 - 977
constexpr static UInt<4> P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
static constexpr uint64_t DELTA_P = 0x1000003D1ULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

// =========================================================================
// GERAÇÃO DA TABELA DE PONTOS SECP256K1 100% EM TEMPO DE COMPILAÇÃO (CONSTEXPR)
// Elimina dependência de arquivos em disco e alinha 256 pontos (16 KB) em L1D
// =========================================================================

struct ConstexprPointA {
    uint64_t x[4];
    uint64_t y[4];
};

struct ConstexprUInt256 {
    uint64_t bits[4] = {0, 0, 0, 0};

    constexpr ConstexprUInt256() = default;
    constexpr ConstexprUInt256(uint64_t b0, uint64_t b1, uint64_t b2, uint64_t b3) : bits{b0, b1, b2, b3} {}

    constexpr bool eqz() const {
        return (bits[0] | bits[1] | bits[2] | bits[3]) == 0;
    }

    constexpr bool operator>=(const ConstexprUInt256& o) const {
        for (int i = 3; i >= 0; --i) {
            if (bits[i] > o.bits[i]) return true;
            if (bits[i] < o.bits[i]) return false;
        }
        return true;
    }
};

constexpr ConstexprUInt256 CP(0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);

constexpr ConstexprUInt256 c_add_mod_p(const ConstexprUInt256& a, const ConstexprUInt256& b) {
    ConstexprUInt256 res{};
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; ++i) {
        c += static_cast<unsigned __int128>(a.bits[i]) + b.bits[i];
        res.bits[i] = static_cast<uint64_t>(c);
        c >>= 64;
    }
    if (c || res >= CP) {
        unsigned __int128 borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 diff = static_cast<unsigned __int128>(res.bits[i]) - CP.bits[i] - borrow;
            res.bits[i] = static_cast<uint64_t>(diff);
            borrow = (diff >> 127) & 1;
        }
    }
    return res;
}

constexpr ConstexprUInt256 c_sub_mod_p(const ConstexprUInt256& a, const ConstexprUInt256& b) {
    ConstexprUInt256 res{};
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 diff = static_cast<unsigned __int128>(a.bits[i]) - b.bits[i] - borrow;
        res.bits[i] = static_cast<uint64_t>(diff);
        borrow = (diff >> 127) & 1;
    }
    if (borrow) {
        unsigned __int128 c = 0;
        for (int i = 0; i < 4; ++i) {
            c += static_cast<unsigned __int128>(res.bits[i]) + CP.bits[i];
            res.bits[i] = static_cast<uint64_t>(c);
            c >>= 64;
        }
    }
    return res;
}

constexpr ConstexprUInt256 c_mul_mod_p(const ConstexprUInt256& a, const ConstexprUInt256& b) {
    uint64_t r[8] = {0};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 prod = static_cast<unsigned __int128>(a.bits[i]) * b.bits[j] + r[i + j] + carry;
            r[i + j] = static_cast<uint64_t>(prod);
            carry = static_cast<uint64_t>(prod >> 64);
        }
        r[i + 4] += carry;
    }

    uint64_t carry = 0;
    uint64_t h_prod[5] = {0};
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 prod = static_cast<unsigned __int128>(r[4 + i]) * DELTA_P + carry;
        h_prod[i] = static_cast<uint64_t>(prod);
        carry = static_cast<uint64_t>(prod >> 64);
    }
    h_prod[4] = carry;

    uint64_t s[5] = {0};
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; ++i) {
        c += static_cast<unsigned __int128>(r[i]) + h_prod[i];
        s[i] = static_cast<uint64_t>(c);
        c >>= 64;
    }
    c += h_prod[4];
    s[4] = static_cast<uint64_t>(c);

    if (s[4] != 0) {
        unsigned __int128 extra = static_cast<unsigned __int128>(s[4]) * DELTA_P;
        c = static_cast<unsigned __int128>(s[0]) + static_cast<uint64_t>(extra);
        s[0] = static_cast<uint64_t>(c);
        c >>= 64;
        c += static_cast<unsigned __int128>(s[1]) + static_cast<uint64_t>(extra >> 64);
        s[1] = static_cast<uint64_t>(c);
        c >>= 64;
        c += s[2];
        s[2] = static_cast<uint64_t>(c);
        c >>= 64;
        c += s[3];
        s[3] = static_cast<uint64_t>(c);
        c >>= 64;
        if (c != 0) {
            unsigned __int128 final_c = c * DELTA_P;
            c = static_cast<unsigned __int128>(s[0]) + static_cast<uint64_t>(final_c);
            s[0] = static_cast<uint64_t>(c);
            c >>= 64;
            s[1] += static_cast<uint64_t>(c);
        }
    }

    ConstexprUInt256 res(s[0], s[1], s[2], s[3]);
    if (res >= CP) {
        unsigned __int128 borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 diff = static_cast<unsigned __int128>(res.bits[i]) - CP.bits[i] - borrow;
            res.bits[i] = static_cast<uint64_t>(diff);
            borrow = (diff >> 127) & 1;
        }
    }
    return res;
}

constexpr ConstexprUInt256 c_sqr_mod_p(const ConstexprUInt256& a) { return c_mul_mod_p(a, a); }

constexpr ConstexprUInt256 c_sqr_n(ConstexprUInt256 a, int n) {
    for (int i = 0; i < n; ++i) a = c_sqr_mod_p(a);
    return a;
}

constexpr ConstexprUInt256 c_inv_mod_p(const ConstexprUInt256& a) {
    ConstexprUInt256 x2 = c_mul_mod_p(c_sqr_mod_p(a), a);
    ConstexprUInt256 x3 = c_mul_mod_p(c_sqr_mod_p(x2), a);
    ConstexprUInt256 x6 = c_mul_mod_p(c_sqr_n(x3, 3), x3);
    ConstexprUInt256 x9 = c_mul_mod_p(c_sqr_n(x6, 3), x3);
    ConstexprUInt256 x11 = c_mul_mod_p(c_sqr_n(x9, 2), x2);
    ConstexprUInt256 x22 = c_mul_mod_p(c_sqr_n(x11, 11), x11);
    ConstexprUInt256 x44 = c_mul_mod_p(c_sqr_n(x22, 22), x22);
    ConstexprUInt256 x88 = c_mul_mod_p(c_sqr_n(x44, 44), x44);
    ConstexprUInt256 x176 = c_mul_mod_p(c_sqr_n(x88, 88), x88);
    ConstexprUInt256 x220 = c_mul_mod_p(c_sqr_n(x176, 44), x44);
    ConstexprUInt256 x223 = c_mul_mod_p(c_sqr_n(x220, 3), x3);
    ConstexprUInt256 t = c_sqr_n(x223, 33);

    constexpr uint32_t LOW32 = 0xFFFFFC2D;
    ConstexprUInt256 low_acc(1, 0, 0, 0);
    ConstexprUInt256 base = a;
    for (int b = 0; b < 32; ++b) {
        if ((LOW32 >> b) & 1U) {
            low_acc = c_mul_mod_p(low_acc, base);
        }
        if (b < 31) base = c_sqr_mod_p(base);
    }
    return c_mul_mod_p(t, low_acc);
}

struct ConstexprPointJ {
    ConstexprUInt256 X;
    ConstexprUInt256 Y;
    ConstexprUInt256 Z;
    bool is_inf = true;

    constexpr ConstexprPointJ() : X(0,0,0,0), Y(0,0,0,0), Z(0,0,0,0), is_inf(true) {}
    constexpr ConstexprPointJ(ConstexprUInt256 x, ConstexprUInt256 y, ConstexprUInt256 z, bool inf = false)
        : X(x), Y(y), Z(z), is_inf(inf) {}
};

constexpr ConstexprPointJ c_point_double(const ConstexprPointJ& p) {
    if (p.is_inf || p.Y.eqz()) return ConstexprPointJ();
    ConstexprUInt256 A = c_sqr_mod_p(p.X);
    ConstexprUInt256 B = c_sqr_mod_p(p.Y);
    ConstexprUInt256 C = c_sqr_mod_p(B);

    ConstexprUInt256 XB = c_add_mod_p(p.X, B);
    ConstexprUInt256 XB2 = c_sqr_mod_p(XB);
    ConstexprUInt256 D = c_sub_mod_p(c_sub_mod_p(XB2, A), C);
    D = c_add_mod_p(D, D);

    ConstexprUInt256 E = c_add_mod_p(c_add_mod_p(A, A), A);
    ConstexprUInt256 E2 = c_sqr_mod_p(E);

    ConstexprUInt256 D2 = c_add_mod_p(D, D);
    ConstexprUInt256 X3 = c_sub_mod_p(E2, D2);

    ConstexprUInt256 DX3 = c_sub_mod_p(D, X3);
    ConstexprUInt256 EDX3 = c_mul_mod_p(E, DX3);

    ConstexprUInt256 C8 = c_add_mod_p(C, C);
    C8 = c_add_mod_p(C8, C8);
    C8 = c_add_mod_p(C8, C8);

    ConstexprUInt256 Y3 = c_sub_mod_p(EDX3, C8);
    ConstexprUInt256 Z3 = c_mul_mod_p(c_add_mod_p(p.Y, p.Y), p.Z);

    return ConstexprPointJ(X3, Y3, Z3, false);
}

// Gera a tabela estática com 256 pontos (2^i * G) em coordenadas afins
constexpr auto generate_secp256k1_g_table_256() {
    constexpr int TOTAL_POINTS = 256;
    std::array<ConstexprPointJ, TOTAL_POINTS> jac_points{};

    // Gerador G em little-endian de limbs de 64 bits
    jac_points[0] = ConstexprPointJ(
        ConstexprUInt256(0x59f2815b16f81798ULL, 0x029bfcdb2dce28d9ULL, 0x55a06295ce870b07ULL, 0x79be667ef9dcbbacULL),
        ConstexprUInt256(0x9c47d08ffb10d4b8ULL, 0xfd17b448a6855419ULL, 0x5da4fbfc0e1108a8ULL, 0x483ada7726a3c465ULL),
        ConstexprUInt256(1, 0, 0, 0), false);

    for (int i = 1; i < TOTAL_POINTS; ++i) {
        jac_points[i] = c_point_double(jac_points[i - 1]);
    }

    // Inversão em lote de Montgomery para normalização simultânea a coordenadas afins
    std::array<ConstexprUInt256, TOTAL_POINTS> prod{};
    prod[0] = jac_points[0].Z;
    for (int i = 1; i < TOTAL_POINTS; ++i) {
        prod[i] = c_mul_mod_p(prod[i - 1], jac_points[i].Z);
    }

    ConstexprUInt256 inv_all = c_inv_mod_p(prod[TOTAL_POINTS - 1]);

    std::array<ConstexprPointA, TOTAL_POINTS> table{};
    for (int i = TOTAL_POINTS - 1; i >= 1; --i) {
        ConstexprUInt256 z_inv = c_mul_mod_p(inv_all, prod[i - 1]);
        inv_all = c_mul_mod_p(inv_all, jac_points[i].Z);

        ConstexprUInt256 z_inv2 = c_sqr_mod_p(z_inv);
        ConstexprUInt256 z_inv3 = c_mul_mod_p(z_inv, z_inv2);
        ConstexprUInt256 x = c_mul_mod_p(jac_points[i].X, z_inv2);
        ConstexprUInt256 y = c_mul_mod_p(jac_points[i].Y, z_inv3);

        table[i] = ConstexprPointA{{x.bits[0], x.bits[1], x.bits[2], x.bits[3]},
                                   {y.bits[0], y.bits[1], y.bits[2], y.bits[3]}};
    }

    ConstexprUInt256 z_inv = inv_all;
    ConstexprUInt256 z_inv2 = c_sqr_mod_p(z_inv);
    ConstexprUInt256 z_inv3 = c_mul_mod_p(z_inv, z_inv2);
    ConstexprUInt256 x = c_mul_mod_p(jac_points[0].X, z_inv2);
    ConstexprUInt256 y = c_mul_mod_p(jac_points[0].Y, z_inv3);
    table[0] = ConstexprPointA{{x.bits[0], x.bits[1], x.bits[2], x.bits[3]},
                               {y.bits[0], y.bits[1], y.bits[2], y.bits[3]}};

    return table;
}

// Tabela de geradores calculada integralmente em tempo de compilação (16 KB na seção .rodata)
inline constexpr auto G_TABLE_CONSTEXPR = generate_secp256k1_g_table_256();

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
// Multiplicação especializada em F_p com redução Koblitz em ~22 instruções x86-64 sem divisões
FORCE_INLINE UInt<4> mul_mod_p(const UInt<4>& a, const UInt<4>& b) noexcept {
    uint64_t r[8] = {};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 prod = static_cast<unsigned __int128>(a.bits[i]) * b.bits[j] + r[i + j] + carry;
            r[i + j] = static_cast<uint64_t>(prod);
            carry = static_cast<uint64_t>(prod >> 64);
        }
        r[i + 4] += carry;
    }
    uint64_t carry = 0;
    uint64_t h_prod[5] = {};
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 prod = static_cast<unsigned __int128>(r[4 + i]) * DELTA_P + carry;
        h_prod[i] = static_cast<uint64_t>(prod);
        carry = static_cast<uint64_t>(prod >> 64);
    }
    h_prod[4] = carry;

    uint64_t s[5] = {};
    unsigned char c = 0;
    c = _addcarry_u64(0, r[0], h_prod[0], reinterpret_cast<unsigned long long*>(&s[0]));
    c = _addcarry_u64(c, r[1], h_prod[1], reinterpret_cast<unsigned long long*>(&s[1]));
    c = _addcarry_u64(c, r[2], h_prod[2], reinterpret_cast<unsigned long long*>(&s[2]));
    c = _addcarry_u64(c, r[3], h_prod[3], reinterpret_cast<unsigned long long*>(&s[3]));
    c = _addcarry_u64(c, 0, h_prod[4], reinterpret_cast<unsigned long long*>(&s[4]));

    if (s[4] != 0) {
        unsigned __int128 extra = static_cast<unsigned __int128>(s[4]) * DELTA_P;
        c = _addcarry_u64(0, s[0], static_cast<uint64_t>(extra), reinterpret_cast<unsigned long long*>(&s[0]));
        c = _addcarry_u64(c, s[1], static_cast<uint64_t>(extra >> 64), reinterpret_cast<unsigned long long*>(&s[1]));
        c = _addcarry_u64(c, s[2], 0, reinterpret_cast<unsigned long long*>(&s[2]));
        c = _addcarry_u64(c, s[3], 0, reinterpret_cast<unsigned long long*>(&s[3]));
        if (c) {
            unsigned __int128 final_c = static_cast<unsigned __int128>(c) * DELTA_P;
            _addcarry_u64(0, s[0], static_cast<uint64_t>(final_c), reinterpret_cast<unsigned long long*>(&s[0]));
        }
    }

    UInt<4> res;
    for (int i = 0; i < 4; ++i) res.bits[i] = s[i];
    if (res >= P) res -= P;
    return res;
}
#pragma GCC diagnostic pop

// Adição modular em F_p
FORCE_INLINE UInt<4> add_mod_p(const UInt<4>& a, const UInt<4>& b) noexcept {
    UInt<4> res;
    unsigned char c = 0;
    c = _addcarry_u64(0, a.bits[0], b.bits[0], reinterpret_cast<unsigned long long*>(&res.bits[0]));
    c = _addcarry_u64(c, a.bits[1], b.bits[1], reinterpret_cast<unsigned long long*>(&res.bits[1]));
    c = _addcarry_u64(c, a.bits[2], b.bits[2], reinterpret_cast<unsigned long long*>(&res.bits[2]));
    c = _addcarry_u64(c, a.bits[3], b.bits[3], reinterpret_cast<unsigned long long*>(&res.bits[3]));
    if (c || res >= P) { res -= P; }
    return res;
}

// Subtração modular em F_p
FORCE_INLINE UInt<4> sub_mod_p(const UInt<4>& a, const UInt<4>& b) noexcept {
    UInt<4> res;
    const auto& p = P;
    unsigned char borrow = 0;
    borrow = _subborrow_u64(0, a.bits[0], b.bits[0], reinterpret_cast<unsigned long long*>(&res.bits[0]));
    borrow = _subborrow_u64(borrow, a.bits[1], b.bits[1], reinterpret_cast<unsigned long long*>(&res.bits[1]));
    borrow = _subborrow_u64(borrow, a.bits[2], b.bits[2], reinterpret_cast<unsigned long long*>(&res.bits[2]));
    borrow = _subborrow_u64(borrow, a.bits[3], b.bits[3], reinterpret_cast<unsigned long long*>(&res.bits[3]));
    if (borrow) { res += p; }
    return res;
}

FORCE_INLINE UInt<4> sqr_mod_p(const UInt<4>& a) noexcept {
    return mul_mod_p(a, a);
}

FORCE_INLINE UInt<4> sqr_n(UInt<4> a, int n) noexcept {
    for (int i = 0; i < n; ++i) a = sqr_mod_p(a);
    return a;
}

// Inversão modular acelerada em F_p via Addition Chain (223 bits + 32 bits): a^(p-2) mod p
inline UInt<4> inv_mod_p(const UInt<4>& a) noexcept {
    UInt<4> x2 = mul_mod_p(sqr_mod_p(a), a);
    UInt<4> x3 = mul_mod_p(sqr_mod_p(x2), a);
    UInt<4> x6 = mul_mod_p(sqr_n(x3, 3), x3);
    UInt<4> x9 = mul_mod_p(sqr_n(x6, 3), x3);
    UInt<4> x11 = mul_mod_p(sqr_n(x9, 2), x2);
    UInt<4> x22 = mul_mod_p(sqr_n(x11, 11), x11);
    UInt<4> x44 = mul_mod_p(sqr_n(x22, 22), x22);
    UInt<4> x88 = mul_mod_p(sqr_n(x44, 44), x44);
    UInt<4> x176 = mul_mod_p(sqr_n(x88, 88), x88);
    UInt<4> x220 = mul_mod_p(sqr_n(x176, 44), x44);
    UInt<4> x223 = mul_mod_p(sqr_n(x220, 3), x3);
    UInt<4> t = sqr_n(x223, 33);

    static constexpr uint32_t LOW32 = 0xFFFFFC2D;
    UInt<4> low_acc = 1;
    UInt<4> base = a;
    for (int b = 0; b < 32; ++b) {
        if ((LOW32 >> b) & 1U) {
            low_acc = mul_mod_p(low_acc, base);
        }
        if (b < 31) base = sqr_mod_p(base);
    }
    return mul_mod_p(t, low_acc);
}

struct PointJacobian {
    UInt<4> X;
    UInt<4> Y;
    UInt<4> Z;
    bool is_infinity = true;
};

// Adição mista Jacobiana-Afim
FORCE_INLINE void point_add_mixed_raw(PointJacobian& p1, const uint64_t p2_x[4], const uint64_t p2_y[4]) noexcept {
    if (p1.is_infinity) {
        for (int i = 0; i < 4; ++i) { p1.X.bits[i] = p2_x[i]; p1.Y.bits[i] = p2_y[i]; }
        p1.Z = 1;
        p1.is_infinity = false;
        return;
    }

    UInt<4> p2x, p2y;
    for (int i = 0; i < 4; ++i) { p2x.bits[i] = p2_x[i]; p2y.bits[i] = p2_y[i]; }

    UInt<4> Z1Z1 = mul_mod_p(p1.Z, p1.Z);
    UInt<4> U2 = mul_mod_p(p2x, Z1Z1);
    UInt<4> S2 = mul_mod_p(p2y, mul_mod_p(p1.Z, Z1Z1));

    UInt<4> H = sub_mod_p(U2, p1.X);
    UInt<4> R = sub_mod_p(S2, p1.Y);

    if (H.eqz()) {
        if (R.eqz()) return;
        else { p1.is_infinity = true; return; }
    }

    UInt<4> Z3 = mul_mod_p(p1.Z, H);
    UInt<4> H2 = mul_mod_p(H, H);
    UInt<4> H3 = mul_mod_p(H, H2);
    UInt<4> U1_H2 = mul_mod_p(p1.X, H2);

    UInt<4> R2 = mul_mod_p(R, R);
    UInt<4> X3 = sub_mod_p(sub_mod_p(R2, H3), add_mod_p(U1_H2, U1_H2));
    UInt<4> Y3 = sub_mod_p(mul_mod_p(R, sub_mod_p(U1_H2, X3)), mul_mod_p(p1.Y, H3));

    p1.X = X3;
    p1.Y = Y3;
    p1.Z = Z3;
}

FORCE_INLINE UInt<4> load_be256(const uint8_t be[32]) noexcept {
    UInt<4> res;
    uint64_t w3, w2, w1, w0;
    std::memcpy(&w3, be + 0, 8);
    std::memcpy(&w2, be + 8, 8);
    std::memcpy(&w1, be + 16, 8);
    std::memcpy(&w0, be + 24, 8);
    res.bits[3] = __builtin_bswap64(w3);
    res.bits[2] = __builtin_bswap64(w2);
    res.bits[1] = __builtin_bswap64(w1);
    res.bits[0] = __builtin_bswap64(w0);
    return res;
}

FORCE_INLINE void store_be256(uint8_t be[32], const UInt<4>& v) noexcept {
    uint64_t w3 = __builtin_bswap64(v.bits[3]);
    uint64_t w2 = __builtin_bswap64(v.bits[2]);
    uint64_t w1 = __builtin_bswap64(v.bits[1]);
    uint64_t w0 = __builtin_bswap64(v.bits[0]);
    std::memcpy(be + 0, &w3, 8);
    std::memcpy(be + 8, &w2, 8);
    std::memcpy(be + 16, &w1, 8);
    std::memcpy(be + 24, &w0, 8);
}

// Multiplicação de gerador G * seckey convertida para coordenadas afins (X, Y)
inline bool secp256k1_ecmult_gen_affine(UInt<4>& x_aff, UInt<4>& y_aff, const uint8_t seckey[32]) noexcept {
    UInt<4> k = load_be256(seckey);
    if (__builtin_expect(k.eqz(), 0)) return false;

    PointJacobian acc;
    for (int limb = 0; limb < 4; ++limb) {
        uint64_t w = k.bits[limb];
        while (w != 0) {
            int bit = __builtin_ctzll(w);
            const auto& pt = G_TABLE_CONSTEXPR[limb * 64 + bit];
            point_add_mixed_raw(acc, pt.x, pt.y);
            w &= (w - 1);
        }
    }

    if (acc.is_infinity) return false;

    UInt<4> z_inv = inv_mod_p(acc.Z);
    UInt<4> z_inv2 = mul_mod_p(z_inv, z_inv);
    UInt<4> z_inv3 = mul_mod_p(z_inv, z_inv2);
    x_aff = mul_mod_p(acc.X, z_inv2);
    y_aff = mul_mod_p(acc.Y, z_inv3);
    return true;
}

// Cria chave pública comprimida (33 bytes) a partir da chave privada (32 bytes)
inline bool secp256k1_pubkey_create_fast(uint8_t out_pub[33], const uint8_t seckey[32]) noexcept {
    UInt<4> x_aff, y_aff;
    if (!secp256k1_ecmult_gen_affine(x_aff, y_aff, seckey)) return false;
    out_pub[0] = (y_aff.bits[0] & 1ULL) ? 0x03 : 0x02;
    store_be256(out_pub + 1, x_aff);
    return true;
}

inline bool secp256k1_pubkey_create_fast(std::array<uint8_t, 33> &out_pub, const std::array<uint8_t, 32> &seckey) noexcept {
    return secp256k1_pubkey_create_fast(out_pub.data(), seckey.data());
}

// Cria chave pública não comprimida (65 bytes: 0x04 || X || Y)
inline bool secp256k1_pubkey_create_uncompressed(uint8_t out_pub[65], const uint8_t seckey[32]) noexcept {
    UInt<4> x_aff, y_aff;
    if (!secp256k1_ecmult_gen_affine(x_aff, y_aff, seckey)) return false;
    out_pub[0] = 0x04;
    store_be256(out_pub + 1, x_aff);
    store_be256(out_pub + 33, y_aff);
    return true;
}

inline bool secp256k1_pubkey_create_uncompressed(std::array<uint8_t, 65> &out_pub, const std::array<uint8_t, 32> &seckey) noexcept {
    return secp256k1_pubkey_create_uncompressed(out_pub.data(), seckey.data());
}

} // namespace crypto
