#pragma once

#include <array>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "../math/UInt.hpp"
#pragma GCC diagnostic pop

#include "secp256k1_scalar.hpp"
#include "g_table_w4.hpp"
#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace crypto {

// Primo do corpo de Koblitz SECP256K1: p = 2^256 - 2^32 - 977
constexpr static UInt<4> P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

static constexpr uint64_t DELTA_P = 0x1000003D1ULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
// Redução especializada em F_p (p = 2^256 - 2^32 - 977) com DELTA_P em ~22 instruções sem divisões
FORCE_INLINE UInt<4> reduce_secp256k1_p(const uint64_t r[8]) noexcept {
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

// Multiplicação em F_p (4x4 = 16 multiplicações)
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
    return reduce_secp256k1_p(r);
}

// Quadratura modular dedicada em F_p: reduz de 16 para 10 multiplicações (37.5% de aceleração)
FORCE_INLINE UInt<4> sqr_mod_p(const UInt<4>& a) noexcept {
    const uint64_t a0 = a.bits[0], a1 = a.bits[1], a2 = a.bits[2], a3 = a.bits[3];

    // 6 produtos cruzados
    const unsigned __int128 c01 = static_cast<unsigned __int128>(a0) * a1;
    const unsigned __int128 c02 = static_cast<unsigned __int128>(a0) * a2;
    const unsigned __int128 c03 = static_cast<unsigned __int128>(a0) * a3;
    const unsigned __int128 c12 = static_cast<unsigned __int128>(a1) * a2;
    const unsigned __int128 c13 = static_cast<unsigned __int128>(a1) * a3;
    const unsigned __int128 c23 = static_cast<unsigned __int128>(a2) * a3;

    uint64_t t[8] = {};
    unsigned char carry = 0;

    t[1] = static_cast<uint64_t>(c01);
    carry = _addcarry_u64(0, static_cast<uint64_t>(c01 >> 64), static_cast<uint64_t>(c02), reinterpret_cast<unsigned long long*>(&t[2]));
    carry = _addcarry_u64(carry, static_cast<uint64_t>(c02 >> 64), static_cast<uint64_t>(c03), reinterpret_cast<unsigned long long*>(&t[3]));
    carry = _addcarry_u64(carry, static_cast<uint64_t>(c03 >> 64), static_cast<uint64_t>(c13), reinterpret_cast<unsigned long long*>(&t[4]));
    carry = _addcarry_u64(carry, static_cast<uint64_t>(c13 >> 64), static_cast<uint64_t>(c23), reinterpret_cast<unsigned long long*>(&t[5]));
    carry = _addcarry_u64(carry, static_cast<uint64_t>(c23 >> 64), 0, reinterpret_cast<unsigned long long*>(&t[6]));

    // Adiciona c12 nos limbs 3 e 4
    carry = _addcarry_u64(0, t[3], static_cast<uint64_t>(c12), reinterpret_cast<unsigned long long*>(&t[3]));
    carry = _addcarry_u64(carry, t[4], static_cast<uint64_t>(c12 >> 64), reinterpret_cast<unsigned long long*>(&t[4]));
    carry = _addcarry_u64(carry, t[5], 0, reinterpret_cast<unsigned long long*>(&t[5]));
    _addcarry_u64(carry, t[6], 0, reinterpret_cast<unsigned long long*>(&t[6]));

    // Multiplica produtos cruzados por 2 (shift de 1 bit à esquerda)
    uint64_t r[8] = {};
    r[7] = t[6] >> 63;
    r[6] = (t[6] << 1) | (t[5] >> 63);
    r[5] = (t[5] << 1) | (t[4] >> 63);
    r[4] = (t[4] << 1) | (t[3] >> 63);
    r[3] = (t[3] << 1) | (t[2] >> 63);
    r[2] = (t[2] << 1) | (t[1] >> 63);
    r[1] = t[1] << 1;
    r[0] = 0;

    // 4 quadrados da diagonal
    const unsigned __int128 d0 = static_cast<unsigned __int128>(a0) * a0;
    const unsigned __int128 d1 = static_cast<unsigned __int128>(a1) * a1;
    const unsigned __int128 d2 = static_cast<unsigned __int128>(a2) * a2;
    const unsigned __int128 d3 = static_cast<unsigned __int128>(a3) * a3;

    // Soma diagonais no acumulador
    r[0] = static_cast<uint64_t>(d0);
    carry = _addcarry_u64(0, r[1], static_cast<uint64_t>(d0 >> 64), reinterpret_cast<unsigned long long*>(&r[1]));
    carry = _addcarry_u64(carry, r[2], static_cast<uint64_t>(d1), reinterpret_cast<unsigned long long*>(&r[2]));
    carry = _addcarry_u64(carry, r[3], static_cast<uint64_t>(d1 >> 64), reinterpret_cast<unsigned long long*>(&r[3]));
    carry = _addcarry_u64(carry, r[4], static_cast<uint64_t>(d2), reinterpret_cast<unsigned long long*>(&r[4]));
    carry = _addcarry_u64(carry, r[5], static_cast<uint64_t>(d2 >> 64), reinterpret_cast<unsigned long long*>(&r[5]));
    carry = _addcarry_u64(carry, r[6], static_cast<uint64_t>(d3), reinterpret_cast<unsigned long long*>(&r[6]));
    _addcarry_u64(carry, r[7], static_cast<uint64_t>(d3 >> 64), reinterpret_cast<unsigned long long*>(&r[7]));

    return reduce_secp256k1_p(r);
}
#pragma GCC diagnostic pop

// Adição modular em F_p via UInt<4>::add_carry
FORCE_INLINE UInt<4> add_mod_p(UInt<4> a, const UInt<4>& b) noexcept {
    if (a.add_carry(b) || a >= P) { a -= P; }
    return a;
}

// Subtração modular em F_p via UInt<4>::sub_borrow
FORCE_INLINE UInt<4> sub_mod_p(UInt<4> a, const UInt<4>& b) noexcept {
    if (a.sub_borrow(b)) { a += P; }
    return a;
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

// Cria chave pública comprimida (33 bytes) a partir da chave privada (32 bytes)
inline bool secp256k1_pubkey_create_fast(std::array<uint8_t, 33> &out_pub, const std::array<uint8_t, 32> &seckey) noexcept {
    const UInt<4> k = load_be256(seckey);
    if (__builtin_expect(k.eqz(), 0)) return false;

    PointJacobian acc;
    for (int w = 0; w < 64; ++w) {
        int limb = w / 16;
        int shift = (w % 16) * 4;
        uint32_t val = (k.bits[limb] >> shift) & 0x0F;
        if (val > 0) {
            const auto& pt = G_TABLE_W4[w][val - 1];
            point_add_mixed_raw(acc, pt.x, pt.y);
        }
    }

    if (acc.is_infinity) return false;

    UInt<4> z_inv = inv_mod_p(acc.Z);
    UInt<4> z_inv2 = mul_mod_p(z_inv, z_inv);
    UInt<4> z_inv3 = mul_mod_p(z_inv, z_inv2);
    UInt<4> x_aff = mul_mod_p(acc.X, z_inv2);
    UInt<4> y_aff = mul_mod_p(acc.Y, z_inv3);

    out_pub[0] = (y_aff.bits[0] & 1ULL) ? 0x03 : 0x02;
    store_be256(out_pub.data() + 1, x_aff);
    return true;
}

// Cria chave pública não comprimida (65 bytes: 0x04 || X || Y)
inline bool secp256k1_pubkey_create_uncompressed(std::array<uint8_t, 65> &out_pub, const std::array<uint8_t, 32> &seckey) noexcept {
    const UInt<4> k = load_be256(seckey);
    if (__builtin_expect(k.eqz(), 0)) return false;

    PointJacobian acc;
    for (uint8_t w = 0; w < 64; ++w) {
        uint8_t limb = w >> 4;
        uint8_t shift = (w & 0x0F) * 4;
        uint32_t val = (k.bits[limb] >> shift) & 0x0F;
        if (val > 0) {
            const auto& pt = G_TABLE_W4[w][val - 1];
            point_add_mixed_raw(acc, pt.x, pt.y);
        }
    }

    if (acc.is_infinity) return false;

    UInt<4> z_inv = inv_mod_p(acc.Z);
    UInt<4> z_inv2 = mul_mod_p(z_inv, z_inv);
    UInt<4> z_inv3 = mul_mod_p(z_inv, z_inv2);
    UInt<4> x_aff = mul_mod_p(acc.X, z_inv2);
    UInt<4> y_aff = mul_mod_p(acc.Y, z_inv3);

    out_pub[0] = 0x04;
    store_be256(out_pub.data() + 1, x_aff);
    store_be256(out_pub.data() + 33, y_aff);
    return true;
}


} // namespace crypto
