#pragma once

#include <array>
#include <cstdint>
#include <cstring>

#include "../math/Point.hpp"
#include "../math/Secp256k1Fp.hpp"

#ifndef FORCE_INLINE
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

namespace crypto {

using SecpFp  = Secp256k1Fp;
using Fe      = SecpFp::Element;   // std::array<u64, 4>
using PointJ  = Point<SecpFp>;

// Apenas 32 pontos: G_256I[i] = 2^(8i) * G em afim (i = 0..31).
// Reduz drasticamente o custo em tempo de compilação.
constexpr auto generate_secp256k1_g_table_32() noexcept {
    std::array<PointJ, 32> t{};

    t[0] = PointJ::from_affine(
        Fe{0x59f2815b16f81798ULL, 0x029bfcdb2dce28d9ULL,
           0x55a06295ce870b07ULL, 0x79be667ef9dcbbacULL},
        Fe{0x9c47d08ffb10d4b8ULL, 0xfd17b448a6855419ULL,
           0x5da4fbfc0e1108a8ULL, 0x483ada7726a3c465ULL});

    // 2^(8i) * G = (2^(8(i-1)) * G) dobrado 8 vezes
    for (int i = 1; i < 32; ++i) {
        PointJ p = t[i - 1];
        for (int k = 0; k < 8; ++k) p = p.doubled();
        t[i] = p;
    }

    std::array<Fe, 32> scratch{};
    PointJ::batch_normalize(t.data(), 32, scratch.data());
    return t;
}

inline constexpr auto G_TABLE_CONSTEXPR = generate_secp256k1_g_table_32();

struct ConstexprPointA { Fe x; Fe y; };

// Comb table: table[i][v] = v · 256^i · G, em afim.
//
// Construção:
//   - J[v]   = J[v-1] + 256^i·G   (255 mixed adds por byte)
//   - batch_normalize em 255 pontos  → 1 inversão por byte (não 255)
//   - Total: 32 inversões em vez de 8192 (~256× menos inversões).
struct Secp256k1ByteTableHolder {
    ConstexprPointA table[32][256];

    Secp256k1ByteTableHolder() noexcept {
        for (int i = 0; i < 32; ++i) {
            std::memset(&table[i][0], 0, sizeof(ConstexprPointA));

            // 256^i · G já está pronto, afim, Z = 1.
            const PointJ& G_i = G_TABLE_CONSTEXPR[i];
            const Fe x1 = G_i[X];
            const Fe y1 = G_i[Y];

            std::array<PointJ, 255> jac{};
            jac[0] = G_i;
            for (int v = 2; v < 256; ++v) {
                jac[v - 1] = jac[v - 2];
                jac[v - 1].add_mixed(x1, y1);
            }

            std::array<Fe, 255> scratch{};
            PointJ::batch_normalize(jac.data(), 255, scratch.data());

            for (int v = 1; v < 256; ++v) {
                table[i][v].x = jac[v - 1][X];
                table[i][v].y = jac[v - 1][Y];
            }
        }
    }
};

inline const ConstexprPointA (*get_secp256k1_byte_table() noexcept)[256] {
    static const Secp256k1ByteTableHolder s_holder;
    return s_holder.table;
}

inline void warmup_secp256k1_table() noexcept {
    (void)get_secp256k1_byte_table();
}

// Serialização BE 256-bit
FORCE_INLINE void store_be256(uint8_t be[32], const Fe& v) noexcept {
    uint64_t w3 = __builtin_bswap64(v[3]);
    uint64_t w2 = __builtin_bswap64(v[2]);
    uint64_t w1 = __builtin_bswap64(v[1]);
    uint64_t w0 = __builtin_bswap64(v[0]);
    std::memcpy(be +  0, &w3, 8);
    std::memcpy(be +  8, &w2, 8);
    std::memcpy(be + 16, &w1, 8);
    std::memcpy(be + 24, &w0, 8);
}

// k·G  —  inicia o acumulador diretamente (evita "add_mixed a partir do
// infinito") e poupa um ramo e um caso especial no primeiro passo.
inline bool secp256k1_ecmult_gen_affine(Fe& x_aff, Fe& y_aff,
                                        const uint8_t seckey[32]) noexcept {
    const auto table = get_secp256k1_byte_table();

    // Encontra o primeiro byte não nulo (a partir do LSB).
    int start = -1;
    for (int i = 0; i < 32; ++i) {
        if (seckey[31 - i] != 0) { start = i; break; }
    }
    if (__builtin_expect(start < 0, 0)) return false;   // seckey == 0

    const uint8_t v0 = seckey[31 - start];
    PointJ acc = PointJ::from_affine(table[start][v0].x,
                                     table[start][v0].y);

    for (int i = start + 1; i < 32; ++i) {
        const uint8_t val = seckey[31 - i];
        if (val != 0) {
            const auto& pt = table[i][val];
            acc.add_mixed(pt.x, pt.y);
        }
    }

    acc.to_affine(x_aff, y_aff);
    return true;
}

// API pública (inalterada)
inline bool secp256k1_pubkey_create_fast(uint8_t out_pub[33],
                                         const uint8_t seckey[32]) noexcept {
    Fe x_aff, y_aff;
    if (!secp256k1_ecmult_gen_affine(x_aff, y_aff, seckey)) return false;
    out_pub[0] = (y_aff[0] & 1ULL) ? 0x03 : 0x02;
    store_be256(out_pub + 1, x_aff);
    return true;
}

inline bool secp256k1_pubkey_create_fast(std::array<uint8_t, 33>& out_pub,
                                         const std::array<uint8_t, 32>& seckey) noexcept {
    return secp256k1_pubkey_create_fast(out_pub.data(), seckey.data());
}

inline bool secp256k1_pubkey_create_uncompressed(uint8_t out_pub[65],
                                                 const uint8_t seckey[32]) noexcept {
    Fe x_aff, y_aff;
    if (!secp256k1_ecmult_gen_affine(x_aff, y_aff, seckey)) return false;
    out_pub[0] = 0x04;
    store_be256(out_pub +  1, x_aff);
    store_be256(out_pub + 33, y_aff);
    return true;
}

inline bool secp256k1_pubkey_create_uncompressed(
    std::array<uint8_t, 65>& out_pub,
    const std::array<uint8_t, 32>& seckey) noexcept {
    return secp256k1_pubkey_create_uncompressed(out_pub.data(), seckey.data());
}

}  // namespace crypto
