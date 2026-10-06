#pragma once

#include <array>
#include <cstddef>

// Campo primo de secp256k1:  p = 2^256 - C,  C = 2^32 + 977 = 0x1000003D1
//
// Representação: std::array<u64,4>, little-endian, SEMPRE canônica (valor < p).
// Por isso is_zero/eq são comparações limb-a-limb simples.
//
// Decisões de desempenho:
//  - Só aritmética u128 pura (sem intrínsecos): constexpr-friendly e o GCC/Clang
//    geram mul/adc/sbb (mulx/adx com -mbmi2 -madx).
//  - Nenhum buffer em memória: produtos de 512 bits vivem em registradores
//    (loops totalmente desenrolados -> SROA).
//  - Redução pseudo-Mersenne: 2^256 ≡ C, então H·2^256 + L ≡ H·C + L.
//  - Correção final "x >= p" é um desvio quase nunca tomado (prob. ~2^-224 para
//    entradas aleatórias), em vez de um subtract+select a cada operação.
//  - add/sub/dbl são sem desvio no caso comum: o ajuste é (C & máscara).
//  - sqr usa 10 multiplicações de 64x64 em vez de 16.
struct Secp256k1Fp {
    using u64 = unsigned long long;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    using u128 = unsigned __int128;
#pragma GCC diagnostic pop

    using Element = std::array<u64, 4>;

    static constexpr std::size_t BITS = 256;
    static constexpr std::size_t LIMBS = 4;

    static constexpr u64 C = 0x1000003D1ULL;   // 2^256 mod p
    static constexpr u64 P0 = 0xFFFFFFFEFFFFFC2FULL;  // limb 0 de p (limbs 1..3 = ~0)

#define SECP_FI inline __attribute__((always_inline))

    // ------------------------------------------------------------------ consts
    static constexpr Element prime() noexcept { return {P0, ~0ULL, ~0ULL, ~0ULL}; }
    static constexpr Element zero() noexcept { return {0, 0, 0, 0}; }
    static constexpr Element one() noexcept { return {1, 0, 0, 0}; }
    static constexpr Element curve_a() noexcept { return zero(); }
    static constexpr Element curve_b() noexcept { return {7, 0, 0, 0}; }
    static constexpr bool is_a_zero() noexcept { return true; }

    // ------------------------------------------------------------- predicados
    static SECP_FI constexpr bool is_zero(const Element& a) noexcept { return (a[0] | a[1] | a[2] | a[3]) == 0; }

    static SECP_FI constexpr bool eq(const Element& a, const Element& b) noexcept {
        return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
    }

    // ------------------------------------------------- interop com UInt<4> etc.
    template <typename U>
    static constexpr Element from_uint(const U& u) noexcept {
        return {u.bits[0], u.bits[1], u.bits[2], u.bits[3]};
    }
    template <typename U>
    static constexpr U to_uint(const Element& e) noexcept {
        U u{};
        u.bits[0] = e[0];
        u.bits[1] = e[1];
        u.bits[2] = e[2];
        u.bits[3] = e[3];
        return u;
    }

   private:
    // l += C (mod 2^256). Usado quando l >= p (então o resultado é l - p).
    static SECP_FI constexpr void add_c_wrap(u64& l0, u64& l1, u64& l2, u64& l3) noexcept {
        u128 t = static_cast<u128>(l0) + C;
        l0 = static_cast<u64>(t);
        t = static_cast<u128>(l1) + static_cast<u64>(t >> 64);
        l1 = static_cast<u64>(t);
        t = static_cast<u128>(l2) + static_cast<u64>(t >> 64);
        l2 = static_cast<u64>(t);
        l3 += static_cast<u64>(t >> 64);
    }

    // Se l >= p, subtrai p (= soma C mod 2^256). Quase nunca dispara.
    static SECP_FI constexpr void cond_sub_p(u64& l0, u64& l1, u64& l2, u64& l3) noexcept {
        if ((l1 & l2 & l3) == ~0ULL && l0 >= P0) [[unlikely]]
            add_c_wrap(l0, l1, l2, l3);
    }

    // Reduz  l + c·2^256  (c < 2^34) para [0, p).
    static SECP_FI constexpr Element fold(u64 l0, u64 l1, u64 l2, u64 l3, u64 c) noexcept {
        u128 t = static_cast<u128>(c) * C + l0;
        l0 = static_cast<u64>(t);
        t = static_cast<u128>(l1) + static_cast<u64>(t >> 64);
        l1 = static_cast<u64>(t);
        t = static_cast<u128>(l2) + static_cast<u64>(t >> 64);
        l2 = static_cast<u64>(t);
        t = static_cast<u128>(l3) + static_cast<u64>(t >> 64);
        l3 = static_cast<u64>(t);
        // Carry residual k ∈ {0,1}. Se k=1, o valor restante é < 2^67, então
        // l2 = l3 = 0 e l1 é minúsculo: a soma de k·C só propaga até l1.
        const u64 k = static_cast<u64>(t >> 64);
        t = static_cast<u128>(l0) + k * C;
        l0 = static_cast<u64>(t);
        l1 += static_cast<u64>(t >> 64);
        cond_sub_p(l0, l1, l2, l3);
        return {l0, l1, l2, l3};
    }

    // Redução de um produto de 512 bits (8 limbs): L + H·C.
    static SECP_FI constexpr Element reduce_512(const std::array<u64, 8>& r) noexcept {
        u128 t = static_cast<u128>(r[4]) * C + r[0];
        const u64 l0 = static_cast<u64>(t);
        t = static_cast<u128>(r[5]) * C + r[1] + static_cast<u64>(t >> 64);
        const u64 l1 = static_cast<u64>(t);
        t = static_cast<u128>(r[6]) * C + r[2] + static_cast<u64>(t >> 64);
        const u64 l2 = static_cast<u64>(t);
        t = static_cast<u128>(r[7]) * C + r[3] + static_cast<u64>(t >> 64);
        const u64 l3 = static_cast<u64>(t);
        return fold(l0, l1, l2, l3, static_cast<u64>(t >> 64));  // c < 2^33 + 1
    }

    // Finaliza a soma de 257 bits (s + cy·2^256), com s,cy já calculados.
    static SECP_FI constexpr Element finish_add(u64 s0, u64 s1, u64 s2, u64 s3, u64 cy) noexcept {
        // Se houve carry: resultado = s + C (garantidamente < p, sem novo carry).
        const u64 add = (0ULL - cy) & C;
        u128 t = static_cast<u128>(s0) + add;
        s0 = static_cast<u64>(t);
        t = static_cast<u128>(s1) + static_cast<u64>(t >> 64);
        s1 = static_cast<u64>(t);
        t = static_cast<u128>(s2) + static_cast<u64>(t >> 64);
        s2 = static_cast<u64>(t);
        s3 += static_cast<u64>(t >> 64);
        cond_sub_p(s0, s1, s2, s3);  // caso s == p..2^256-1 sem carry
        return {s0, s1, s2, s3};
    }

   public:
    // ------------------------------------------------------------ add/sub/neg
    static SECP_FI constexpr Element add(const Element& a, const Element& b) noexcept {
        u128 t = static_cast<u128>(a[0]) + b[0];
        const u64 s0 = static_cast<u64>(t);
        t = static_cast<u128>(a[1]) + b[1] + static_cast<u64>(t >> 64);
        const u64 s1 = static_cast<u64>(t);
        t = static_cast<u128>(a[2]) + b[2] + static_cast<u64>(t >> 64);
        const u64 s2 = static_cast<u64>(t);
        t = static_cast<u128>(a[3]) + b[3] + static_cast<u64>(t >> 64);
        return finish_add(s0, s1, s2, static_cast<u64>(t), static_cast<u64>(t >> 64));
    }

    static SECP_FI constexpr Element dbl(const Element& a) noexcept {
        return finish_add(a[0] << 1, (a[1] << 1) | (a[0] >> 63), (a[2] << 1) | (a[1] >> 63),
                          (a[3] << 1) | (a[2] >> 63), a[3] >> 63);
    }

    static SECP_FI constexpr Element tpl(const Element& a) noexcept { return add(dbl(a), a); }

    static SECP_FI constexpr Element sub(const Element& a, const Element& b) noexcept {
        // d = a - b mod 2^256. Se houve borrow: d - C = a - b + p.
        u128 t = static_cast<u128>(a[0]) - b[0];
        u64 d0 = static_cast<u64>(t);
        t = static_cast<u128>(a[1]) - b[1] - (static_cast<u64>(t >> 64) & 1);
        u64 d1 = static_cast<u64>(t);
        t = static_cast<u128>(a[2]) - b[2] - (static_cast<u64>(t >> 64) & 1);
        u64 d2 = static_cast<u64>(t);
        t = static_cast<u128>(a[3]) - b[3] - (static_cast<u64>(t >> 64) & 1);
        u64 d3 = static_cast<u64>(t);
        const u64 sub_c = (0ULL - (static_cast<u64>(t >> 64) & 1)) & C;

        t = static_cast<u128>(d0) - sub_c;
        d0 = static_cast<u64>(t);
        t = static_cast<u128>(d1) - (static_cast<u64>(t >> 64) & 1);
        d1 = static_cast<u64>(t);
        t = static_cast<u128>(d2) - (static_cast<u64>(t >> 64) & 1);
        d2 = static_cast<u64>(t);
        d3 -= static_cast<u64>(t >> 64) & 1;
        return {d0, d1, d2, d3};
    }

    static SECP_FI constexpr Element neg(const Element& a) noexcept { return sub(zero(), a); }

    // a·k para k < 2^32 (k pequeno e constante: 3, 4, 8, 21, ...).
    static SECP_FI constexpr Element mul_small(const Element& a, u64 k) noexcept {
        u128 t = static_cast<u128>(a[0]) * k;
        const u64 l0 = static_cast<u64>(t);
        t = static_cast<u128>(a[1]) * k + static_cast<u64>(t >> 64);
        const u64 l1 = static_cast<u64>(t);
        t = static_cast<u128>(a[2]) * k + static_cast<u64>(t >> 64);
        const u64 l2 = static_cast<u64>(t);
        t = static_cast<u128>(a[3]) * k + static_cast<u64>(t >> 64);
        return fold(l0, l1, l2, static_cast<u64>(t), static_cast<u64>(t >> 64));  // c < 2^32
    }

    // ------------------------------------------------------------- mul / sqr
    static constexpr Element mul(const Element& a, const Element& b) noexcept {
        std::array<u64, 8> r{};
        u64 carry = 0;
#pragma GCC unroll 4
        for (int j = 0; j < 4; ++j) {
            const u128 t = static_cast<u128>(a[0]) * b[j] + carry;
            r[j] = static_cast<u64>(t);
            carry = static_cast<u64>(t >> 64);
        }
        r[4] = carry;
#pragma GCC unroll 3
        for (int i = 1; i < 4; ++i) {
            carry = 0;
#pragma GCC unroll 4
            for (int j = 0; j < 4; ++j) {
                const u128 t = static_cast<u128>(a[i]) * b[j] + r[i + j] + carry;
                r[i + j] = static_cast<u64>(t);
                carry = static_cast<u64>(t >> 64);
            }
            r[i + 4] = carry;
        }
        return reduce_512(r);
    }

    static constexpr Element sqr(const Element& a) noexcept {
        std::array<u64, 8> r{};
        // 1) produtos cruzados a[i]·a[j], i<j  (6 mults)
        u64 carry = 0;
#pragma GCC unroll 3
        for (int j = 1; j < 4; ++j) {
            const u128 t = static_cast<u128>(a[0]) * a[j] + carry;
            r[j] = static_cast<u64>(t);
            carry = static_cast<u64>(t >> 64);
        }
        r[4] = carry;
#pragma GCC unroll 2
        for (int i = 1; i < 3; ++i) {
            carry = 0;
#pragma GCC unroll 3
            for (int j = i + 1; j < 4; ++j) {
                const u128 t = static_cast<u128>(a[i]) * a[j] + r[i + j] + carry;
                r[i + j] = static_cast<u64>(t);
                carry = static_cast<u64>(t >> 64);
            }
            r[i + 4] = carry;
        }
        // 2) dobra (r[0] = 0, r[7] recebe o bit de r[6])
        r[7] = r[6] >> 63;
        r[6] = (r[6] << 1) | (r[5] >> 63);
        r[5] = (r[5] << 1) | (r[4] >> 63);
        r[4] = (r[4] << 1) | (r[3] >> 63);
        r[3] = (r[3] << 1) | (r[2] >> 63);
        r[2] = (r[2] << 1) | (r[1] >> 63);
        r[1] = r[1] << 1;
        // 3) soma os quadrados a[i]² (4 mults)
        carry = 0;
#pragma GCC unroll 4
        for (int i = 0; i < 4; ++i) {
            const u128 d = static_cast<u128>(a[i]) * a[i];
            u128 s = static_cast<u128>(r[2 * i]) + static_cast<u64>(d) + carry;
            r[2 * i] = static_cast<u64>(s);
            s = static_cast<u128>(r[2 * i + 1]) + static_cast<u64>(d >> 64) + static_cast<u64>(s >> 64);
            r[2 * i + 1] = static_cast<u64>(s);
            carry = static_cast<u64>(s >> 64);
        }
        return reduce_512(r);
    }

    // ---------------------------------------------------------------- inversão
    // a^(p-2) mod p. Cadeia de adição de 255 quadrados + 15 multiplicações.
    // inv(0) = 0.
    static constexpr Element inv(const Element& a) noexcept {
        auto sqn = [](Element x, int n) constexpr noexcept {
            for (int i = 0; i < n; ++i)
                x = sqr(x);
            return x;
        };

        Element x2 = mul(sqr(a), a);
        Element x3 = mul(sqr(x2), a);
        Element x6 = mul(sqn(x3, 3), x3);
        Element x9 = mul(sqn(x6, 3), x3);
        Element x11 = mul(sqn(x9, 2), x2);
        Element x22 = mul(sqn(x11, 11), x11);
        Element x44 = mul(sqn(x22, 22), x22);
        Element x88 = mul(sqn(x44, 44), x44);
        Element x176 = mul(sqn(x88, 88), x88);
        Element x220 = mul(sqn(x176, 44), x44);
        Element x223 = mul(sqn(x220, 3), x3);

        // Reaproveita x2 como acumulador final (x22/x3/a ainda são necessários).
        Element t = mul(sqn(x223, 23), x22);
        t = mul(sqn(t, 5), a);
        t = mul(sqn(t, 3), x2);
        return mul(sqn(t, 2), a);
    }

#undef SECP_FI
};
