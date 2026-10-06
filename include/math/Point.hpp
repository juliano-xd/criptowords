#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

enum CORD { X, Y, Z };

// Ponto em curva de Weierstrass curta y² = x³ + ax + b.
// Coordenadas Jacobianas: (X, Y, Z) ≡ (X/Z², Y/Z³); Z == 0 ⟺ ∞.
//
// Genérico sobre a política `Fp`. Contrato obrigatório:
//   typename Element                    -- indexável: e[i] -> limb u64 (escalares)
//   static constexpr size_t BITS
//   static constexpr Element zero(), one()
//   static constexpr Element add(a,b), sub(a,b), mul(a,b), sqr(a), inv(a)
//   static constexpr bool    is_zero(a), eq(a,b)
//   static constexpr Element curve_a(), curve_b()
//   static constexpr bool    is_a_zero()
//
// Opcionais (detectados via `requires`):
//   Fp::dbl(a), Fp::tpl(a), Fp::neg(a), Fp::mul_small(a, k)  (k < 2^32)
//
// Notas de implementação:
//  - Cada operação lê as entradas uma vez e só escreve x/y/z no final (ou assim
//    que a coordenada correspondente fica morta), reaproveitando temporários.
//  - operator* usa wNAF + tabela afim (1 inversão em lote) + adição mista.
//  - NÃO é tempo-constante: não use com escalares secretos.

template <typename Fp>
class alignas(32) Point {
   public:
    using Fe = typename Fp::Element;

   private:
    Fe x{}, y{}, z{};

    // --- Operações opcionais do campo --------------------------------------
    static constexpr Fe dbl_fe(const Fe& a) noexcept {
        if constexpr (requires { Fp::dbl(a); })
            return Fp::dbl(a);
        else
            return Fp::add(a, a);
    }
    static constexpr Fe tpl_fe(const Fe& a) noexcept {
        if constexpr (requires { Fp::tpl(a); })
            return Fp::tpl(a);
        else
            return Fp::add(dbl_fe(a), a);
    }
    static constexpr Fe neg_fe(const Fe& a) noexcept {
        if constexpr (requires { Fp::neg(a); })
            return Fp::neg(a);
        else
            return Fp::sub(Fp::zero(), a);
    }
    static constexpr Fe mul8_fe(const Fe& a) noexcept {
        if constexpr (requires { Fp::mul_small(a, 8ULL); }) {
            return Fp::mul_small(a, 8ULL);
        } else {
            Fe t = dbl_fe(a);
            t = dbl_fe(t);
            return dbl_fe(t);
        }
    }

    // --- Núcleos de adição (NegY: soma -q / -(x2,y2) sem criar cópia) -------
    template <bool NegY>
    [[gnu::flatten]]
    constexpr Point& add_impl(const Point& q) noexcept;

    template <bool NegY>
    [[gnu::flatten]]
    constexpr Point& add_mixed_impl(const Fe& x2, const Fe& y2) noexcept;

    // --- Auxiliares do wNAF -------------------------------------------------
    static constexpr std::size_t LIMBS = (Fp::BITS + 63) / 64;

    /// n bits (n <= 8) de k a partir de `pos`; zeros acima de BITS.
    static constexpr unsigned get_bits(const Fe& k, std::size_t pos, unsigned n) noexcept {
        const std::size_t limb = pos >> 6;
        const unsigned off = static_cast<unsigned>(pos & 63);
        if (limb >= LIMBS)
            return 0;
        unsigned long long v = k[limb] >> off;
        if (off + n > 64 && limb + 1 < LIMBS)
            v |= static_cast<unsigned long long>(k[limb + 1]) << (64 - off);
        return static_cast<unsigned>(v & ((1ULL << n) - 1));
    }

   public:
    // ========== Construção ==============================================
    constexpr Point() noexcept = default;

    constexpr Point(const Fe& x_, const Fe& y_, const Fe& z_) noexcept : x(x_), y(y_), z(z_) {}

    /// Ponto afim (Z = 1).
    static constexpr Point from_affine(const Fe& x_, const Fe& y_) noexcept { return Point{x_, y_, Fp::one()}; }

    static constexpr Point infinity() noexcept { return Point{}; }

    /// Acesso à coordenada (X, Y, Z).
    [[nodiscard]] constexpr const Fe& operator[](CORD c) const noexcept {
        switch (c) {
            case X:
                return x;
            case Y:
                return y;
            case Z:
                return z;
        }
        __builtin_unreachable();
    }

    // ========== Predicados ==============================================
    [[nodiscard]] constexpr bool is_infinity() const noexcept { return Fp::is_zero(z); }

    [[nodiscard]] constexpr bool is_affine() const noexcept { return Fp::eq(z, Fp::one()); }

    /// Valida y² = x³ + ax + b (Jacobiana: y² = x³ + a·x·z⁴ + b·z⁶).
    [[nodiscard]] constexpr bool is_on_curve() const noexcept {
        if (is_infinity())
            return true;

        const Fe lhs = Fp::sqr(y);
        Fe rhs = Fp::mul(Fp::sqr(x), x);  // x³

        if (Fp::eq(z, Fp::one())) {  // fast-path afim
            if constexpr (!Fp::is_a_zero())
                rhs = Fp::add(rhs, Fp::mul(Fp::curve_a(), x));
            rhs = Fp::add(rhs, Fp::curve_b());
        } else {
            Fe t = Fp::sqr(z);  // z²
            t = Fp::sqr(t);     // z⁴
            if constexpr (!Fp::is_a_zero())
                rhs = Fp::add(rhs, Fp::mul(Fp::mul(Fp::curve_a(), x), t));
            t = Fp::mul(t, Fp::sqr(z));  // z⁶
            rhs = Fp::add(rhs, Fp::mul(Fp::curve_b(), t));
        }
        return Fp::eq(lhs, rhs);
    }

    // ========== Negação ==================================================
    [[nodiscard]] constexpr Point operator-() const noexcept {
        if (is_infinity()) [[unlikely]]
            return *this;
        return Point{x, neg_fe(y), z};
    }

    // ========== Duplicação in-place: *this = 2·*this =====================
    /// dbl-2009-l (2M + 5S para a = 0). z e y são sobrescritos assim que ficam
    /// mortos; x só no final.
    [[gnu::flatten]]
    constexpr Point& dbl_inplace() noexcept {
        if (is_infinity() || Fp::is_zero(y)) [[unlikely]] {
            z = Fp::zero();
            return *this;
        }

        Fe e = Fp::sqr(x);  // A = X²
        Fe a = e;           // guarda A
        e = tpl_fe(e);      // E = 3A
        if constexpr (!Fp::is_a_zero()) {
            Fe t = Fp::sqr(z);
            t = Fp::sqr(t);  // Z⁴
            e = Fp::add(e, Fp::mul(Fp::curve_a(), t));
        }

        Fe b = Fp::sqr(y);  // B = Y²
        z = Fp::mul(dbl_fe(y), z);  // Z3 = 2YZ (y e z antigos mortos)

        Fe c = Fp::sqr(b);  // C = B²
        b = Fp::add(x, b);
        b = Fp::sqr(b);
        b = Fp::sub(b, a);
        b = Fp::sub(b, c);  // b = 2·X·Y²
        b = dbl_fe(b);      // D = 4·X·Y²

        x = Fp::sqr(e);
        x = Fp::sub(x, dbl_fe(b));  // X3 = E² - 2D

        a = Fp::sub(b, x);          // reutiliza a: D - X3
        y = Fp::mul(a, e);          // E·(D - X3)
        y = Fp::sub(y, mul8_fe(c)); // Y3 = E·(D - X3) - 8C
        return *this;
    }

    [[nodiscard]] constexpr Point doubled() const noexcept {
        Point r = *this;
        r.dbl_inplace();
        return r;
    }

    // ========== Adição in-place: *this += q ==============================
    constexpr Point& add_inplace(const Point& q) noexcept { return add_impl<false>(q); }
    constexpr Point& sub_inplace(const Point& q) noexcept { return add_impl<true>(q); }

    [[nodiscard]] constexpr Point operator+(const Point& q) const noexcept {
        Point r = *this;
        r.add_inplace(q);
        return r;
    }
    [[nodiscard]] constexpr Point operator-(const Point& q) const noexcept {
        Point r = *this;
        r.sub_inplace(q);
        return r;
    }
    constexpr Point& operator+=(const Point& q) noexcept { return add_inplace(q); }
    constexpr Point& operator-=(const Point& q) noexcept { return sub_inplace(q); }

    // ========== Adição mista in-place: *this += (x2, y2) afim ============
    /// madd-2007-bl (variante 8M + 3S): evita Z2 e todas as multiplicações por ele.
    constexpr Point& add_mixed(const Fe& x2, const Fe& y2) noexcept { return add_mixed_impl<false>(x2, y2); }
    constexpr Point& sub_mixed(const Fe& x2, const Fe& y2) noexcept { return add_mixed_impl<true>(x2, y2); }

    // ========== Multiplicação escalar: k·*this ===========================
    /// wNAF de largura W (dígitos ímpares em (-2^(W-1), 2^(W-1))).
    /// Pré-computa P,3P,5P,... em afim (1 inversão em lote) e usa adição mista.
    template <unsigned W = 4>
    [[nodiscard]]
    constexpr Point mul_wnaf(const Fe& k) const noexcept {
        static_assert(W >= 2 && W <= 7, "W deve estar em [2, 7] (dígitos cabem em int8_t)");
        constexpr std::size_t TAB = std::size_t{1} << (W - 2);
        constexpr std::size_t LEN = Fp::BITS + 1;  // +1 absorve o carry final

        if (is_infinity())
            return Point{};

        // --- 1) recodificação wNAF (esparsa: ~1 dígito não-nulo a cada W+1 bits)
        std::array<std::int8_t, LEN> naf{};
        int hi = -1;
        {
            std::size_t bit = 0;
            unsigned carry = 0;
            while (bit < LEN) {
                if (get_bits(k, bit, 1) == carry) {  // (bit + carry) par -> dígito 0
                    ++bit;
                    continue;
                }
                unsigned now = W;
                if (now > LEN - bit)
                    now = static_cast<unsigned>(LEN - bit);
                unsigned word = get_bits(k, bit, now) + carry;
                carry = (word >> (W - 1)) & 1u;
                naf[bit] = static_cast<std::int8_t>(static_cast<int>(word) - static_cast<int>(carry << W));
                hi = static_cast<int>(bit);
                bit += now;
            }
        }
        if (hi < 0)
            return Point{};

        // --- 2) tabela de múltiplos ímpares, normalizada para afim
        std::array<Point, TAB> tab{};
        tab[0] = *this;
        if constexpr (TAB > 1) {
            const Point d2 = doubled();
            for (std::size_t i = 1; i < TAB; ++i) {
                tab[i] = tab[i - 1];
                tab[i].add_inplace(d2);
            }
        }
        std::array<Fe, TAB> scratch;
        batch_normalize(tab.data(), TAB, scratch.data());

        // --- 3) laço principal
        auto idx = [](int d) constexpr noexcept { return static_cast<std::size_t>(((d < 0 ? -d : d) - 1) >> 1); };

        Point r;
        {
            const int d = naf[hi];
            const Point& t = tab[idx(d)];
            r = (d > 0) ? t : -t;
        }
        for (int i = hi - 1; i >= 0; --i) {
            r.dbl_inplace();
            const int d = naf[i];
            if (d == 0)
                continue;
            const Point& t = tab[idx(d)];
            if (t.is_infinity()) [[unlikely]]  // só em curvas com pontos de ordem pequena
                continue;
            if (d > 0)
                r.add_mixed(t.x, t.y);
            else
                r.sub_mixed(t.x, t.y);
        }
        return r;
    }

    [[nodiscard]] constexpr Point operator*(const Fe& k) const noexcept { return mul_wnaf<4>(k); }

    friend constexpr Point operator*(const Fe& k, const Point& p) noexcept { return p * k; }

    // ========== Igualdade ================================================
    /// Sem inversão: fast-path afim, senão multiplicação cruzada.
    [[nodiscard]] constexpr bool operator==(const Point& q) const noexcept {
        const bool inf1 = is_infinity(), inf2 = q.is_infinity();
        if (inf1 || inf2)
            return inf1 && inf2;
        if (Fp::eq(z, q.z)) {  // mesmo Z (inclui o caso afim): compara direto
            return Fp::eq(x, q.x) && Fp::eq(y, q.y);
        }

        Fe a = Fp::sqr(z);    // Z1²
        Fe b = Fp::sqr(q.z);  // Z2²
        if (!Fp::eq(Fp::mul(x, b), Fp::mul(q.x, a)))
            return false;
        a = Fp::mul(a, z);    // Z1³
        b = Fp::mul(b, q.z);  // Z2³
        return Fp::eq(Fp::mul(y, b), Fp::mul(q.y, a));
    }
    [[nodiscard]] constexpr bool operator!=(const Point& q) const noexcept { return !(*this == q); }

    // ========== Conversão para afim ======================================
    /// Escreve x, y afins. Retorna (0, 0) se ∞.
    constexpr void to_affine(Fe& out_x, Fe& out_y) const noexcept {
        if (is_infinity()) {
            out_x = Fp::zero();
            out_y = Fp::zero();
            return;
        }
        if (Fp::eq(z, Fp::one())) {
            out_x = x;
            out_y = y;
            return;
        }

        const Fe zi = Fp::inv(z);
        Fe t = Fp::sqr(zi);  // zi²
        const Fe rx = Fp::mul(x, t);
        t = Fp::mul(t, zi);  // zi³
        out_y = Fp::mul(y, t);
        out_x = rx;
    }

    [[nodiscard]] constexpr std::pair<Fe, Fe> to_affine() const noexcept {
        std::pair<Fe, Fe> r;
        to_affine(r.first, r.second);
        return r;
    }

    // ========== Normalização em lote =====================================
    /// Truque de Montgomery: 1 inversão + ~5n multiplicações em vez de n inversões.
    /// `scratch` deve ter capacidade para `n` elementos. Pontos no ∞ são ignorados.
    static constexpr void batch_normalize(Point* pts, std::size_t n, Fe* scratch) noexcept {
        if (n == 0)
            return;

        Fe acc = Fp::one();
        for (std::size_t i = 0; i < n; ++i) {
            scratch[i] = acc;
            if (!pts[i].is_infinity())
                acc = Fp::mul(acc, pts[i].z);
        }

        acc = Fp::inv(acc);  // acc passa a ser o inverso do produto restante

        for (std::size_t i = n; i-- > 0;) {
            Point& p = pts[i];
            if (p.is_infinity())
                continue;
            Fe t = Fp::mul(acc, scratch[i]);  // z⁻¹
            acc = Fp::mul(acc, p.z);          // remove z_i do inverso acumulado
            scratch[i] = Fp::sqr(t);          // z⁻²  (scratch[i] já foi consumido)
            p.x = Fp::mul(p.x, scratch[i]);
            t = Fp::mul(t, scratch[i]);       // z⁻³
            p.y = Fp::mul(p.y, t);
            p.z = Fp::one();
        }
    }
};

// add_impl: add-1998-cmo-2 (12M + 4S) com reuso máximo de temporários.
// Nada de *this é escrito antes de todos os desvios de saída antecipada.
template <typename Fp>
template <bool NegY>
[[gnu::flatten]]
constexpr Point<Fp>& Point<Fp>::add_impl(const Point& q) noexcept {
    if (is_infinity()) {
        x = q.x;
        y = NegY ? neg_fe(q.y) : q.y;
        z = q.z;
        return *this;
    }
    if (q.is_infinity())
        return *this;

    Fe a = Fp::sqr(z);    // Z1²
    Fe b = Fp::sqr(q.z);  // Z2²
    Fe u1 = Fp::mul(x, b);
    Fe h = Fp::mul(q.x, a);  // U2
    b = Fp::mul(b, q.z);     // Z2³
    Fe s1 = Fp::mul(y, b);   // S1
    a = Fp::mul(a, z);       // Z1³
    Fe r = Fp::mul(NegY ? neg_fe(q.y) : q.y, a);  // S2

    h = Fp::sub(h, u1);  // H = U2 - U1
    r = Fp::sub(r, s1);  // R = S2 - S1

    if (Fp::is_zero(h)) [[unlikely]] {
        if (Fp::is_zero(r))
            return dbl_inplace();
        z = Fp::zero();
        return *this;
    }

    z = Fp::mul(Fp::mul(z, q.z), h);  // Z3 = Z1·Z2·H

    a = Fp::sqr(h);       // H²
    h = Fp::mul(h, a);    // H³
    u1 = Fp::mul(u1, a);  // V = U1·H²

    x = Fp::sqr(r);
    x = Fp::sub(x, h);
    x = Fp::sub(x, dbl_fe(u1));  // X3 = R² - H³ - 2V

    u1 = Fp::sub(u1, x);
    u1 = Fp::mul(u1, r);
    s1 = Fp::mul(s1, h);
    y = Fp::sub(u1, s1);  // Y3 = R·(V - X3) - S1·H³
    return *this;
}

// add_mixed_impl: Z2 = 1 (8M + 3S).
template <typename Fp>
template <bool NegY>
[[gnu::flatten]]
constexpr Point<Fp>& Point<Fp>::add_mixed_impl(const Fe& x2, const Fe& y2) noexcept {
    if (is_infinity()) {
        x = x2;
        y = NegY ? neg_fe(y2) : y2;
        z = Fp::one();
        return *this;
    }

    Fe a = Fp::sqr(z);      // Z1²
    Fe h = Fp::mul(x2, a);  // U2
    a = Fp::mul(a, z);      // Z1³
    Fe r = Fp::mul(NegY ? neg_fe(y2) : y2, a);  // S2

    h = Fp::sub(h, x);  // H = U2 - X1
    r = Fp::sub(r, y);  // R = S2 - Y1

    if (Fp::is_zero(h)) [[unlikely]] {
        if (Fp::is_zero(r))
            return dbl_inplace();
        z = Fp::zero();
        return *this;
    }

    z = Fp::mul(z, h);  // Z3 = Z1·H

    a = Fp::sqr(h);     // H²
    h = Fp::mul(h, a);  // H³
    a = Fp::mul(a, x);  // U1·H²

    x = Fp::sqr(r);
    x = Fp::sub(x, h);
    x = Fp::sub(x, dbl_fe(a));  // X3 = R² - H³ - 2·U1·H²

    a = Fp::sub(a, x);
    a = Fp::mul(a, r);
    y = Fp::sub(a, Fp::mul(y, h));  // Y3 = R·(U1·H² - X3) - Y1·H³
    return *this;
}
