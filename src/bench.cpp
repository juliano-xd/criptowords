#include "../include/math/UInt.hpp"
#include "../include/crypto/secp256k1_point.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <print>

#if defined(__x86_64__)
    #include <x86intrin.h>
#else
    #error "Este benchmark requer x86-64"
#endif

using u8 = std::uint8_t;

int main(int argc, char** argv) {
    int failures = 0;
    int section = 0;
    auto check = [&](bool cond, const char* name) {
        if (cond) {
            std::println("[PASS] {}", name);
        } else {
            std::println("[FAIL] {}", name);
            ++failures;
        }
    };

    try {

    std::println("--- Running UInt tests ---");

    // ============================================================
    // 1. INITIALIZATION FROM BYTE ARRAY (LSB BitOrder)
    // ============================================================
    {
        u8 d[8] = {12, 34, 56, 78, 90, 100, 110, 120};
        UInt<2> a(d, BitOrder::LSB);
        check(a.bits[0] == 0x786E645A4E38220CULL && a.bits[1] == 0,
              "LSB byte array init (8 bytes -> 2 limbs)");
    }

    // ============================================================
    // 2. INITIALIZATION FROM u64
    // ============================================================
    {
        UInt<2> x(0x1122334455667788ULL);
        check(x.bits[0] == 0x1122334455667788ULL && x.bits[1] == 0, "u64 init LSB");
    }

    // ============================================================
    // 3. ENDIANNESS SWITCHING
    // ============================================================
    {
        UInt<2> x(0x1122334455667788ULL);
        x.set_endianness(Endianness::big);
        check(x.endianness() == Endianness::big, "endianness getter");
        check(x.bits[1] == 0x1122334455667788ULL && x.bits[0] == 0,
              "endianness big: u64 at MSW limb");

        x.set_endianness(Endianness::little);
        check(x.endianness() == Endianness::little, "endianness back to little");
        check(x.bits[0] == 0x1122334455667788ULL && x.bits[1] == 0,
              "endianness back: u64 at LSW limb");
    }

    // ============================================================
    // 4. MULTI-LIMB ENDIANNESS SWAP
    // ============================================================
    {
        UInt<3> y;
        y.bits[0] = 0xAAA;
        y.bits[1] = 0xBBB;
        y.bits[2] = 0xCCC;
        y.set_endianness(Endianness::big);
        check(y.bits[0] == 0xCCC && y.bits[1] == 0xBBB && y.bits[2] == 0xAAA,
              "3-limb endianness swap");
        y.set_endianness(Endianness::little);
        check(y.bits[0] == 0xAAA && y.bits[1] == 0xBBB && y.bits[2] == 0xCCC,
              "3-limb endianness swap back");
    }

    // ============================================================
    // 5. SCALAR MODE ARITHMETIC (default)
    // ============================================================
    {
        UInt<2> a(0xFFFFFFFFFFFFFFFFULL);
        UInt<2> b(1ULL);
        a.set_mode(Backend::Scalar);
        a += b;
        check(a.bits[0] == 0 && a.bits[1] == 1, "scalar add with carry across limbs");
    }

    // ============================================================
    // 6. SIMD MODE ARITHMETIC (no carry)
    // ============================================================
    {
        UInt<2> a(0xFFFFFFFFFFFFFFFFULL);
        a.set_mode(Backend::SIMD);
        a += UInt<2>(1ULL);
        check(a.bits[0] == 0 && a.bits[1] == 0, "SIMD add wrap (no carry)");
    }

    // ============================================================
    // 7. MODE SWITCHING AT RUNTIME
    // ============================================================
    {
        UInt<2> a(0xFFFFFFFFFFFFFFFFULL);
        UInt<2> b(1ULL);
        a.set_mode(Backend::Scalar);
        a += b;
        check(a.bits[0] == 0 && a.bits[1] == 1, "scalar add: a=(0,1)");

        a.set_mode(Backend::SIMD);
        UInt<2> c(1ULL);
        a += c;
        check(a.bits[0] == 1 && a.bits[1] == 1, "switch to SIMD mid-operation");
    }

    // ============================================================
    // 8. MULTIPLICATION IN SCALAR vs SIMD
    // ============================================================
    {
        UInt<2> a(3ULL), b(5ULL);
        a.set_mode(Backend::Scalar);
        a *= b;
        check(a.bits[0] == 15, "scalar multiply small");

        UInt<2> c(3ULL);
        c.set_mode(Backend::SIMD);
        c *= UInt<2>(5ULL);
        check(c.bits[0] == 15, "SIMD multiply small");
    }

    // ============================================================
    // 9. SUBTRACTION WITH BORROW (scalar)
    // ============================================================
    {
        UInt<2> a(1ULL), b(1ULL);
        a.set_mode(Backend::Scalar);
        a -= b;
        check(a.bits[0] == 0 && a.bits[1] == 0, "scalar sub result zero");

        UInt<2> d(0ULL);
        d.bits[1] = 1;
        d -= UInt<2>(1ULL);
        check(d.bits[0] == (u64)(-1) && d.bits[1] == 0, "scalar sub with borrow");
    }

    // ============================================================
    // 10. TRUNCATION: UInt<N> -> UInt<M> (M < N)
    // ============================================================
    {
        UInt<4> big;
        big.bits[0] = 0x1111111111111111ULL;
        big.bits[1] = 0x2222222222222222ULL;
        big.bits[2] = 0x3333333333333333ULL;
        big.bits[3] = 0x4444444444444444ULL;

        UInt<2> small = big.truncate<2>();
        check(small.bits[0] == 0x1111111111111111ULL && small.bits[1] == 0x2222222222222222ULL,
              "truncate 4->2");
    }

    // ============================================================
    // 11. TRUNCATION VIA CONSTRUCTION FROM LARGER UInt
    // ============================================================
    {
        UInt<4> big;
        big.bits[0] = 0xAAAA;
        big.bits[1] = 0xBBBB;
        big.bits[2] = 0xCCCC;
        big.bits[3] = 0xDDDD;

        UInt<2> small(big);
        check(small.bits[0] == 0xAAAA && small.bits[1] == 0xBBBB,
              "constructor from larger UInt");
    }

    // ============================================================
    // 12. ASSIGNMENT FROM SMALLER UInt TO BIGGER UInt
    // ============================================================
    {
        UInt<2> small;
        small.bits[0] = 0xF0F0;
        small.bits[1] = 0xF1F1;

        UInt<4> big;
        big = small;
        check(big.bits[0] == 0xF0F0 && big.bits[1] == 0xF1F1 &&
              big.bits[2] == 0 && big.bits[3] == 0,
              "assign smaller to bigger UInt");
    }

    // ============================================================
    // 13. ENDIANNESS + BYTE ARRAY INTERACTION
    // ============================================================
    {
        u8 bytes[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        UInt<2> le(bytes, BitOrder::LSB);
        check(le.bits[0] == 1 && le.bits[1] == 0, "LSB byte order: byte 0 -> limb 0");

        UInt<2> be(bytes, BitOrder::MSB);
        check(be.bits[0] == 0 && be.bits[1] == 0x0100000000000000ULL,
              "MSB byte order: byte 0 -> MSW limb");
    }

    // ============================================================
    // 14. COMPARISON OPERATORS
    // ============================================================
    {
        UInt<2> a(10ULL), b(20ULL);
        check((a < b) && !(a > b) && (a != b), "comparison 10 < 20");
        check((b > a) && !(b < a) && (b != a), "comparison 20 > 10");
        check(a <= b && b >= a, "<= and >= ");

        UInt<2> c(10ULL);
        check(a == c && !(a != c), "equality 10 == 10");
    }

    // ============================================================
    // 15. SHIFT OPERATIONS (scalar)
    // ============================================================
    {
        UInt<2> a(1ULL);
        a <<= 64;
        check(a.bits[0] == 0 && a.bits[1] == 1, "scalar << 64");

        UInt<2> b(0ULL);
        b.bits[1] = 1;
        b >>= 64;
        check(b.bits[0] == 1 && b.bits[1] == 0, "scalar >> 64");
    }

    // ============================================================
    // 16. SHIFT OPERATIONS (SIMD)
    // ============================================================
    {
        UInt<2> a(1ULL);
        a.set_mode(Backend::SIMD);
        a <<= 64;
        check(a.bits[0] == 0 && a.bits[1] == 0, "SIMD << 64 (no cross-limb)");

        UInt<2> b(1ULL);
        b.set_mode(Backend::SIMD);
        b <<= 1;
        check(b.bits[0] == 2 && b.bits[1] == 0, "SIMD << 1");
    }

    // ============================================================
    // 17. BIT OPERATIONS
    // ============================================================
    {
        UInt<2> a(0xF0F0F0F0F0F0F0F0ULL);
        UInt<2> b(0x0F0F0F0F0F0F0F0FULL);
        a &= b;
        check(a.bits[0] == 0x0000000000000000ULL, "AND: F0F0 & 0F0F = 0");

        UInt<2> c(0xF0F0F0F0F0F0F0F0ULL);
        c |= b;
        check(c.bits[0] == 0xFFFFFFFFFFFFFFFFULL, "OR: F0F0 | 0F0F = FFFF");

        UInt<2> d(0xAAAA);
        d = ~d;
        check(d.bits[0] == ~0xAAAAULL, "NOT operation");
    }

    // ============================================================
    // 18. ARITHMETIC OPERATORS (global)
    // ============================================================
    {
        UInt<2> a(100ULL), b(30ULL);
        UInt<2> c = a + b;
        check(c.bits[0] == 130, "global +");

        UInt<2> d = a - b;
        check(d.bits[0] == 70, "global -");

        UInt<2> e(5ULL), f(3ULL);
        UInt<2> g = e * f;
        check(g.bits[0] == 15, "global *");

        UInt<2> h(100ULL), i(10ULL);
        UInt<2> j = h / i;
        check(j.bits[0] == 10, "global /");

        UInt<2> k(107ULL), l(10ULL);
        UInt<2> m = k % l;
        check(m.bits[0] == 7, "global %");
    }

    // ============================================================
    // 19. STRING CONSTRUCTION
    // ============================================================
    {
        UInt<2> hex("0x1234567890ABCDEF");
        check(hex.bits[0] == 0x1234567890ABCDEFULL && hex.bits[1] == 0,
              "hex string init (fits in 1 limb)");

        UInt<2> dec("100");
        check(dec.bits[0] == 100, "decimal string init");
    }

    // ============================================================
    // 20. TO STRING / TO HEX
    // ============================================================
    {
        UInt<2> x(0x1122334455667788ULL);
        auto hs = x.to_hex_string();
        check(!hs.empty() && hs.find("1122334455667788") != std::string::npos,
              "to_hex_string");

        auto s = x.to_string();
        check(s == "1234605616436508552", "to_string value check");
    }

    // ============================================================
    // 21. EQZ AND NUM_LIMBS
    // ============================================================
    {
        UInt<2> zero;
        check(zero.eqz() && zero.num_limbs() == 0, "zero detection");

        UInt<2> nz(42ULL);
        check(!nz.eqz() && nz.num_limbs() == 1, "non-zero detection");
    }

    // ============================================================
    // 22. RANDOM
    // ============================================================
    {
        auto r1 = UInt<2>::random(42);
        auto r2 = UInt<2>::random(42);
        check(r1.bits == r2.bits, "random deterministic");
    }

    // ============================================================
    // 23. DIVISION (scalar)
    // ============================================================
    {
        UInt<2> a(100ULL), b(7ULL);
        a.set_mode(Backend::Scalar);
        auto [q, r] = a.divmod(b);
        check(q.bits[0] == 14 && r.bits[0] == 2, "scalar divmod 100/7");
    }

    // ============================================================
    // 24. DIVISION SIMD (element-wise)
    // ============================================================
    {
        try {
            UInt<2> a(100ULL, 1ULL);
            UInt<2> b(7ULL, 3ULL);
            a.set_mode(Backend::SIMD);
            b.set_mode(Backend::SIMD);
            std::println("before divmod, a.bits[0]={}, b.bits[0]={}", a.bits[0], b.bits[0]);
            auto [q, r] = a.divmod(b);
            std::println("after divmod");
            check(q.bits[0] == 14 && q.bits[1] == 0 && r.bits[0] == 2 && r.bits[1] == 1,
                  "SIMD divmod element-wise");
        } catch (const std::exception& e) {
            std::println("EXCEPTION in SIMD divmod: {}", e.what());
            throw;
        }
    }

    // ============================================================
    // 25. COPY / MOVE SEMANTICS
    // ============================================================
    {
        UInt<2> original(42ULL);
        UInt<2> copy(original);
        check(copy.bits[0] == 42, "copy constructor");

        UInt<2> moved(std::move(copy));
        check(moved.bits[0] == 42, "move constructor");

        UInt<2> assigned;
        assigned = std::move(moved);
        check(assigned.bits[0] == 42, "move assignment");
    }

    // ============================================================
    // 26. INCREMENT / DECREMENT
    // ============================================================
    {
        UInt<2> a(5ULL);
        ++a;
        check(a.bits[0] == 6, "pre-increment");

        UInt<2> b(5ULL);
        b++;
        check(b.bits[0] == 6, "post-increment");

        UInt<2> c(5ULL);
        --c;
        check(c.bits[0] == 4, "pre-decrement");

        UInt<2> d(5ULL);
        d--;
        check(d.bits[0] == 4, "post-decrement");
    }

    // ============================================================
    // 27. SET_MODE GETTER CONSISTENCY
    // ============================================================
    {
        UInt<2> x;
        check(x.is_scalar() && !x.is_simd(), "default is scalar");
        x.set_mode(Backend::SIMD);
        check(!x.is_scalar() && x.is_simd(), "after set_mode SIMD");
    }

    // ============================================================
    // 28. VARIADIC CONSTRUCTOR
    // ============================================================
    {
        UInt<3> x(0x1111ULL, 0x2222ULL, 0x3333ULL);
        check(x.bits[0] == 0x1111 && x.bits[1] == 0x2222 && x.bits[2] == 0x3333,
              "variadic constructor");
    }

    // ============================================================
    // 29. CONSTEXPR COMPARISON
    // ============================================================
    {
        constexpr UInt<2> a(10ULL);
        constexpr UInt<2> b(20ULL);
        static_assert(a < b, "constexpr comparison");
        static_assert(a != b, "constexpr inequality");
    }

    // ============================================================
    // 30. ENDIANNESS PRESERVES VALUE
    // ============================================================
    {
        UInt<2> x(12345ULL);
        Endianness orig = x.endianness();
        x.set_endianness(Endianness::big);
        x.set_endianness(Endianness::little);
        check(x.bits[0] == 12345ULL, "round-trip endianness preserves value");
    }

    // ============================================================
    // 31. HEX STRING WITH MULTIPLE LIMBS
    // ============================================================
    {
        UInt<2> x("0x11111111111111112222222222222222");
        check(x.bits[0] == 0x2222222222222222ULL && x.bits[1] == 0x1111111111111111ULL,
              "hex string 2 limbs");
        auto hs = x.to_hex_string();
        check(hs.find("2222222222222222") != std::string::npos &&
              hs.find("1111111111111111") != std::string::npos,
              "to_hex_string multi-limb");
    }

    // ============================================================
    // 32. BIG STRING CONSTRUCTION
    // ============================================================
    {
        UInt<4> big("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        check(big.bits[0] == 0xFFFFFFFFFFFFFFFFULL &&
              big.bits[1] == 0xFFFFFFFFFFFFFFFFULL &&
              big.bits[2] == 0 && big.bits[3] == 0,
              "big hex string 4 limbs (32 hex chars = 2 limbs)");
    }

    // ============================================================
    // 33. ADD_CARRY AND SUB_BORROW
    // ============================================================
    {
        UInt<2> a(0xFFFFFFFFFFFFFFFFULL);
        a.bits[1] = 0xFFFFFFFFFFFFFFFFULL;
        UInt<2> b(1ULL);
        uint8_t c = a.add_carry(b);
        check(c == 1 && a.bits[0] == 0 && a.bits[1] == 0, "add_carry with overflow flag");

        UInt<2> zero;
        uint8_t borrow = zero.sub_borrow(b);
        check(borrow == 1 && zero.bits[0] == 0xFFFFFFFFFFFFFFFFULL && zero.bits[1] == 0xFFFFFFFFFFFFFFFFULL,
              "sub_borrow with borrow flag");
    }

    // ============================================================
    // 34. SINGLE-LIMB DIVMOD(U64)
    // ============================================================
    {
        UInt<2> val;
        val.bits[0] = 1000;
        val.bits[1] = 5;
        auto [q, rem] = val.divmod(58ULL);
        // Verify q * 58 + rem == val:
        UInt<2> back = q;
        back *= 58ULL;
        back += rem;
        check(back == val && rem < 58, "single-limb divmod(58ULL) correctness");
    }

    // ============================================================
    // 35. SQUARED ARITHMETIC (square and square_wide)
    // ============================================================
    {
        UInt<4> a("0xDEADBEEFCAFE1234567890ABCDEF112233445566778899AABBCCDDEEFF001122");
        UInt<4> sq_trunc = a.square();
        UInt<4> mul_trunc = a * a;
        check(sq_trunc == mul_trunc, "truncated square() matches a * a for UInt<4>");

        UInt<8> sq_wide = a.square_wide();
        UInt<8> a_ext(a);
        UInt<8> mul_wide = a_ext * a_ext;
        check(sq_wide == mul_wide, "square_wide() matches wide a * a for UInt<4> -> UInt<8>");
    }

    // ============================================================
    // 36. VECTORIZED EQZ & COMPARISON ACROSS N
    // ============================================================
    {
        UInt<4> z4;
        check(z4.eqz(), "UInt<4> zero eqz");
        z4.bits[3] = 1;
        check(!z4.eqz(), "UInt<4> high limb non-zero eqz");

        UInt<8> z8;
        check(z8.eqz(), "UInt<8> zero eqz");
        z8.bits[7] = 1;
        check(!z8.eqz(), "UInt<8> high limb non-zero eqz");

        UInt<4> c1(100ULL), c2(200ULL);
        check(c1 < c2 && c2 > c1 && !(c1 == c2), "UInt<4> three-way comparison");
    }

    // ============================================================
    // 37. SINGLE-PASS BIT SHIFTS
    // ============================================================
    {
        UInt<4> x("0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        UInt<4> shl = x;
        shl <<= 65; // 1 limb + 1 bit
        UInt<4> shr = shl;
        shr >>= 65;
        UInt<4> mask;
        mask.bits[0] = ~0ULL;
        mask.bits[1] = ~0ULL;
        mask.bits[2] = 0x7FFFFFFFFFFFFFFFULL;
        mask.bits[3] = 0ULL;
        check(shl != x && shr == (x & mask), "single-pass bit shifts boundary check");
    }

    // ============================================================
    // 38. SECP256K1 POINT MATH & MODULAR INVERSION
    // ============================================================
    {
        std::array<uint8_t, 32> seckey = {};
        seckey[31] = 1;
        std::array<uint8_t, 33> pub_fast;
        check(crypto::secp256k1_pubkey_create_fast(pub_fast, seckey), "pubkey_create_fast G");
        check(pub_fast[0] == 0x02 && pub_fast[1] == 0x79 && pub_fast[2] == 0xbe, "pubkey G matches known coordinates");

        UInt<4> a("0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF");
        UInt<4> inv_a = crypto::inv_mod_p(a);
        UInt<4> one = crypto::mul_mod_p(a, inv_a);
        check(one == UInt<4>(1), "inv_mod_p mathematical exactness (a * inv(a) == 1 mod p)");
    }

    // ============================================================
    // 39. NATIVE BIG-ENDIAN INITIALIZATION & TO_BYTES
    // ============================================================
    {
        std::array<uint8_t, 32> be_bytes = {};
        be_bytes[31] = 0x42;
        be_bytes[0]  = 0x01;
        // Big endian: byte 0 is MSB (bits[3]), byte 31 is LSB (bits[0])
        UInt<4> u_be(be_bytes, Endianness::big);
        check((u_be.bits[0] & 0xFF) == 0x42, "UInt(arr, Endianness::big) LSB matches");
        check((u_be.bits[3] >> 56) == 0x01,  "UInt(arr, Endianness::big) MSB matches");

        auto exported = u_be.to_bytes(Endianness::big);
        check(exported == be_bytes, "u_be.to_bytes(Endianness::big) round-trip exact");

        std::array<uint8_t, 32> out_buf = {};
        u_be.to_bytes(out_buf, Endianness::big);
        check(out_buf == be_bytes, "u_be.to_bytes(out_buf, Endianness::big) exact");

        // Factory and helper methods
        auto u_from_be = UInt<4>::from_be(be_bytes);
        check(u_from_be == u_be, "UInt::from_be matches UInt constructor");
    }

    std::println("{}", failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::println("EXCEPTION in section {}: {}", section, e.what());
        return 2;
    }
}
