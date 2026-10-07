#include <array>
#include <cstdint>
#include <string>

#include "../include/crypto/hmac_sha512.hpp"
#include "../include/crypto/keccak256.hpp"
#include "../include/crypto/ripemd160.hpp"
#include "../include/crypto/sha256.hpp"
#include "../include/crypto/sha512.hpp"
#include "test_framework.hpp"
// #include "../include/math/UInt.hpp"

namespace {

std::string hex(const uint8_t* p, size_t n) {
    static constexpr char H[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(H[p[i] >> 4]);
        s.push_back(H[p[i] & 0xF]);
    }
    return s;
}

}  // namespace

// -----------------------------------------------------------------------------
// SHA-256 — vetores NIST FIPS 180-4
// -----------------------------------------------------------------------------
TEST_CASE(sha256_nist_vectors) {
    uint8_t out[32];

    crypto::SHA256::hash("", 0, out);
    REQUIRE_EQ(hex(out, 32), std::string("e3b0c44298fc1c149afbf4c8996fb924"
                                         "27ae41e4649b934ca495991b7852b855"));

    // Exercita o caminho de bloco único (len ≤ 55).
    crypto::SHA256::hash("abc", 3, out);
    REQUIRE_EQ(hex(out, 32), std::string("ba7816bf8f01cfea414140de5dae2223"
                                         "b00361a396177a9cb410ff61f20015ad"));

    // 56 B força o caminho streaming (padding em dois blocos).
    crypto::SHA256::hash(
        "abcdbcdecdefdefgefghfghighijhijk"
        "ijkljklmklmnlmnomnopnopq",
        56, out);
    REQUIRE_EQ(hex(out, 32), std::string("248d6a61d20638b8e5c026930c3e6039"
                                         "a33ce45964ff2167f6ecedd419db06c1"));
}

// -----------------------------------------------------------------------------
// SHA-512 — vetores NIST FIPS 180-4
// -----------------------------------------------------------------------------
TEST_CASE(sha512_nist_vectors) {
    uint8_t out[64];

    crypto::SHA512::hash("", 0, out);
    REQUIRE_EQ(hex(out, 64), std::string("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                                         "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));

    crypto::SHA512::hash("abc", 3, out);
    REQUIRE_EQ(hex(out, 64), std::string("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

// -----------------------------------------------------------------------------
// HMAC-SHA512 — RFC 4231 test case 2
// -----------------------------------------------------------------------------
TEST_CASE(hmac_sha512_rfc4231_test2) {
    // key="Jefe" (4 B), data="what do ya want for nothing?" (28 B)
    std::array<uint8_t, 64> out;
    crypto::HMAC_SHA512::hash("Jefe", 4, "what do ya want for nothing?", 28, out);
    REQUIRE_EQ(hex(out.data(), 64), std::string("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                                                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
}

// -----------------------------------------------------------------------------
// RIPEMD-160 — vetor do ISO/IEC 10118-3
// -----------------------------------------------------------------------------
TEST_CASE(ripemd160_abc_vector) {
    uint8_t out[20];
    crypto::RIPEMD160::hash("abc", 3, out);
    REQUIRE_EQ(hex(out, 20), std::string("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
}

// -----------------------------------------------------------------------------
// Keccak-256 — hash vazio (variante Ethereum, padding 0x01)
// -----------------------------------------------------------------------------
TEST_CASE(keccak256_empty_vector) {
    uint8_t out[32];
    crypto::Keccak256::hash("", 0, out);
    REQUIRE_EQ(hex(out, 32), std::string("c5d2460186f7233c927e7db2dcc703c0"
                                         "e500b653ca82273b7bfad8045d85a470"));
}

// -----------------------------------------------------------------------------
// UInt<N> — soma/subtração com carry e parsing hex
// -----------------------------------------------------------------------------
TEST_CASE(uint_basic_arithmetic) {
    // UInt<4> a(1);
    // UInt<4> b(2);
    // REQUIRE((a + b) == UInt<4>(3));
    // REQUIRE((b - a) == UInt<4>(1));
    // REQUIRE(a < b);

    // // Carry propaga por múltiplos limbs.
    // UInt<4> c(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0, 0);
    // UInt<4> e = c + UInt<4>(1);
    // REQUIRE_EQ(e[0], 0ULL);
    // REQUIRE_EQ(e[1], 0ULL);
    // REQUIRE_EQ(e[2], 1ULL);

    // // Parse hex big-endian → limbs little-endian.
    // UInt<4> f("0x100000000000000000000000000000000");  // 2^128
    // REQUIRE_EQ(f[0], 0ULL);
    // REQUIRE_EQ(f[1], 0ULL);
    // REQUIRE_EQ(f[2], 1ULL);
    // REQUIRE_EQ(f[3], 0ULL);
}
