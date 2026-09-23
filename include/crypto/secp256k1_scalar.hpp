#pragma once

#include <array>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "../math/UInt.hpp"
#pragma GCC diagnostic pop

#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace crypto {

// Ordem do grupo SECP256K1 n:
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    constexpr UInt<4> N_VAL("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

// Delta para redução rápida de carry de 256 bits:
// Delta = 2^256 - n = 0x14551231950B75FC4402DA1732FC9BEBF
// limb 0: 0x402DA1732FC9BEBF
// limb 1: 0x4551231950B75FC4
// limb 2: 0x0000000000000001
// limb 3: 0x0000000000000000
    constexpr UInt<4> DELTA(0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL, 0x0000000000000001ULL, 0x0000000000000000ULL);

// Carrega 32 bytes em big-endian para UInt<4> nativo via MOVBE (1 ciclo x86-64)
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

FORCE_INLINE UInt<4> load_be256(const std::array<uint8_t, 32> &be) noexcept {
    return load_be256(be.data());
}

// Armazena UInt<4> nativo em buffer big-endian de 32 bytes via MOVBE
FORCE_INLINE void store_be256(uint8_t* be, const UInt<4>& v) noexcept {
    uint64_t w3 = __builtin_bswap64(v.bits[3]);
    uint64_t w2 = __builtin_bswap64(v.bits[2]);
    uint64_t w1 = __builtin_bswap64(v.bits[1]);
    uint64_t w0 = __builtin_bswap64(v.bits[0]);
    std::memcpy(be + 0, &w3, 8);
    std::memcpy(be + 8, &w2, 8);
    std::memcpy(be + 16, &w1, 8);
    std::memcpy(be + 24, &w0, 8);
}

FORCE_INLINE void store_be256(std::array<uint8_t, 32> &be, const UInt<4>& v) noexcept {
    store_be256(be.data(), v);
}

// Adição escalar rápida: seckey = (seckey + tweak) mod n
// Equivalente bit-a-bit à rotina secp256k1_ec_seckey_tweak_add com performance nativa inlined via UInt<4>.
FORCE_INLINE bool secp256k1_tweak_add_fast(uint8_t* seckey, const uint8_t* tweak) noexcept {
    UInt<4> k = load_be256(seckey);
    const UInt<4> tw = load_be256(tweak);

    // Regra estrita SECP256K1 / BIP-32: tweak < n e 0 < seckey < n
    if (__builtin_expect(tw >= N_VAL || k >= N_VAL || k.eqz(), 0)) {
        return false;
    }

    const uint8_t carry = k.add_carry(tw);
    if (carry) {
        k += DELTA;
    } else {
        if (k >= N_VAL) {
            k -= N_VAL;
        }
    }

    if (k.eqz()) [[unlikely]] return false;

    store_be256(seckey, k);
    return true;
}

FORCE_INLINE bool secp256k1_tweak_add_fast(std::array<uint8_t, 32> &seckey, const std::array<uint8_t, 32> &tweak) noexcept {
    return secp256k1_tweak_add_fast(seckey.data(), tweak.data());
}

} // namespace crypto
