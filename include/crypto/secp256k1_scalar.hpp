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

// Adição escalar rápida: seckey = (seckey + tweak) mod n
// Equivalente bit-a-bit à rotina secp256k1_ec_seckey_tweak_add com performance nativa inlined via UInt<4>.
FORCE_INLINE bool secp256k1_tweak_add_fast(uint8_t* seckey, const uint8_t* tweak) noexcept {
    UInt<4> k(seckey, 32, Endianness::big);
    const UInt<4> tw(tweak, 32, Endianness::big);

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

    k.to_bytes(seckey, 32, Endianness::big);
    return true;
}

FORCE_INLINE bool secp256k1_tweak_add_fast(std::array<uint8_t, 32> &seckey, const std::array<uint8_t, 32> &tweak) noexcept {
    UInt<4> k(seckey, Endianness::big);
    const UInt<4> tw(tweak, Endianness::big);

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

    k.to_bytes(seckey, Endianness::big);
    return true;
}

} // namespace crypto
