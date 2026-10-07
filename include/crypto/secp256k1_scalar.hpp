#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <gmp.h>

namespace crypto {

// Ordem do grupo SECP256K1 n (big-endian):
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
inline constexpr std::array<uint8_t, 32> N_BYTES = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

struct SecpTweakCtx {
    mpz_t k, tw, n;
    SecpTweakCtx() {
        mpz_inits(k, tw, n, nullptr);
        mpz_import(n, 32, /*order=*/1, /*size=*/1, /*endian=*/1, /*nail=*/0, N_BYTES.data());
    }
    ~SecpTweakCtx() { mpz_clears(k, tw, n, nullptr); }
};

inline SecpTweakCtx& tweak_ctx() {
    thread_local SecpTweakCtx ctx;
    return ctx;
}

// seckey = (seckey + tweak) mod n, in-place (32 bytes big-endian).
// Retorna false se qualquer entrada é inválida (≥ n) ou se o resultado é zero.
inline bool secp256k1_tweak_add_fast(uint8_t* seckey, const uint8_t* tweak) noexcept {
    auto& ctx = tweak_ctx();

    mpz_import(ctx.k,  32, 1, 1, 1, 0, seckey);
    mpz_import(ctx.tw, 32, 1, 1, 1, 0, tweak);

    // Regra estrita SECP256K1 / BIP-32: 0 < seckey < n e 0 < tweak < n.
    if (mpz_cmp(ctx.tw, ctx.n) >= 0 || mpz_cmp(ctx.k, ctx.n) >= 0 ||
        mpz_sgn(ctx.k) == 0) {
        return false;
    }

    mpz_add(ctx.k, ctx.k, ctx.tw);
    mpz_mod(ctx.k, ctx.k, ctx.n);

    if (mpz_sgn(ctx.k) == 0) return false;

    // Exporta big-endian, zero-padded à esquerda.
    std::memset(seckey, 0, 32);
    size_t written = 0;
    mpz_export(seckey, &written, 1, 1, 1, 0, ctx.k);
    if (written < 32) {
        std::memmove(seckey + (32 - written), seckey, written);
        std::memset(seckey, 0, 32 - written);
    }
    return true;
}

inline bool secp256k1_tweak_add_fast(std::array<uint8_t, 32>& seckey,
                                     const std::array<uint8_t, 32>& tweak) noexcept {
    return secp256k1_tweak_add_fast(seckey.data(), tweak.data());
}

}  // namespace crypto
