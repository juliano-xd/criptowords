#include <iostream>
#include <cassert>
#include <cstring>
#include <random>
#include <secp256k1.h>
#include "include/crypto/secp256k1_point.hpp"


int main() {
    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::mt19937_64 rng(999);
    const int TEST_COUNT = 1000;

    std::cout << "[+] Validando secp256k1_pubkey_create_fast (33 bytes) e uncompressed (65 bytes)..." << std::endl;

    for (int t = 0; t < TEST_COUNT; ++t) {
        uint8_t seckey[32];
        for (int i = 0; i < 32; ++i) seckey[i] = static_cast<uint8_t>(rng());
        seckey[0] &= 0x7F;

        // Ground truth via libsecp256k1
        secp256k1_pubkey pubkey;
        int ok = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
        assert(ok == 1);

        uint8_t exp_comp[33];
        size_t len_c = 33;
        secp256k1_ec_pubkey_serialize(ctx, exp_comp, &len_c, &pubkey, SECP256K1_EC_COMPRESSED);

        uint8_t exp_uncomp[65];
        size_t len_u = 65;
        secp256k1_ec_pubkey_serialize(ctx, exp_uncomp, &len_u, &pubkey, SECP256K1_EC_UNCOMPRESSED);

        // Actual via our fast UInt<4> point multiplier
        uint8_t act_comp[33];
        bool ok_c = crypto::secp256k1_pubkey_create_fast(act_comp, seckey);
        assert(ok_c);

        uint8_t act_uncomp[65];
        bool ok_u = crypto::secp256k1_pubkey_create_uncompressed(act_uncomp, seckey);
        assert(ok_u);

        if (std::memcmp(exp_comp, act_comp, 33) != 0) {
            std::cerr << "[!] Divergência no formato comprimido (teste " << t << ")!\n";
            return 1;
        }
        if (std::memcmp(exp_uncomp, act_uncomp, 65) != 0) {
            std::cerr << "[!] Divergência no formato não comprimido (teste " << t << ")!\n";
            return 1;
        }
    }

    std::cout << "[✓] 1.000 chaves públicas (COMPRESSED e UNCOMPRESSED) 100% IDÊNTICAS à libsecp256k1!" << std::endl;
    secp256k1_context_destroy(ctx);
    return 0;
}
