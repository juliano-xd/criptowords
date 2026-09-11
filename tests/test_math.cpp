#include "../include/bip39.hpp"
#include "../include/crypto_impl.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <string>

using namespace cryptowords;

void test_checksum() {
    std::cout << "[TDD] Testing Checksum Math...\n";
    std::vector<uint16_t> ids = {1031, 0, 382, 1437, 1408, 649, 1223, 496, 1252, 954, 3, 32};
    bool valid = Bip39Deriver::verify_checksum(ids);
    assert(valid == true);
    std::cout << "  -> Checksum tests passed.\n";
}

void test_derivation() {
    std::cout << "[TDD] Testing BIP39/BIP32 Derivation...\n";
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    std::vector<std::string> wordlist(2048, "word"); 
    wordlist[1031] = "liberty"; wordlist[0] = "abandon"; wordlist[382] = "cool"; wordlist[1437] = "recipe";
    wordlist[1408] = "quote"; wordlist[649] = "eye"; wordlist[1223] = "ocean"; wordlist[496] = "dignity";
    wordlist[1252] = "orient"; wordlist[954] = "jar"; wordlist[3] = "about"; wordlist[32] = "advice";

    std::vector<uint16_t> ids = {1031, 0, 382, 1437, 1408, 649, 1223, 496, 1252, 954, 3, 32};
    
    std::string address = Bip39Deriver::derive_btc_address(ctx, ids, wordlist, "", 0);
    assert(address == "13CaGwjnNeEnsRMi5kmCKnna9KAUKo7q9i");

    uint8_t decoded_target[20];
    bool dec_ok = Bip39Deriver::decode_base58_btc_address("13CaGwjnNeEnsRMi5kmCKnna9KAUKo7q9i", decoded_target);
    assert(dec_ok);
    
    std::string mnemonic = "liberty abandon cool recipe quote eye ocean dignity orient jar about advice";
    std::string salt_str = "mnemonic";
    uint8_t seed[64];
    crypto::pbkdf2_hmac_sha512(mnemonic.data(), mnemonic.size(), (const uint8_t*)salt_str.data(), salt_str.size(), 2048, seed, 64);
    
    bool check_ok = Bip39Deriver::check_btc_target_from_seed(ctx, seed, decoded_target);
    assert(check_ok);

    secp256k1_context_destroy(ctx);
    std::cout << "  -> Derivation tests passed.\n";
}

int main() {
    std::cout << "Running TDD Suite...\n";
    test_checksum();
    test_derivation();
    std::cout << "All current tests passed!\n";
    return 0;
}
