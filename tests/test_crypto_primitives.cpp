#include "../include/crypto_impl.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <iomanip>

using namespace crypto;

// Helper to convert hex to bytes
void from_hex(const char* hex, uint8_t* out) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len; i += 2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        out[i/2] = (uint8_t)strtol(buf, nullptr, 16);
    }
}

// Helper to check array equality
bool check_eq(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

void test_sha256() {
    std::cout << "[TDD] Testing SHA-256 primitive...\n";
    const char* input = "abc";
    uint8_t expected[32];
    from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected);
    
    uint8_t out[32];
    SHA256::hash((const uint8_t*)input, 3, out);
    assert(check_eq(out, expected, 32));
    std::cout << "  -> SHA-256 passed.\n";
}

void test_hmac_sha512() {
    std::cout << "[TDD] Testing HMAC-SHA-512 primitive...\n";
    // RFC 4231 Test Case 1
    const uint8_t key[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
    const char* data = "Hi There";
    uint8_t expected[64];
    from_hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", expected);
    
    uint8_t out[64];
    HMAC_SHA512 hmac;
    hmac.init(key, 20);
    hmac.update((const uint8_t*)data, 8);
    hmac.finalize(out);
    
    assert(check_eq(out, expected, 64));
    std::cout << "  -> HMAC-SHA-512 passed.\n";
}

int main() {
    std::cout << "Running Crypto Primitives TDD Suite...\n";
    test_sha256();
    test_hmac_sha512();
    std::cout << "All tests passed!\n";
    return 0;
}
