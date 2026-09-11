#include <iostream>
#include <iomanip>
#include "../include/crypto_impl.hpp"

using namespace crypto;

void dump(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    uint8_t data[] = "abc";
    uint8_t out[32];
    Keccak256::hash(data, 3, out);
    dump(out, 32);
    return 0;
}
