#include "../include/base58.hpp"
#include "../include/sha256.hpp"
#include <cstring>

namespace cryptowords {
namespace base58 {

bool decode_btc_address(const std::string& address, uint8_t out_ripemd[20]) {
    std::vector<uint8_t> result;
    result.reserve(25);
    for (char c : address) {
        const char* p = strchr(BASE58_ALPHABET, c);
        if (p == nullptr) return false;
        int val = p - BASE58_ALPHABET;
        for (size_t i = 0; i < result.size(); ++i) {
            val += result[i] * 58;
            result[i] = val % 256;
            val /= 256;
        }
        while (val > 0) {
            result.push_back(val % 256);
            val /= 256;
        }
    }
    int leading_zeros = 0;
    while (leading_zeros < address.size() && address[leading_zeros] == '1') leading_zeros++;
    while (result.size() < 25 - static_cast<size_t>(leading_zeros)) result.push_back(0);
    if (result.size() + leading_zeros != 25) return false;

    uint8_t decoded[25] = {};
    for(int i = 0; i < leading_zeros; i++) decoded[i] = 0;
    for(size_t i = 0; i < result.size(); i++) decoded[24 - i] = result[i];

    if (decoded[0] != 0x00) return false;

    uint8_t checksum[32];
    crypto::SHA256::hash(decoded, 21, checksum);
    crypto::SHA256::hash(checksum, 32, checksum);
    if (memcmp(decoded + 21, checksum, 4) != 0) return false;

    memcpy(out_ripemd, decoded + 1, 20);
    return true;
}

size_t encode_raw(const uint8_t* payload, size_t len, char* out_buf) {
    size_t leading_zeros = 0;
    while (leading_zeros < len && payload[leading_zeros] == 0x00) {
        leading_zeros++;
    }

    std::vector<uint8_t> num;
    num.reserve(len * 2);

    for (size_t i = 0; i < len; ++i) {
        uint32_t carry = payload[i];
        for (size_t j = 0; j < num.size(); ++j) {
            carry += num[j] * 256;
            num[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            num.push_back(carry % 58);
            carry /= 58;
        }
    }

    size_t out_len = 0;
    for (size_t i = 0; i < leading_zeros; ++i) {
        out_buf[out_len++] = BASE58_ALPHABET[0];
    }

    for (auto it = num.rbegin(); it != num.rend(); ++it) {
        out_buf[out_len++] = BASE58_ALPHABET[*it];
    }

    if (out_len == 0) out_buf[out_len++] = BASE58_ALPHABET[0];

    out_buf[out_len] = ' ';
    return out_len;
}

} // namespace base58
} // namespace cryptowords
