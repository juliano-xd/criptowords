#include "../../include/crypto/base58.hpp"
#include "../../include/crypto/sha256.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace cryptowords {
namespace base58 {

    bool decode_btc_address(const std::string& address, uint8_t out_ripemd[20]) {
        if (address.size() < 26 || address.size() > 35) return false;

        // '1' inicial = byte 0x00 à esquerda.
        size_t leading = 0;
        while (leading < address.size() && address[leading] == '1') ++leading;

        // Big-number base58 -> bytes little-endian.
        std::vector<uint8_t> bytes;
        bytes.reserve(25);
        for (char c : address) {
            const char* p = strchr(BASE58_ALPHABET, c);
            if (!p) return false;
            int carry = static_cast<int>(p - BASE58_ALPHABET);
            for (auto& b : bytes) {
                carry += b * 58;
                b      = static_cast<uint8_t>(carry & 0xFF);
                carry >>= 8;
            }
            while (carry > 0) {
                bytes.push_back(static_cast<uint8_t>(carry & 0xFF));
                carry >>= 8;
            }
        }

        while (bytes.size() < 25 - leading) bytes.push_back(0);
        if (bytes.size() + leading != 25) return false;

        uint8_t decoded[25] = {};
        for (size_t i = 0; i < bytes.size(); ++i) decoded[24 - i] = bytes[i];

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

    out_buf[out_len] = '\0';
    return out_len;
}

} // namespace base58
} // namespace cryptowords
