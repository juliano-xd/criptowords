#include "../../include/crypto/base58.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/math/UInt.hpp"
#include <cstdint>
#include <cstring>
#include <string>

namespace cryptowords {
namespace base58 {

    bool decode_btc_address(const std::string& address, uint8_t out_ripemd[20]) {
        if (address.size() < 26 || address.size() > 35) return false;

        // '1' inicial = byte 0x00 à esquerda.
        size_t leading = 0;
        while (leading < address.size() && address[leading] == '1') ++leading;
        if (leading >= 25) return false;

        UInt<4> val = 0;
        for (char c : address) {
            const char* p = std::strchr(BASE58_ALPHABET, c);
            if (!p) return false;
            val *= 58ULL;
            val += static_cast<u64>(p - BASE58_ALPHABET);
        }

        uint8_t decoded[25] = {};
        for (int i = 0; i < 4; ++i) {
            uint64_t w = val.bits[i];
            for (int b = 0; b < 8; ++b) {
                int pos = 24 - (i * 8 + b);
                if (pos >= 0) {
                    decoded[pos] = static_cast<uint8_t>(w & 0xFF);
                }
                w >>= 8;
            }
        }

        if (decoded[0] != 0x00) return false;

        uint8_t checksum[32];
        crypto::SHA256::hash(decoded, 21, checksum);
        crypto::SHA256::hash(checksum, 32, checksum);
        if (std::memcmp(decoded + 21, checksum, 4) != 0) return false;

        std::memcpy(out_ripemd, decoded + 1, 20);
        return true;
    }

size_t encode_raw(const uint8_t* payload, size_t len, char* out_buf) {
    size_t leading_zeros = 0;
    while (leading_zeros < len && payload[leading_zeros] == 0x00) {
        leading_zeros++;
    }

    if (len == 0) {
        out_buf[0] = '\0';
        return 0;
    }

    // Carrega payload em big-endian no UInt<4> (até 25 bytes / 200 bits)
    UInt<4> val = 0;
    for (size_t i = leading_zeros; i < len; ++i) {
        val <<= 8;
        val += payload[i];
    }

    char tmp[64];
    size_t tmp_len = 0;
    while (!val.eqz()) {
        auto [q, rem] = val.divmod(58ULL);
        val = q;
        tmp[tmp_len++] = BASE58_ALPHABET[rem];
    }

    size_t out_len = 0;
    for (size_t i = 0; i < leading_zeros; ++i) {
        out_buf[out_len++] = BASE58_ALPHABET[0];
    }
    for (size_t i = 0; i < tmp_len; ++i) {
        out_buf[out_len++] = tmp[tmp_len - 1 - i];
    }
    if (out_len == 0) {
        out_buf[out_len++] = BASE58_ALPHABET[0];
    }

    out_buf[out_len] = '\0';
    return out_len;
}

} // namespace base58
} // namespace cryptowords
