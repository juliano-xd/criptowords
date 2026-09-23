#include "../../include/crypto/base58.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/math/UInt.hpp"
#include <cstdint>
#include <cstring>
#include <string>

namespace cryptowords {
namespace base58 {

    // Tabela estática de lookup O(1) para caracteres Base58 (256 bytes)
    constexpr auto make_b58_table() {
        std::array<int8_t, 256> tbl{};
        tbl.fill(-1);
        for (int i = 0; i < 58; ++i) {
            tbl[static_cast<uint8_t>(BASE58_ALPHABET[i])] = static_cast<int8_t>(i);
        }
        return tbl;
    }
    constexpr auto B58_LOOKUP = make_b58_table();

    bool decode_btc_address(const std::string& address, uint8_t out_ripemd[20]) {
        if (address.size() < 26 || address.size() > 35) return false;

        // '1' inicial = byte 0x00 à esquerda.
        size_t leading = 0;
        while (leading < address.size() && address[leading] == '1') ++leading;
        if (leading >= 25) return false;

        UInt<4> val = 0;
        for (char c : address) {
            int8_t digit = B58_LOOKUP[static_cast<uint8_t>(c)];
            if (__builtin_expect(digit < 0, 0)) return false;
            val *= 58ULL;
            val += static_cast<u64>(digit);
        }

        alignas(8) uint8_t raw[32];
        val.to_bytes(raw, Endianness::big);
        const uint8_t* decoded = raw + 7; // 32 - 25 = 7

        if (decoded[0] != 0x00) return false;

        uint8_t checksum[32];
        crypto::SHA256::hash(decoded, 21, checksum);
        crypto::SHA256::hash(checksum, 32, checksum);
        if (std::memcmp(decoded + 21, checksum, 4) != 0) return false;

        std::memcpy(out_ripemd, decoded + 1, 20);
        return true;
    }

size_t encode_raw(const uint8_t* payload, size_t len, char* out_buf) {
    if (len == 0) {
        out_buf[0] = '\0';
        return 0;
    }

    size_t leading_zeros = 0;
    while (leading_zeros < len && payload[leading_zeros] == 0x00) {
        leading_zeros++;
    }

    // Carrega payload em big-endian diretamente no UInt<4>
    UInt<4> val(payload + leading_zeros, len - leading_zeros, Endianness::big);

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
