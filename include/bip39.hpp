#pragma once
#include "Arbitrary/UInt.hpp"
#include "crypto_impl.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <flat_map>
#include <print>
#include <secp256k1.h>
#include <string>
#include <string_view>
#include <vector>


#ifndef BUILTIN_EXPECT
#define BUILTIN_EXPECT(x, y) (__builtin_expect(!!(x), y))
#endif

namespace cryptowords {

static constexpr size_t MAX_MNEMONIC_LEN = 300;
static constexpr size_t BIP39_WORDLIST_SIZE = 2048;

class Bip39Deriver {
  public:
    static inline size_t build_mnemonic_str(const std::vector<uint16_t>& __restrict ids_vec,
                                            const std::vector<std::string>& wl,
                                            const std::string& separator,
                                            char* __restrict out_buf) noexcept {
        const size_t count = ids_vec.size();
        if (count == 0)
            return 0;

        const uint16_t* __restrict ids = ids_vec.data();
        char* __restrict ptr = out_buf;

        std::string_view w0 = wl[ids[0]];
        std::memcpy(ptr, w0.data(), w0.size());
        ptr += w0.size();

        for (size_t i = 1; i < count; ++i) {
            std::memcpy(ptr, separator.data(), separator.size());
            ptr += separator.size();
            std::string_view w = wl[ids[i]];
            std::memcpy(ptr, w.data(), w.size());
            ptr += w.size();
        }

        return ptr - out_buf;
    }

  private:
    static inline bool derive_child_key(const secp256k1_context* ctx, uint8_t* priv_key,
                                        uint8_t* chain_code, uint32_t index) noexcept {
        uint8_t data[37] = {0};

        if (index & 0x80000000u) {
            data[0] = 0;
            std::memcpy(data + 1, priv_key, 32);
        } else {
            secp256k1_pubkey pub;
            size_t pub_len = 33;
            if (!secp256k1_ec_pubkey_create(ctx, &pub, priv_key))
                return false;
            secp256k1_ec_pubkey_serialize(ctx, data, &pub_len, &pub,
                                          SECP256K1_EC_COMPRESSED);
        }

        // Seriação big-endian do índice.
        data[33] = static_cast<uint8_t>(index >> 24);
        data[34] = static_cast<uint8_t>(index >> 16);
        data[35] = static_cast<uint8_t>(index >> 8);
        data[36] = static_cast<uint8_t>(index);

        uint8_t I[64];

        
        crypto::HMAC_SHA512 hmac;
        hmac.init(chain_code, 32);
        hmac.update(data, 37);
        hmac.finalize(I);


        if (!secp256k1_ec_seckey_tweak_add(ctx, priv_key, I))
            return false;

        std::memcpy(chain_code, I + 32, 32);
        return true;
    }

  public:
    static std::string derive_btc_address(const secp256k1_context* ctx,
                                          const std::vector<uint16_t>& mnemonic_ids,
                                          const std::vector<std::string>& wl,
                                          const char* passphrase = nullptr,
                                          size_t passphrase_len = 0) {
        char buf[MAX_MNEMONIC_LEN];
        size_t len = build_mnemonic_str(mnemonic_ids, wl, " ", buf);

        uint8_t seed[64];
        uint8_t master_node[64];
        uint8_t priv_key[32];
        uint8_t chain_code[32];

        uint8_t pub_serialized[33];
        uint8_t hash_buf[32];
        uint8_t ripemd_buf[20];
        uint8_t payload[25];
        uint8_t checksum[32];
        char result[64];
        std::array<uint8_t, 256> salt_buf = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};

        std::memcpy(salt_buf.data(), "mnemonic", 8);
        size_t salt_len = 8;
        if (passphrase && passphrase_len > 0) {
            std::memcpy(salt_buf.data() + 8, passphrase, passphrase_len);
            salt_len += passphrase_len;
        }

        crypto::pbkdf2_hmac_sha512(buf, len, salt_buf.data(), salt_len, 2048, seed, 64);
        crypto::HMAC_SHA512 hmac;
        hmac.init((const uint8_t*)"Bitcoin seed", 12);
        hmac.update(seed, 64);
        hmac.finalize(master_node);

        std::memcpy(priv_key, master_node, 32);
        std::memcpy(chain_code, master_node + 32, 32);

        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000002C))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key))
            return "";
        size_t pub_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &pub_len, &pubkey,
                                      SECP256K1_EC_COMPRESSED);

        crypto::SHA256::hash(pub_serialized, pub_len, hash_buf);
        crypto::RIPEMD160::hash(hash_buf, 32, ripemd_buf);

        payload[0] = 0x00;
        std::memcpy(payload + 1, ripemd_buf, 20);

        crypto::SHA256::hash(payload, 21, checksum);
        crypto::SHA256::hash(checksum, 32, checksum);
        std::memcpy(payload + 21, checksum, 4);

        size_t final_len = base58_encode_raw(payload, 25, result);
        return std::string(result, final_len);
    }

    static std::string derive_eth_address(const secp256k1_context* ctx,
                                          const std::vector<uint16_t>& mnemonic_ids,
                                          const std::vector<std::string>& wl,
                                          const char* passphrase = nullptr,
                                          size_t passphrase_len = 0) {
        char buf[MAX_MNEMONIC_LEN];
        size_t len = build_mnemonic_str(mnemonic_ids, wl, " ", buf);

        uint8_t seed[64];
        uint8_t master_node[64];
        uint8_t priv_key[32];
        uint8_t chain_code[32];

        uint8_t pub_uncompressed[65];
        uint8_t hash_buf[32];

        uint8_t salt_buf[256];
        std::memcpy(salt_buf, "mnemonic", 8);
        size_t salt_len = 8;
        if (passphrase && passphrase_len > 0) {
            std::memcpy(salt_buf + 8, passphrase, passphrase_len);
            salt_len += passphrase_len;
        }

        crypto::pbkdf2_hmac_sha512(buf, len, salt_buf, salt_len, 2048, seed, 64);
        crypto::HMAC_SHA512 hmac;
        hmac.init((const uint8_t*)"Bitcoin seed", 12);
        hmac.update(seed, 64);
        hmac.finalize(master_node);

        std::memcpy(priv_key, master_node, 32);
        std::memcpy(chain_code, master_node + 32, 32);

        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000002C))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000003C))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key))
            return "";
        size_t pub_len = 65;
        secp256k1_ec_pubkey_serialize(ctx, pub_uncompressed, &pub_len, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED);

        crypto::Keccak256::hash(pub_uncompressed + 1, 64, hash_buf);

        char hex[43];
        hex[0] = '0';
        hex[1] = 'x';
        static const char hextable[] = "0123456789abcdef";
        for (int i = 0; i < 20; ++i) {
            hex[2 + i * 2] = hextable[(hash_buf[12 + i] >> 4) & 0x0f];
            hex[2 + i * 2 + 1] = hextable[(hash_buf[12 + i] & 0x0f)];
        }
        return std::string(hex, 42);
    }

    static std::string derive_btc_address_from_seed(const secp256k1_context* ctx,
                                                    const uint8_t* seed, const char* passphrase,
                                                    size_t passphrase_len) {
        uint8_t master_node[64];
        uint8_t priv_key[32];
        uint8_t chain_code[32];
        uint8_t pub_serialized[33];
        uint8_t hash_buf[32];
        uint8_t ripemd_buf[20];
        uint8_t payload[25];
        uint8_t checksum[32];
        char result[64];
        crypto::HMAC_SHA512 hmac;
        hmac.init((const uint8_t*)"Bitcoin seed", 12);
        hmac.update(seed, 64);
        hmac.finalize(master_node);

        std::memcpy(priv_key, master_node, 32);
        std::memcpy(chain_code, master_node + 32, 32);

        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000002C))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key))
            return "";
        size_t pub_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &pub_len, &pubkey,
                                      SECP256K1_EC_COMPRESSED);

        crypto::SHA256::hash(pub_serialized, pub_len, hash_buf);
        crypto::RIPEMD160::hash(hash_buf, 32, ripemd_buf);

        payload[0] = 0x00;
        std::memcpy(payload + 1, ripemd_buf, 20);

        crypto::SHA256::hash(payload, 21, checksum);
        crypto::SHA256::hash(checksum, 32, checksum);
        std::memcpy(payload + 21, checksum, 4);

        size_t final_len = base58_encode_raw(payload, 25, result);
        return std::string(result, final_len);
    }

    static std::string derive_eth_address_from_seed(const secp256k1_context* ctx,
                                                    const uint8_t* seed, const char* passphrase,
                                                    size_t passphrase_len) {
        uint8_t master_node[64];
        uint8_t priv_key[32];
        uint8_t chain_code[32];
        uint8_t pub_uncompressed[65];
        uint8_t hash_buf[32];
        crypto::HMAC_SHA512 hmac;
        hmac.init((const uint8_t*)"Bitcoin seed", 12);
        hmac.update(seed, 64);
        hmac.finalize(master_node);

        std::memcpy(priv_key, master_node, 32);
        std::memcpy(chain_code, master_node + 32, 32);

        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000002C))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000003C))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";
        if (!derive_child_key(ctx, priv_key, chain_code, 0))
            return "";

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key))
            return "";
        size_t pub_len = 65;
        secp256k1_ec_pubkey_serialize(ctx, pub_uncompressed, &pub_len, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED);

        crypto::Keccak256::hash(pub_uncompressed + 1, 64, hash_buf);

        char hex[43];
        hex[0] = '0';
        hex[1] = 'x';
        static const char hextable[] = "0123456789abcdef";
        for (int i = 0; i < 20; ++i) {
            hex[2 + i * 2] = hextable[(hash_buf[12 + i] >> 4) & 0x0f];
            hex[2 + i * 2 + 1] = hextable[(hash_buf[12 + i] & 0x0f)];
        }
        return std::string(hex, 42);
    }


    static inline bool decode_base58_btc_address(const std::string& address, uint8_t out_ripemd[20]) {
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
        while (result.size() < 25 - leading_zeros) result.push_back(0);
        if (result.size() + leading_zeros != 25) return false;
        
        uint8_t decoded[25] = {0};
        for(int i = 0; i < leading_zeros; i++) decoded[i] = 0;
        for(size_t i = 0; i < result.size(); i++) decoded[24 - i] = result[i];
        
        uint8_t checksum[32];
        crypto::SHA256::hash(decoded, 21, checksum);
        crypto::SHA256::hash(checksum, 32, checksum);
        if (memcmp(decoded + 21, checksum, 4) != 0) return false;
        
        memcpy(out_ripemd, decoded + 1, 20);
        return true;
    }

    static inline bool decode_hex_eth_address(const std::string& hex_addr, uint8_t out_target[20]) {
        std::string s = hex_addr;
        if (s.length() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
        if (s.length() != 40) return false;
        for (int i = 0; i < 20; i++) {
            std::string byteString = s.substr(i * 2, 2);
            out_target[i] = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        }
        return true;
    }

    static inline bool check_btc_target_from_seed(const secp256k1_context* ctx,
                                                    const uint8_t* seed,
                                                    const uint8_t* target_ripemd) {
        uint8_t master_node[64];
        uint8_t priv_key[32];
        uint8_t chain_code[32];
        uint8_t pub_serialized[33];
        uint8_t hash_buf[32];
        uint8_t ripemd_buf[20];

        static const crypto::HMAC_SHA512 base_hmac = [](){
            crypto::HMAC_SHA512 h;
            h.init((const uint8_t*)"Bitcoin seed", 12);
            return h;
        }();
        
        crypto::HMAC_SHA512 hmac = base_hmac;
        hmac.update(seed, 64);
        hmac.finalize(master_node);

        std::memcpy(priv_key, master_node, 32);
        std::memcpy(chain_code, master_node + 32, 32);

        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000002C)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0)) return false;

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) return false;
        size_t pub_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &pub_len, &pubkey,
                                      SECP256K1_EC_COMPRESSED);

        crypto::SHA256::hash(pub_serialized, pub_len, hash_buf);
        crypto::RIPEMD160::hash(hash_buf, 32, ripemd_buf);

        return std::memcmp(ripemd_buf, target_ripemd, 20) == 0;
    }

    static inline bool check_eth_target_from_seed(const secp256k1_context* ctx,
                                                    const uint8_t* seed,
                                                    const uint8_t* target_eth) {
        uint8_t master_node[64];
        uint8_t priv_key[32];
        uint8_t chain_code[32];
        uint8_t pub_uncompressed[65];
        uint8_t hash_buf[32];

        static const crypto::HMAC_SHA512 base_hmac = [](){
            crypto::HMAC_SHA512 h;
            h.init((const uint8_t*)"Bitcoin seed", 12);
            return h;
        }();
        
        crypto::HMAC_SHA512 hmac = base_hmac;
        hmac.update(seed, 64);
        hmac.finalize(master_node);

        std::memcpy(priv_key, master_node, 32);
        std::memcpy(chain_code, master_node + 32, 32);

        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000002C)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0x8000003C)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0x80000000)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0)) return false;
        if (!derive_child_key(ctx, priv_key, chain_code, 0)) return false;

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) return false;
        size_t pub_len = 65;
        secp256k1_ec_pubkey_serialize(ctx, pub_uncompressed, &pub_len, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED);

        crypto::Keccak256::hash(pub_uncompressed + 1, 64, hash_buf);

        return std::memcmp(hash_buf + 12, target_eth, 20) == 0;
    }

    constexpr static const char* BASE58_ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    static inline size_t base58_encode_raw(const uint8_t* payload, size_t len,
                                           char* out_buf) noexcept {
        size_t leading_zeros = 0;
        while (leading_zeros < len && payload[leading_zeros] == 0x00) {
            leading_zeros++;
        }

        UInt<4> num = 0;
        num.bits.fill(0);

        for (size_t i = 0; i < len; ++i) {
            num *= 256;
            num += static_cast<uint64_t>(payload[i]);
        }

        char temp_buf[64];
        size_t temp_len = 0;

        while (!num.eqz()) {
            unsigned __int128 rem = 0;
            for (int i = 3; i >= 0; --i) {
                unsigned __int128 cur = static_cast<unsigned __int128>(num.bits[i]) | (rem << 64);
                num.bits[i] = static_cast<uint64_t>(cur / 58);
                rem = cur % 58;
            }
            temp_buf[temp_len++] = BASE58_ALPHABET[static_cast<size_t>(rem)];
        }

        for (size_t i = 0; i < leading_zeros; ++i) {
            temp_buf[temp_len++] = BASE58_ALPHABET[0];
        }

        for (size_t i = 0; i < temp_len; ++i) {
            out_buf[i] = temp_buf[temp_len - 1 - i];
        }
        out_buf[temp_len] = '\0';

        return temp_len;
    }

    // ============================================================
    // O SEU VALIDADOR DEFINITIVO
    // ============================================================
    static bool verify_checksum(const std::vector<uint16_t>& mnemonic_ids) noexcept {
        const size_t n = mnemonic_ids.size();

        if (BUILTIN_EXPECT(n < 12 || n > 24 || n % 3 != 0, 0))
            return false;

        const size_t entropy_bytes = (n * 4) / 3;
        const unsigned checksum_bits = n / 3;

        const uint16_t* __restrict ids = mnemonic_ids.data();

        std::array<uint32_t, 8> data{};
        uint64_t buffer = 0;
        uint32_t* out = data.data();

        for (size_t i = 0, shift = 1; i < n; i += 3, ++shift) {
            const uint64_t chunk =
                (uint64_t(ids[i]) << 22) | (uint64_t(ids[i + 1]) << 11) | uint64_t(ids[i + 2]);

            buffer = (buffer << 33) | chunk;
            *out++ = __builtin_bswap32(static_cast<uint32_t>(buffer >> shift));
        }

        const uint8_t original_checksum =
            static_cast<uint8_t>(buffer & ((uint64_t{1} << checksum_bits) - 1));

        std::array<uint8_t, 32> hash{};
        crypto::SHA256::hash(reinterpret_cast<const uint8_t*>(data.data()), entropy_bytes,
                             hash.data());

        return original_checksum == (hash[0] >> (8 - checksum_bits));
    }
};

} // namespace cryptowords
