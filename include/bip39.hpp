#pragma once
#include "Arbitrary/UInt.hpp"
#include "crypto_impl.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <flat_map>
#include <openssl/hmac.h>
#include <print>
#include <secp256k1.h>
#include <string>
#include <string_view>
#include <vector>

// #include "../keyhunt/sha3/sha3.h"

#ifndef BUILTIN_EXPECT
#define BUILTIN_EXPECT(x, y) (__builtin_expect(!!(x), y))
#endif

namespace cryptowords {

static constexpr size_t MAX_MNEMONIC_LEN = 300;
static constexpr size_t BIP39_WORDLIST_SIZE = 2048;

class Bip39Deriver {
  public:
    static inline size_t build_mnemonic_str(const std::vector<uint16_t>& __restrict ids_vec,
                                            const std::flat_map<std::string, uint16_t>& wl,
                                            char* __restrict out_buf) noexcept {
        const size_t count = ids_vec.size();
        if (count == 0)
            return 0;

        const uint16_t* __restrict ids = ids_vec.data();
        auto wl_begin = wl.begin();
        char* __restrict ptr = out_buf;

        std::string_view w0 = (wl_begin + ids[0])->first;
        __builtin_memcpy(ptr, w0.data(), 16);
        ptr += w0.size();

        for (size_t i = 1; i < count; ++i) {
            *ptr++ = ' ';
            std::string_view w = (wl_begin + ids[i])->first;
            __builtin_memcpy(ptr, w.data(), 16);
            ptr += w.size();
        }

        return ptr - out_buf;
    }

  private:
    static inline bool derive_child_key(const secp256k1_context* ctx, uint8_t* priv_key,
                                        uint8_t* chain_code, uint32_t index) noexcept {
        uint8_t data[37] = {0};
        // uint8_t data[37];

        if (index & 0x80000000u) {
            data[0] = 0;
            std::memcpy(data + 1, priv_key, 32);
        } else {
            secp256k1_pubkey pub;
            size_t pub_len = 33;
            (void) secp256k1_ec_pubkey_create(ctx, &pub, priv_key);
            secp256k1_ec_pubkey_serialize(ctx, data, &pub_len, &pub,
                                          SECP256K1_EC_COMPRESSED);
        }

        // Seriação big-endian do índice.
        data[33] = static_cast<uint8_t>(index >> 24);
        data[34] = static_cast<uint8_t>(index >> 16);
        data[35] = static_cast<uint8_t>(index >> 8);
        data[36] = static_cast<uint8_t>(index);

        uint8_t I[64];
        unsigned int len = sizeof(I);

        HMAC(EVP_sha512(), chain_code, 32, data, 37, I, &len);

        (void) secp256k1_ec_seckey_tweak_add(ctx, priv_key, I);

        std::memcpy(chain_code, I + 32, 32);
        return true;
    }

  public:
    static std::string derive_btc_address(const secp256k1_context* ctx,
                                          const std::vector<uint16_t>& mnemonic_ids,
                                          const std::flat_map<std::string, uint16_t>& wl,
                                          const char* passphrase = nullptr,
                                          size_t passphrase_len = 0) {
        char buf[MAX_MNEMONIC_LEN];
        size_t len = build_mnemonic_str(mnemonic_ids, wl, buf);

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

        // secp256k1_context* ctx = nullptr;
        // if (BUILTIN_EXPECT(!ctx, 0)) {
        //     ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        // }

        // array<uint8_t, 256> salt_buf;
        std::array<uint8_t, 256> salt_buf = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
        // uint8_t salt_buf[256];

        std::memcpy(salt_buf.data(), "mnemonic", 8);

        // std::memcpy(salt_buf, "mnemonic", 8);
        size_t salt_len = 8;
        if (passphrase && passphrase_len > 0) {
            std::memcpy(salt_buf.data() + 8, passphrase, passphrase_len);
            salt_len += passphrase_len;
        }

        crypto::pbkdf2_hmac_sha512(buf, len, salt_buf.data(), salt_len, 2048, seed, 64);

        unsigned int md_len = 64;
        HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, 64, master_node, &md_len);

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
                                          const std::flat_map<std::string, uint16_t>& wl,
                                          const char* passphrase = nullptr,
                                          size_t passphrase_len = 0) {
        char buf[MAX_MNEMONIC_LEN];
        size_t len = build_mnemonic_str(mnemonic_ids, wl, buf);

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

        unsigned int md_len = 64;
        HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, 64, master_node, &md_len);

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

        std::println("Seed byte 0: {:02x}", seed[0]); unsigned int md_len = 64;
        HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, 64, master_node, &md_len);

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

        unsigned int md_len = 64;
        HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, 64, master_node, &md_len);

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
