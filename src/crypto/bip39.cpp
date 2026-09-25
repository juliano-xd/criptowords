#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/base58.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/hmac_sha512.hpp"
#include "../../include/crypto/ripemd160.hpp"
#include "../../include/crypto/keccak256.hpp"
#include "../../include/crypto/secp256k1_point.hpp"
#include "../../include/crypto/secp256k1_scalar.hpp"
#include <cstring>
#include <array>

#ifndef BUILTIN_EXPECT
    #define BUILTIN_EXPECT(x, y) (__builtin_expect(!!(x), y))
#endif

namespace cryptowords {

struct BitcoinSeedHmacTemplate {
    crypto::HMAC_SHA512 hmac;

    BitcoinSeedHmacTemplate() {
        hmac.preset("Bitcoin seed", 12, 64);
    }

    inline void compute_master_node(const uint8_t* seed, std::array<uint8_t, 64> &master_node) const noexcept {
        hmac.complete(seed, 64, master_node);
    }
};

static const BitcoinSeedHmacTemplate& get_bitcoin_seed_template() {
    static const BitcoinSeedHmacTemplate tpl;
    return tpl;
}

size_t Bip39Deriver::build_mnemonic_str(std::span<const uint16_t> ids_vec,
                                        const std::vector<std::string>& wl,
                                        const std::string& separator,
                                        char* out_buf) noexcept {
    const size_t count = ids_vec.size();
    if (count == 0) return 0;

    const uint16_t* ids = ids_vec.data();
    char* ptr = out_buf;

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

bool Bip39Deriver::derive_child_key([[maybe_unused]] const secp256k1_context &ctx,
                                    std::array<uint8_t, 32> &priv_key,
                                    std::array<uint8_t, 32> &chain_code,
                                    uint32_t index) noexcept {
    std::array<uint8_t, 37> data;
    if (index >= 0x80000000) {
        data[0] = 0x00;
        std::memcpy(data.data() + 1, priv_key.data(), 32);
    } else {
        std::array<uint8_t, 33> pub;
        if (__builtin_expect(!crypto::secp256k1_pubkey_create_fast(pub, priv_key), 0)) return false;
        std::memcpy(data.data(), pub.data(), 33);
    }

    data[33] = static_cast<uint8_t>(index >> 24);
    data[34] = static_cast<uint8_t>(index >> 16);
    data[35] = static_cast<uint8_t>(index >> 8);
    data[36] = static_cast<uint8_t>(index);

    std::array<uint8_t, 64> I;
    crypto::HMAC_SHA512::bip32_hash(chain_code, data, I);

    if (__builtin_expect(!crypto::secp256k1_tweak_add_fast(priv_key.data(), I.data()), 0)) return false;

    std::memcpy(chain_code.data(), I.data() + 32, 32);
    return true;
}

static bool derive_bip44_privkey(const secp256k1_context& ctx,
                                 const uint8_t* seed,
                                 uint32_t coin_type,
                                 std::array<uint8_t, 32>& priv_key) noexcept {
    std::array<uint8_t, 64> master_node;
    std::array<uint8_t, 32> chain_code;
    get_bitcoin_seed_template().compute_master_node(seed, master_node);
    std::memcpy(priv_key.data(), master_node.data(), 32);
    std::memcpy(chain_code.data(), master_node.data() + 32, 32);

    return Bip39Deriver::derive_child_key(ctx, priv_key, chain_code, 0x8000002C) &&
           Bip39Deriver::derive_child_key(ctx, priv_key, chain_code, 0x80000000 | coin_type) &&
           Bip39Deriver::derive_child_key(ctx, priv_key, chain_code, 0x80000000) &&
           Bip39Deriver::derive_child_key(ctx, priv_key, chain_code, 0) &&
           Bip39Deriver::derive_child_key(ctx, priv_key, chain_code, 0);
}

bool Bip39Deriver::derive_child_key_hardened([[maybe_unused]] const secp256k1_context &ctx,
                                              std::array<uint8_t, 32> &priv_key,
                                              std::array<uint8_t, 32> &chain_code,
                                              uint32_t index) noexcept {
    return derive_child_key(ctx, priv_key, chain_code, index);
}

std::string Bip39Deriver::derive_btc_address_from_seed(const secp256k1_context &ctx,
                                                       const std::array<uint8_t, 64> &seed,
                                                       [[maybe_unused]] const char* passphrase,
                                                       [[maybe_unused]] size_t passphrase_len) noexcept {
    std::array<uint8_t, 32> priv_key;
    if (!derive_bip44_privkey(ctx, seed.data(), 0, priv_key)) return "";

    std::array<uint8_t, 33> pub_serialized;
    if (!crypto::secp256k1_pubkey_create_fast(pub_serialized, priv_key)) return "";

    std::array<uint8_t, 32> hash_buf;
    std::array<uint8_t, 20> ripemd_buf;
    crypto::SHA256::hash33(pub_serialized, hash_buf);
    crypto::RIPEMD160::hash32(hash_buf, ripemd_buf);

    std::array<uint8_t, 25> payload;
    payload[0] = 0x00;
    std::memcpy(payload.data() + 1, ripemd_buf.data(), 20);

    std::array<uint8_t, 32> checksum;
    crypto::SHA256::hash(payload.data(), 21, checksum.data());
    crypto::SHA256::hash(checksum.data(), 32, checksum.data());
    std::memcpy(payload.data() + 21, checksum.data(), 4);

    char result[100];
    size_t final_len = base58::encode_raw(payload.data(), 25, result);
    return std::string(result, final_len);
}

std::string Bip39Deriver::derive_eth_address_from_seed([[maybe_unused]] const secp256k1_context &ctx,
                                                       const uint8_t* seed,
                                                       [[maybe_unused]] const char* passphrase,
                                                       [[maybe_unused]] size_t passphrase_len) noexcept {
    std::array<uint8_t, 32> priv_key;
    if (!derive_bip44_privkey(ctx, seed, 60, priv_key)) return "";

    std::array<uint8_t, 65> pub_uncompressed;
    if (!crypto::secp256k1_pubkey_create_uncompressed(pub_uncompressed, priv_key)) return "";

    std::array<uint8_t, 32> hash_buf;
    crypto::Keccak256::hash(pub_uncompressed.data() + 1, 64, hash_buf.data());

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

bool Bip39Deriver::decode_base58_btc_address(const std::string& address, uint8_t out_ripemd[20]) noexcept {
    return base58::decode_btc_address(address, out_ripemd);
}

bool Bip39Deriver::decode_hex_eth_address(const std::string& hex_addr, uint8_t out_target[20]) noexcept {
    std::string_view s = hex_addr;
    if (s.length() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
    if (s.length() != 40) return false;
    for (size_t i = 0; i < 40; i++) {
        if (!std::isxdigit(static_cast<unsigned char>(s[i]))) return false;
    }
    auto hex_val = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        return static_cast<uint8_t>(c - 'A' + 10);
    };
    for (size_t i = 0; i < 20; i++) {
        out_target[i] = static_cast<uint8_t>((hex_val(s[i * 2]) << 4) | hex_val(s[i * 2 + 1]));
    }
    return true;
}

bool Bip39Deriver::check_btc_target_from_seed(const secp256k1_context* ctx,
                                               const uint8_t* seed,
                                               const uint8_t* target_ripemd,
                                               uint64_t target_fast64) noexcept {
    std::array<uint8_t, 32> priv_key;
    if (!derive_bip44_privkey(*ctx, seed, 0, priv_key)) return false;

    std::array<uint8_t, 33> pub_serialized;
    if (!crypto::secp256k1_pubkey_create_fast(pub_serialized, priv_key)) return false;

    std::array<uint8_t, 32> hash_buf;
    std::array<uint8_t, 20> ripemd_buf;
    crypto::SHA256::hash33(pub_serialized, hash_buf);
    crypto::RIPEMD160::hash32(hash_buf, ripemd_buf);

    // Otimização Matemática C1-64: Rejeição de 64 bits em 1 instrução (Probabilidade de falso positivo: 2^-64)
    uint64_t ripemd_fast64;
    std::memcpy(&ripemd_fast64, ripemd_buf.data(), 8);
    if (ripemd_fast64 != target_fast64) return false;
    return std::memcmp(ripemd_buf.data() + 8, target_ripemd + 8, 12) == 0;
}

bool Bip39Deriver::check_btc_target_from_seed(const secp256k1_context* ctx,
                                               const uint8_t* seed,
                                               const uint8_t* target_ripemd,
                                               [[maybe_unused]] uint32_t target_fast) noexcept {
    uint64_t target_fast64 = 0;
    std::memcpy(&target_fast64, target_ripemd, 8);
    return check_btc_target_from_seed(ctx, seed, target_ripemd, target_fast64);
}

bool Bip39Deriver::check_eth_target_from_seed([[maybe_unused]] const secp256k1_context &ctx,
                                               const uint8_t* seed,
                                               const uint8_t* target_eth,
                                               uint64_t target_fast64) noexcept {
    std::array<uint8_t, 32> priv_key;
    if (!derive_bip44_privkey(ctx, seed, 60, priv_key)) return false;

    std::array<uint8_t, 65> pub_uncompressed;
    if (!crypto::secp256k1_pubkey_create_uncompressed(pub_uncompressed, priv_key)) return false;

    std::array<uint8_t, 32> hash_buf;
    crypto::Keccak256::hash(pub_uncompressed.data() + 1, 64, hash_buf.data());

    // Otimização Matemática C1-64: Rejeição de 64 bits em 1 instrução (Probabilidade de falso positivo: 2^-64)
    uint64_t eth_fast64;
    std::memcpy(&eth_fast64, hash_buf.data() + 12, 8);
    if (__builtin_expect(eth_fast64 != target_fast64, 1)) return false;
    return std::memcmp(hash_buf.data() + 20, target_eth + 8, 12) == 0;
}

bool Bip39Deriver::check_eth_target_from_seed(const secp256k1_context &ctx,
                                               const uint8_t* seed,
                                               const uint8_t* target_eth,
                                               [[maybe_unused]] uint32_t target_fast) noexcept {
    uint64_t target_fast64 = 0;
    std::memcpy(&target_fast64, target_eth, 8);
    return check_eth_target_from_seed(ctx, seed, target_eth, target_fast64);
}

bool Bip39Deriver::verify_checksum(std::span<const uint16_t> mnemonic_ids) noexcept {
    const size_t n = mnemonic_ids.size();

    if (n < 12 || n > 24 || n % 3 != 0) [[unlikely]] return false;

    const size_t entropy_bytes = (n * 4) / 3;
    const unsigned checksum_bits = n / 3;
    const uint16_t* ids = mnemonic_ids.data();

    std::array<uint32_t, 8> data{};
    uint64_t buffer = 0;
    uint32_t* out = data.data();

    for (size_t i = 0, shift = 1; i < n; i += 3, ++shift) {
        const uint64_t chunk = (uint64_t(ids[i]) << 22) | (uint64_t(ids[i + 1]) << 11) | uint64_t(ids[i + 2]);
        buffer = (buffer << 33) | chunk;
        *out++ = __builtin_bswap32(static_cast<uint32_t>(buffer >> shift));
    }

    const uint8_t original_checksum = static_cast<uint8_t>(buffer & ((uint64_t{1} << checksum_bits) - 1));

    std::array<uint8_t, 32> hash{};
    crypto::SHA256::hash(data.data(), entropy_bytes, hash.data());

    return original_checksum == (hash[0] >> (8 - checksum_bits));
}

static void compute_bip39_seed(std::span<const uint16_t> mnemonic_ids,
                               const std::vector<std::string>& wl,
                               const char* passphrase,
                               size_t passphrase_len,
                               uint32_t rounds,
                               const std::string& separator,
                               uint8_t* out_seed) noexcept {
    char buf[MAX_MNEMONIC_LEN];
    size_t len = Bip39Deriver::build_mnemonic_str(mnemonic_ids, wl, separator, buf);

    uint8_t salt_buf[256];
    std::memcpy(salt_buf, "mnemonic", 8);
    size_t salt_len = 8;
    if (passphrase && passphrase_len > 0) {
        size_t copy_len = std::min(passphrase_len, sizeof(salt_buf) - 8);
        std::memcpy(salt_buf + 8, passphrase, copy_len);
        salt_len += copy_len;
    }

    crypto::pbkdf2_hmac_sha512(buf, len, salt_buf, salt_len, rounds, out_seed, 64);
}

std::string Bip39Deriver::derive_btc_address(const secp256k1_context* ctx,
                                             std::span<const uint16_t> mnemonic_ids,
                                             const std::vector<std::string>& wl,
                                             const char* passphrase,
                                             size_t passphrase_len,
                                             uint32_t rounds,
                                             const std::string& separator) noexcept {
    std::array<uint8_t, 64> seed;
    compute_bip39_seed(mnemonic_ids, wl, passphrase, passphrase_len, rounds, separator, seed.data());
    return derive_btc_address_from_seed(*ctx, seed, passphrase, passphrase_len);
}

std::string Bip39Deriver::derive_eth_address(const secp256k1_context &ctx,
                                             std::span<const uint16_t> mnemonic_ids,
                                             const std::vector<std::string>& wl,
                                             const char* passphrase,
                                             size_t passphrase_len,
                                             uint32_t rounds,
                                             const std::string& separator) {
    std::array<uint8_t, 64> seed;
    compute_bip39_seed(mnemonic_ids, wl, passphrase, passphrase_len, rounds, separator, seed.data());
    return derive_eth_address_from_seed(ctx, seed.data(), passphrase, passphrase_len);
}
} // namespace cryptowords
