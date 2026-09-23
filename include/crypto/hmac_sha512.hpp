#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "sha512.hpp"

namespace crypto {

class HMAC_SHA512 {
public:
    HMAC_SHA512() noexcept = default;
    HMAC_SHA512(const void* key, size_t key_len) noexcept { init((uint8_t*)key, key_len); }

    // =========================================================
    // STREAMING API
    // =========================================================
    constexpr void init(const uint8_t* key, const size_t key_len) noexcept {
        std::array<uint8_t, SHA512::block_size> ipad;
        std::array<uint8_t, SHA512::block_size> opad;
        build_pads(key, key_len, ipad, opad);

        inner_.reset();
        inner_.update(ipad.data(), SHA512::block_size);
        inner_base_ = inner_;

        // O outer recebe SEMPRE 64 bytes (o inner_hash) — template perfeito.
        outer_base_.preset(opad.data(), SHA512::block_size, SHA512::digest_size);

        is_preset_    = false;
        expected_len_ = 0;
    }

    constexpr void update(const uint8_t* data,const size_t len) noexcept {
        inner_.update(data, len);
    }

    void finalize(uint8_t* out) noexcept {
        std::array<uint8_t, SHA512::digest_size> inner_hash;
        inner_.finalize(inner_hash.data());
        outer_base_.complete(inner_hash.data(), out);
    }

    void reset_inner() noexcept { inner_ = inner_base_; }

    // =========================================================
    // TEMPLATE / PRESET API
    // =========================================================
    constexpr void preset(const void* key,const size_t key_len, const size_t expected_data_len = 0) noexcept {
        std::array<uint8_t, SHA512::block_size> ipad;
        std::array<uint8_t, SHA512::block_size> opad;
        build_pads(key, key_len, ipad, opad);

        inner_base_.preset(ipad.data(), SHA512::block_size, expected_data_len);
        inner_ = inner_base_;
        outer_base_.preset(opad.data(), SHA512::block_size, SHA512::digest_size);

        is_preset_    = true;
        expected_len_ = expected_data_len;
    }

    constexpr void complete(const void* data, size_t len, std::array<uint8_t, SHA512::digest_size> &out) const noexcept {
        std::array<uint8_t, SHA512::digest_size> inner_hash;
        inner_base_.complete(data, len, inner_hash.data());
        outer_base_.complete(inner_hash.data(), out.data());
    }

    constexpr void complete(const void* data, std::array<uint8_t, SHA512::digest_size> &out) const noexcept {
        complete(data, expected_len_, out);
    }

    // =========================================================
    // STATIC FAST-PATHS & ONE-SHOT API
    // =========================================================
    constexpr static void hash(const void* key, size_t key_len, const void* data, size_t data_len, std::array<uint8_t, SHA512::digest_size> &out) noexcept {
        // Caminho rápido: mensagem cabe em um único bloco após o ipad.
        if (data_len <= 111) {
            HMAC_SHA512 h;
            h.preset(key, key_len, data_len);
            h.complete(data, out);
        } else {
            HMAC_SHA512 h;
            h.init(static_cast<const uint8_t*>(key), key_len);
            h.update(static_cast<const uint8_t*>(data), data_len);
            h.finalize(out.data());
        }
    }

    // BIP-32: HMAC-SHA512(chain_code, data[37]) — key 32B, msg 37B.
    // O preset gera template de bloco único; complete faz 2 compressões.
    static void bip32_hash(const std::array<uint8_t, 32> &chain_code,
                           const std::array<uint8_t, 37> &data,
                           std::array<uint8_t, SHA512::digest_size> &out) noexcept {
        HMAC_SHA512 h;
        h.preset(chain_code.data(), 32, 37);
        h.complete(data.data(), 37, out);
    }

    static void hash_single_block(const void* key, size_t key_len,
                                  const void* data, size_t data_len,
                                  std::array<uint8_t, SHA512::digest_size> &out) noexcept {
        HMAC_SHA512 h;
        h.preset(key, key_len, data_len);
        h.complete(data, out);
    }

public:
    SHA512 inner_;
    SHA512 outer_base_;
    SHA512 inner_base_;

private:
    bool   is_preset_    = false;
    size_t expected_len_ = 0;

    // Constrói os dois pads (ipad/opad) já XORados com a chave normalizada.
    constexpr static void build_pads(const void* key,const size_t key_len,
        std::array<uint8_t, SHA512::block_size> &ipad,
        std::array<uint8_t, SHA512::block_size> &opad) noexcept {

        std::array<uint8_t, SHA512::block_size> k_use{};
        size_t  k_use_len = 0;
        if (key_len > SHA512::block_size) {
            SHA512::hash(key, key_len, k_use.data());
            k_use_len = SHA512::digest_size;
        } else if (key_len > 0) {
            std::memcpy(k_use.data(), key, key_len);
            k_use_len = key_len;
        }
        std::memset(ipad.data(), 0x36, SHA512::block_size);
        std::memset(opad.data(), 0x5c, SHA512::block_size);
        if (key_len == 32) {
            const auto* k_words = static_cast<const uint64_t*>(key);
            auto* ip_words = reinterpret_cast<uint64_t*>(ipad.data());
            auto* op_words = reinterpret_cast<uint64_t*>(opad.data());
            #pragma GCC unroll 4
            for (size_t i = 0; i < 4; ++i) {
                ip_words[i] ^= k_words[i];
                op_words[i] ^= k_words[i];
            }
        } else {
            for (size_t i = 0; i < k_use_len; ++i) {
                ipad[i] ^= k_use[i];
                opad[i] ^= k_use[i];
            }
        }
    }
};

void pbkdf2_hmac_sha512(const char* password, size_t password_len,
                        const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len);

} // namespace crypto
