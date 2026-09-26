#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
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
    void init(const uint8_t* key, const size_t key_len) noexcept {
        std::array<uint8_t, SHA512::block_size> ipad;
        std::array<uint8_t, SHA512::block_size> opad;
        build_pads(key, key_len, ipad, opad);

        inner_.reset();
        inner_.update(ipad.data(), SHA512::block_size);
        inner_base_ = inner_;

        // O outer recebe SEMPRE 64 bytes (o inner_hash) — template perfeito.
        outer_base_.preset(opad.data(), SHA512::block_size, SHA512::digest_size);

        is_preset_ = false;
        expected_len_ = 0;
    }

    void update(const uint8_t* data, const size_t len) noexcept { inner_.update(data, len); }

    void finalize(uint8_t* out) noexcept {
        std::array<uint8_t, SHA512::digest_size> inner_hash;
        inner_.finalize(inner_hash.data());

        alignas(64) uint64_t W[16];
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            W[i] = SHA512::load_be64(inner_hash.data() + i * 8);
        }
        uint64_t outer_words[8];
        SHA512::compress_padded_block64(outer_state(), W, outer_words);

#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            SHA512::store_be64(out + i * 8, outer_words[i]);
        }
    }

    void reset_inner() noexcept { inner_ = inner_base_; }

    // =========================================================
    // TEMPLATE / PRESET API
    // =========================================================
    void preset(const void* key, const size_t key_len, const size_t expected_data_len = 0) noexcept {
        std::array<uint8_t, SHA512::block_size> ipad;
        std::array<uint8_t, SHA512::block_size> opad;
        build_pads(key, key_len, ipad, opad);

        inner_base_.preset(ipad.data(), SHA512::block_size, expected_data_len);
        inner_ = inner_base_;
        outer_base_.preset(opad.data(), SHA512::block_size, SHA512::digest_size);

        is_preset_ = true;
        expected_len_ = expected_data_len;
    }

    void complete(const void* data, size_t len, std::array<uint8_t, SHA512::digest_size>& out) const noexcept {
        if (len == 64 && is_preset_ && expected_len_ == 64) {
            alignas(64) uint64_t W[16];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                W[i] = SHA512::load_be64(static_cast<const uint8_t*>(data) + i * 8);
            }
            uint64_t inner_words[8];
            SHA512::compress_padded_block64(inner_state(), W, inner_words);

#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                W[i] = inner_words[i];
            }
            uint64_t outer_words[8];
            SHA512::compress_padded_block64(outer_state(), W, outer_words);

#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                SHA512::store_be64(out.data() + i * 8, outer_words[i]);
            }
            return;
        }

        std::array<uint8_t, SHA512::digest_size> inner_hash;
        inner_base_.complete(data, len, inner_hash.data());

        alignas(64) uint64_t W[16];
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            W[i] = SHA512::load_be64(inner_hash.data() + i * 8);
        }
        uint64_t outer_words[8];
        SHA512::compress_padded_block64(outer_state(), W, outer_words);

#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            SHA512::store_be64(out.data() + i * 8, outer_words[i]);
        }
    }

    void complete(const void* data, std::array<uint8_t, SHA512::digest_size>& out) const noexcept {
        complete(data, expected_len_, out);
    }

    // =========================================================
    // STATIC FAST-PATHS & ONE-SHOT API
    // =========================================================
    static void hash(const void* key, size_t key_len, const void* data, size_t data_len,
                     std::array<uint8_t, SHA512::digest_size>& out) noexcept {
        if (key_len == 32 && data_len == 64) {
            uint64_t kw[4];
#pragma GCC unroll 4
            for (int i = 0; i < 4; ++i) {
                kw[i] = SHA512::load_be64(static_cast<const uint8_t*>(key) + i * 8);
            }
            uint64_t inner_iv[8], outer_iv[8];
            SHA512::compress_pad128_32bytekey<0x3636363636363636ULL>(kw, inner_iv);
            SHA512::compress_pad128_32bytekey<0x5c5c5c5c5c5c5c5cULL>(kw, outer_iv);

            alignas(64) uint64_t W[16];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                W[i] = SHA512::load_be64(static_cast<const uint8_t*>(data) + i * 8);
            }
            uint64_t inner[8];
            SHA512::compress_padded_block64(inner_iv, W, inner);

#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                W[i] = inner[i];
            }
            uint64_t outer[8];
            SHA512::compress_padded_block64(outer_iv, W, outer);

#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                SHA512::store_be64(out.data() + i * 8, outer[i]);
            }
            return;
        }

        if (key_len == 64 && data_len == 64) {
            uint64_t kw[8];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                kw[i] = SHA512::load_be64(static_cast<const uint8_t*>(key) + i * 8);
            }
            uint64_t inner_iv[8], outer_iv[8];
            SHA512::compress_pad128_64bytekey<0x3636363636363636ULL>(kw, inner_iv);
            SHA512::compress_pad128_64bytekey<0x5c5c5c5c5c5c5c5cULL>(kw, outer_iv);

            alignas(64) uint64_t W[16];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                W[i] = SHA512::load_be64(static_cast<const uint8_t*>(data) + i * 8);
            }
            uint64_t inner[8];
            SHA512::compress_padded_block64(inner_iv, W, inner);

#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                W[i] = inner[i];
            }
            uint64_t outer[8];
            SHA512::compress_padded_block64(outer_iv, W, outer);

#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                SHA512::store_be64(out.data() + i * 8, outer[i]);
            }
            return;
        }

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
    // Otimização Algébrica: Todos os 4 blocos (Pad128, Msg37, Pad128, Msg64)
    // usam expansão e compressão direta com constantes fundidas, sem stack overhead.
    static void bip32_hash(const std::array<uint8_t, 32>& chain_code, const std::array<uint8_t, 37>& data,
                           std::array<uint8_t, SHA512::digest_size>& out) noexcept {
        uint64_t cc_words[4];
        cc_words[0] = SHA512::load_be64(chain_code.data() + 0);
        cc_words[1] = SHA512::load_be64(chain_code.data() + 8);
        cc_words[2] = SHA512::load_be64(chain_code.data() + 16);
        cc_words[3] = SHA512::load_be64(chain_code.data() + 24);

        // 1. Bloco Inner Pad (128B) -> FUSED pad128
        uint64_t inner_state[8];
        SHA512::compress_pad128_32bytekey<0x3636363636363636ULL>(cc_words, inner_state);

        // 2. Bloco Inner Msg (37B + padding) -> FUSED block37
        alignas(64) uint64_t w_in[16];
        w_in[0] = SHA512::load_be64(data.data() + 0);
        w_in[1] = SHA512::load_be64(data.data() + 8);
        w_in[2] = SHA512::load_be64(data.data() + 16);
        w_in[3] = SHA512::load_be64(data.data() + 24);

        uint64_t w4 = (static_cast<uint64_t>(data[32]) << 56) | (static_cast<uint64_t>(data[33]) << 48) |
                      (static_cast<uint64_t>(data[34]) << 40) | (static_cast<uint64_t>(data[35]) << 32) |
                      (static_cast<uint64_t>(data[36]) << 24) | (0x80ULL << 16);
        w_in[4] = w4;

        uint64_t final_inner[8];
        SHA512::compress_padded_block37(inner_state, w_in, final_inner);

        // 3. Bloco Outer Pad (128B) -> FUSED pad128
        uint64_t outer_state[8];
        SHA512::compress_pad128_32bytekey<0x5c5c5c5c5c5c5c5cULL>(cc_words, outer_state);

// 4. Bloco Outer Msg (64B + padding) -> FUSED block64
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            w_in[i] = final_inner[i];
        }

        uint64_t final_outer[8];
        SHA512::compress_padded_block64(outer_state, w_in, final_outer);

#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            SHA512::store_be64(out.data() + i * 8, final_outer[i]);
        }
    }

    static void hash_single_block(const void* key, size_t key_len, const void* data, size_t data_len,
                                  std::array<uint8_t, SHA512::digest_size>& out) noexcept {
        HMAC_SHA512 h;
        h.preset(key, key_len, data_len);
        h.complete(data, out);
    }

   public:
    SHA512 inner_;
    SHA512 outer_base_;
    SHA512 inner_base_;

    const uint64_t* inner_state() const noexcept { return inner_base_.h_.data(); }
    const uint64_t* outer_state() const noexcept { return outer_base_.h_.data(); }

   private:
    bool is_preset_ = false;
    size_t expected_len_ = 0;

    // Constrói os dois pads (ipad/opad) já XORados com a chave normalizada.
    static void build_pads(const void* key, const size_t key_len, std::array<uint8_t, SHA512::block_size>& ipad,
                           std::array<uint8_t, SHA512::block_size>& opad) noexcept {
        constexpr uint64_t IPAD64 = 0x3636363636363636ULL;
        constexpr uint64_t OPAD64 = 0x5c5c5c5c5c5c5c5cULL;

        auto* ip_words = reinterpret_cast<uint64_t*>(ipad.data());
        auto* op_words = reinterpret_cast<uint64_t*>(opad.data());

        if (key_len == 32) {
            const auto* k_words = static_cast<const uint64_t*>(key);
#pragma GCC unroll 4
            for (size_t i = 0; i < 4; ++i) {
                ip_words[i] = k_words[i] ^ IPAD64;
                op_words[i] = k_words[i] ^ OPAD64;
            }
#pragma GCC unroll 12
            for (size_t i = 4; i < 16; ++i) {
                ip_words[i] = IPAD64;
                op_words[i] = OPAD64;
            }
            return;
        }

        if (key_len == 64) {
            const auto* k_words = static_cast<const uint64_t*>(key);
#pragma GCC unroll 8
            for (size_t i = 0; i < 8; ++i) {
                ip_words[i] = k_words[i] ^ IPAD64;
                op_words[i] = k_words[i] ^ OPAD64;
            }
#pragma GCC unroll 8
            for (size_t i = 8; i < 16; ++i) {
                ip_words[i] = IPAD64;
                op_words[i] = OPAD64;
            }
            return;
        }

        alignas(16) std::array<uint8_t, SHA512::block_size> k_use{};
        if (key_len > SHA512::block_size) {
            SHA512::hash(key, key_len, k_use.data());
        } else if (key_len > 0) {
            std::memcpy(k_use.data(), key, key_len);
        }
        const auto* k_words = reinterpret_cast<const uint64_t*>(k_use.data());
#pragma GCC unroll 16
        for (size_t i = 0; i < 16; ++i) {
            ip_words[i] = k_words[i] ^ IPAD64;
            op_words[i] = k_words[i] ^ OPAD64;
        }
    }
};

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len, int iterations,
                        uint8_t* out, size_t out_len);

}  // namespace crypto
