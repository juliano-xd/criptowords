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
    HMAC_SHA512(const void* key, size_t key_len) noexcept {
        init(static_cast<const uint8_t*>(key), key_len);
    }

    // ---- Streaming API ----
    void init(const uint8_t* key, const size_t key_len) noexcept {
        alignas(64) std::array<uint8_t, SHA512::block_size> pad;
        build_ipad(key, key_len, pad);

        inner_.reset();
        inner_.update(pad.data(), pad.size());
        inner_base_ = inner_;

        // Reutiliza o mesmo bloco: (K ^ 0x36) ^ 0x6A == K ^ 0x5C.
        make_opad(pad);
        outer_state_ = SHA512::IV_;
        SHA512::compress(outer_state_, pad.data());

        is_preset_ = false;
        expected_len_ = 0;
    }

    void update(const uint8_t* data, const size_t len) noexcept { inner_.update(data, len); }

    void finalize(uint8_t* out) noexcept {
        std::array<uint8_t, SHA512::digest_size> inner_hash;
        inner_.finalize(inner_hash.data());
        finish_outer(outer_state(), inner_hash.data(), out);
    }

    void reset_inner() noexcept { inner_ = inner_base_; }

    // ---- Template / preset API ----
    void preset(const void* key, const size_t key_len, const size_t expected_data_len = 0) noexcept {
        alignas(64) std::array<uint8_t, SHA512::block_size> pad;
        build_ipad(key, key_len, pad);

        inner_base_.preset(pad.data(), pad.size(), expected_data_len);
        inner_ = inner_base_;

        make_opad(pad);
        outer_state_ = SHA512::IV_;
        SHA512::compress(outer_state_, pad.data());

        is_preset_ = true;
        expected_len_ = expected_data_len;
    }

    void complete(const void* data, size_t len,
                  std::array<uint8_t, SHA512::digest_size>& out) const noexcept {
        // A compressão rápida usa o comprimento SHA-512 real do HMAC:
        // 128 bytes de ipad + 64 bytes de mensagem = 1536 bits.
        if (len == 64 && is_preset_ && expected_len_ == 64) {
            alignas(64) uint64_t message_words[8];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i)
                message_words[i] = SHA512::load_be64(static_cast<const uint8_t*>(data) + i * 8);

            alignas(64) uint64_t inner_words[8];
            compress_hmac64(inner_state(), message_words, inner_words);
            finish_outer_words(outer_state(), inner_words, out.data());
            return;
        }

        std::array<uint8_t, SHA512::digest_size> inner_hash;
        inner_base_.complete(data, len, inner_hash.data());
        finish_outer(outer_state(), inner_hash.data(), out.data());
    }

    void complete(const void* data, std::array<uint8_t, SHA512::digest_size>& out) const noexcept {
        complete(data, expected_len_, out);
    }

    // ---- One-shot hash ----
    static void hash(const void* key, size_t key_len, const void* data, size_t data_len,
                     std::array<uint8_t, SHA512::digest_size>& out) noexcept {
        // Fast paths dedicados para key 32/64 B + data 64 B (casos dominantes em BIP-32).
        if (data_len == 64 && (key_len == 32 || key_len == 64)) {
            alignas(64) std::array<uint64_t, 8> inner_iv = SHA512::IV_;
            alignas(64) std::array<uint64_t, 8> outer_iv = SHA512::IV_;
            if (key_len == 32) {
                uint64_t kw[4];
#pragma GCC unroll 4
                for (int i = 0; i < 4; ++i)
                    kw[i] = SHA512::load_be64(static_cast<const uint8_t*>(key) + i * 8);
                SHA512::compress_pad128_32bytekey<0x3636363636363636ULL>(kw, inner_iv.data());
                SHA512::compress_pad128_32bytekey<0x5c5c5c5c5c5c5c5cULL>(kw, outer_iv.data());
            } else {
                uint64_t kw[8];
#pragma GCC unroll 8
                for (int i = 0; i < 8; ++i)
                    kw[i] = SHA512::load_be64(static_cast<const uint8_t*>(key) + i * 8);
                SHA512::compress_pad128_64bytekey<0x3636363636363636ULL>(kw, inner_iv.data());
                SHA512::compress_pad128_64bytekey<0x5c5c5c5c5c5c5c5cULL>(kw, outer_iv.data());
            }

            alignas(64) uint64_t message_words[8];
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i)
                message_words[i] = SHA512::load_be64(static_cast<const uint8_t*>(data) + i * 8);

            alignas(64) uint64_t inner[8];
            compress_hmac64(inner_iv.data(), message_words, inner);
            finish_outer_words(outer_iv.data(), inner, out.data());
            return;
        }

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
    // Outer pad é independente da mensagem; computá-lo antes aumenta ILP.
    static void bip32_hash(const std::array<uint8_t, 32>& chain_code,
                           const std::array<uint8_t, 37>& data,
                           std::array<uint8_t, SHA512::digest_size>& out) noexcept {
        uint64_t cc_words[4];
        cc_words[0] = SHA512::load_be64(chain_code.data() +  0);
        cc_words[1] = SHA512::load_be64(chain_code.data() +  8);
        cc_words[2] = SHA512::load_be64(chain_code.data() + 16);
        cc_words[3] = SHA512::load_be64(chain_code.data() + 24);

        alignas(64) std::array<uint64_t, 8> outer_state = SHA512::IV_;
        SHA512::compress_pad128_32bytekey<0x5c5c5c5c5c5c5c5cULL>(cc_words, outer_state.data());

        alignas(64) std::array<uint64_t, 8> inner_state = SHA512::IV_;
        SHA512::compress_pad128_32bytekey<0x3636363636363636ULL>(cc_words, inner_state.data());

        alignas(64) uint64_t w_in[16] = {};
        w_in[0] = SHA512::load_be64(data.data() +  0);
        w_in[1] = SHA512::load_be64(data.data() +  8);
        w_in[2] = SHA512::load_be64(data.data() + 16);
        w_in[3] = SHA512::load_be64(data.data() + 24);
        w_in[4] = (static_cast<uint64_t>(data[32]) << 56) |
                  (static_cast<uint64_t>(data[33]) << 48) |
                  (static_cast<uint64_t>(data[34]) << 40) |
                  (static_cast<uint64_t>(data[35]) << 32) |
                  (static_cast<uint64_t>(data[36]) << 24) |
                  (0x80ULL << 16);

        // Prefixo ipad + mensagem de 37 bytes = 165 bytes = 1320 bits.
        // A compressão genérica mantém esse comprimento exato no bloco final.
        w_in[15] = 1320;
        alignas(64) uint64_t final_inner[8];
        compress_block(inner_state.data(), w_in, final_inner);
        finish_outer_words(outer_state.data(), final_inner, out.data());
    }

    static void hash_single_block(const void* key, size_t key_len, const void* data, size_t data_len,
                                  std::array<uint8_t, SHA512::digest_size>& out) noexcept {
        HMAC_SHA512 h;
        h.preset(key, key_len, data_len);
        h.complete(data, out);
    }

   public:
    SHA512 inner_;
    alignas(64) std::array<uint64_t, 8> outer_state_{};
    SHA512 inner_base_;

    const uint64_t* inner_state() const noexcept { return inner_base_.h_.data(); }
    const uint64_t* outer_state() const noexcept { return outer_state_.data(); }

   private:
    bool is_preset_ = false;
    size_t expected_len_ = 0;

    // Cria apenas o ipad. O mesmo buffer é transformado em opad depois
    // que o estado interno já consumiu o ipad.
    static void build_ipad(
        const void* key,
        const size_t key_len,
        std::array<uint8_t, SHA512::block_size>& ipad
    ) noexcept {
        constexpr uint8_t IPAD_BYTE = 0x36;
        constexpr uint64_t IPAD_WORD = 0x3636363636363636ULL;

        ipad.fill(IPAD_BYTE);

        if (key_len == 0)
            return;

        const auto* key_bytes = static_cast<const uint8_t*>(key);

        // Caminhos comuns BIP-32. memcpy permite chaves desalinhadas sem
        // violar alinhamento nem strict-aliasing.
        if (key_len == 32 || key_len == 64) {
            for (size_t offset = 0; offset < key_len; offset += sizeof(uint64_t)) {
                uint64_t word;
                std::memcpy(&word, key_bytes + offset, sizeof(word));
                word ^= IPAD_WORD;
                std::memcpy(ipad.data() + offset, &word, sizeof(word));
            }
            return;
        }

        if (key_len > SHA512::block_size) {
            std::array<uint8_t, SHA512::digest_size> hashed_key;
            SHA512::hash(key, key_len, hashed_key.data());

            for (size_t i = 0; i < hashed_key.size(); ++i)
                ipad[i] = static_cast<uint8_t>(hashed_key[i] ^ IPAD_BYTE);
            return;
        }

        std::memcpy(ipad.data(), key_bytes, key_len);
        for (size_t i = 0; i < key_len; ++i)
            ipad[i] ^= IPAD_BYTE;
    }

    static void make_opad(std::array<uint8_t, SHA512::block_size>& pad) noexcept {
        // (K ^ 0x36) ^ 0x6A == K ^ 0x5C, byte a byte.
        for (auto& byte : pad)
            byte ^= 0x6A;
    }

    // Comprime um bloco de palavras SHA-512 sem impor o comprimento de
    // mensagem de 512 bits usado pelo helper compress_padded_block64.
    static void compress_block(
        const uint64_t* initial_state,
        const uint64_t block_words[16],
        uint64_t out[8]
    ) noexcept {
        alignas(64) std::array<uint64_t, 8> state;
        std::memcpy(state.data(), initial_state, sizeof(state));
        SHA512::compress_words(state, block_words);
        std::memcpy(out, state.data(), sizeof(state));
    }

    // Comprime o bloco final para HMAC(prefixo ipad/opad de 128 bytes,
    // mensagem de 64 bytes). O campo de comprimento precisa ser 1536 bits.
    static void compress_hmac64(
        const uint64_t* initial_state,
        const uint64_t message_words[8],
        uint64_t out[8]
    ) noexcept {
        alignas(64) uint64_t words[16]{};
        std::memcpy(words, message_words, 8 * sizeof(uint64_t));
        words[8] = 0x8000000000000000ULL;
        words[15] = 1536;
        compress_block(initial_state, words, out);
    }

    static void finish_outer_words(
        const uint64_t* outer_state,
        const uint64_t inner_words[8],
        uint8_t* out
    ) noexcept {
        alignas(64) uint64_t outer_words[8];
        compress_hmac64(outer_state, inner_words, outer_words);

#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            SHA512::store_be64(out + i * 8, outer_words[i]);
    }

    static void finish_outer(
        const uint64_t* outer_state,
        const uint8_t* inner_hash,
        uint8_t* out
    ) noexcept {
        alignas(64) uint64_t inner_words[8];
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i)
            inner_words[i] = SHA512::load_be64(inner_hash + i * 8);

        finish_outer_words(outer_state, inner_words, out);
    }

};

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt,
                        size_t salt_len, int iterations, uint8_t* out, size_t out_len);

}  // namespace crypto
