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
    // BIP-32: HMAC-SHA512(chain_code, data[37]) — key 32B, msg 37B.
    // Otimização Algébrica: Sem alocação de buffers na stack, pré-formatação direta de palavras e compressão via registradores
    static void bip32_hash(const std::array<uint8_t, 32> &chain_code,
                           const std::array<uint8_t, 37> &data,
                           std::array<uint8_t, SHA512::digest_size> &out) noexcept {
        // 1. Bloco Inner Pad (128B) carregado diretamente em W[16]
        alignas(64) uint64_t w_in[16];
        w_in[0] = SHA512::load_be64(chain_code.data() + 0)  ^ 0x3636363636363636ULL;
        w_in[1] = SHA512::load_be64(chain_code.data() + 8)  ^ 0x3636363636363636ULL;
        w_in[2] = SHA512::load_be64(chain_code.data() + 16) ^ 0x3636363636363636ULL;
        w_in[3] = SHA512::load_be64(chain_code.data() + 24) ^ 0x3636363636363636ULL;
        #pragma GCC unroll 12
        for (int i = 4; i < 16; ++i) {
            w_in[i] = 0x3636363636363636ULL;
        }

        std::array<uint64_t, 8> inner_state = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        SHA512::compress_words(inner_state, w_in);

        // 2. Bloco Inner Msg (37B + padding) -> Total stream: 128 + 37 = 165 bytes (1320 bits)
        w_in[0] = SHA512::load_be64(data.data() + 0);
        w_in[1] = SHA512::load_be64(data.data() + 8);
        w_in[2] = SHA512::load_be64(data.data() + 16);
        w_in[3] = SHA512::load_be64(data.data() + 24);

        // Palavra 4: bytes 32..36 (5 bytes) + 0x80 + 2 bytes de zero
        uint64_t w4 = (static_cast<uint64_t>(data[32]) << 56) |
                      (static_cast<uint64_t>(data[33]) << 48) |
                      (static_cast<uint64_t>(data[34]) << 40) |
                      (static_cast<uint64_t>(data[35]) << 32) |
                      (static_cast<uint64_t>(data[36]) << 24) |
                      (0x80ULL << 16);
        w_in[4] = w4;

        #pragma GCC unroll 10
        for (int i = 5; i < 15; ++i) {
            w_in[i] = 0ULL;
        }
        w_in[15] = 1320ULL;

        SHA512::compress_words(inner_state, w_in);

        // 3. Bloco Outer Pad (128B)
        w_in[0] = SHA512::load_be64(chain_code.data() + 0)  ^ 0x5c5c5c5c5c5c5c5cULL;
        w_in[1] = SHA512::load_be64(chain_code.data() + 8)  ^ 0x5c5c5c5c5c5c5c5cULL;
        w_in[2] = SHA512::load_be64(chain_code.data() + 16) ^ 0x5c5c5c5c5c5c5c5cULL;
        w_in[3] = SHA512::load_be64(chain_code.data() + 24) ^ 0x5c5c5c5c5c5c5c5cULL;
        #pragma GCC unroll 12
        for (int i = 4; i < 16; ++i) {
            w_in[i] = 0x5c5c5c5c5c5c5c5cULL;
        }

        std::array<uint64_t, 8> outer_state = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        SHA512::compress_words(outer_state, w_in);

        // 4. Bloco Outer Msg (64B + padding) -> Total stream: 128 + 64 = 192 bytes (1536 bits)
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            w_in[i] = inner_state[i];
        }
        w_in[8] = 0x8000000000000000ULL;
        #pragma GCC unroll 6
        for (int i = 9; i < 15; ++i) {
            w_in[i] = 0ULL;
        }
        w_in[15] = 1536ULL;

        SHA512::compress_words(outer_state, w_in);

        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            uint64_t s_be = std::byteswap(outer_state[i]);
            std::memcpy(out.data() + i * 8, &s_be, 8);
        }
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

        if (key_len == 32) {
            constexpr uint64_t IPAD64 = 0x3636363636363636ULL;
            constexpr uint64_t OPAD64 = 0x5c5c5c5c5c5c5c5cULL;
            const auto* k_words = static_cast<const uint64_t*>(key);
            auto* ip_words = reinterpret_cast<uint64_t*>(ipad.data());
            auto* op_words = reinterpret_cast<uint64_t*>(opad.data());
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
        for (size_t i = 0; i < k_use_len; ++i) {
            ipad[i] ^= k_use[i];
            opad[i] ^= k_use[i];
        }
    }
};

void pbkdf2_hmac_sha512(const char* password, size_t password_len,
                        const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len);

} // namespace crypto
