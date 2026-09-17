#pragma once
#include <cstdint>
#include <cstddef>
#include "sha512.hpp"

namespace crypto {

class HMAC_SHA512 {
  public:
    HMAC_SHA512() = default;
    HMAC_SHA512(const void* key, size_t key_len);

    // =========================================================
    // STREAMING API (Compatibilidade Total)
    // =========================================================
    void init(const uint8_t* key, size_t key_len);
    void update(const uint8_t* data, size_t len);
    void finalize(uint8_t* out);
    void reset_inner();

    // =========================================================
    // TEMPLATE / PRESET API (Capacidades Reais do SHA-512)
    // =========================================================
    // Pré-computa os midstates do ipad e do opad uma única vez.
    // Se expected_data_len <= 111, pré-calcula tabelas de W e padding completos.
    // Chamadas subsequentes a complete() executam apenas os blocos variáveis (2x mais rápido).
    void preset(const void* key, size_t key_len, size_t expected_data_len = 0);
    void complete(const void* data, size_t len, uint8_t out[64]) const;
    void complete(const void* data, uint8_t out[64]) const;

    // =========================================================
    // STATIC FAST-PATHS & ONE-SHOT API
    // =========================================================
    // One-shot HMAC sem overhead de instâncias temporárias ou buffers dinâmicos
    static void hash(const void* key, size_t key_len,
                     const void* data, size_t data_len,
                     uint8_t out[64]);

    // Fast-path dedicado para derivação de chaves BIP-32 HD (key: 32B, data: 37B)
    static void bip32_hash(const uint8_t chain_code[32],
                           const uint8_t data[37],
                           uint8_t out[64]);

    // Fast-path para mensagens de bloco único (len <= 111 bytes)
    static void hash_single_block(const void* key, size_t key_len,
                                  const void* data, size_t data_len,
                                  uint8_t out[64]);

  public:
    SHA512 inner_;
    SHA512 outer_base_;
    SHA512 inner_base_;

  private:
    bool   is_preset_ = false;
    size_t expected_len_ = 0;
};

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len);

} // namespace crypto
