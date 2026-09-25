#pragma once
#include <cstddef>
#include <cstdint>
#include <secp256k1.h>
#include <vector>

namespace cryptowords {

// Tamanho máximo de slot de senha por via SIMD (comporta 24 palavras em qualquer idioma UTF-8)
static constexpr size_t PW_SLOT_SIZE = 512;

// Todo o estado mutável de uma thread. Um contexto = um núcleo.
struct PipelineThreadContext {
    alignas(64) char     pw[16 * PW_SLOT_SIZE];
    alignas(64) uint8_t  seed[16 * 64];
    alignas(64) uint16_t valid_batch[16 * 24];
    alignas(64) uint16_t checksum_batch[32 * 24];

    size_t pw_len[16]     = {};
    size_t valid_batch_sz = 0;
    size_t c_batch_sz     = 0;

    uint8_t decoded_target[20] = {};
    uint8_t salt_buf[256]      = {};
    size_t  salt_len           = 0;
    alignas(64) uint64_t salt_block64[16] = {};
    bool    prefix_initialized = false;

    const secp256k1_context* ctx = nullptr;

    std::vector<size_t>   state;
    std::vector<uint16_t> current_ids;
    size_t thread_idx = 0;
    size_t step_size = 1;
    size_t pair_idx  = 0;
    size_t pair_end  = 0;
    size_t triplet_idx = 0;
    size_t triplet_end = 0;
    bool   is_done   = false;

    // OTM-03 / Generalização Afim em F_2^C (K >= 3)
    // No BIP-39, o checksum consome de 4 a 8 bits. Para um prefixo fixo, no máximo 128 palavras
    // (2048 / 2^4) satisfazem o checksum. 256 elementos garantem 100% de margem com 512 bytes em vez de 4KB.
    std::vector<size_t> outer_state;
    uint16_t k_last_w_list[256] = {};
    size_t   k_last_w_count = 0;
    size_t   k_last_w_idx   = 0;
    alignas(64) uint8_t k_block64[64] = {};

    // OTM-23: Fast-Forwarding PBKDF2 Round 1
    alignas(64) uint64_t kw_salt[80] = {};

    size_t local_tested = 0;
    size_t local_valid  = 0;

    ~PipelineThreadContext() = default;
};

} // namespace cryptowords
