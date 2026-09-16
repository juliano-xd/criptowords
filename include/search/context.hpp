#pragma once
#include <cstddef>
#include <cstdint>
#include <secp256k1.h>
#include <vector>

namespace cryptowords {

// Todo o estado mutável de uma thread. Um contexto = um núcleo.
struct PipelineThreadContext {
    alignas(64) char     pw[16 * 256];
    alignas(64) uint8_t  seed[16 * 64];
    alignas(64) uint16_t valid_batch[16 * 24];
    alignas(64) uint16_t checksum_batch[32 * 24];

    size_t pw_len[16]     = {};
    size_t valid_batch_sz = 0;
    size_t c_batch_sz     = 0;

    uint8_t decoded_target[20] = {};
    uint8_t salt_buf[1024]     = {};
    size_t  salt_len           = 0;

    secp256k1_context* ctx = nullptr;

    std::vector<size_t>   state;
    std::vector<uint16_t> current_ids;
    size_t step_size = 1;
    bool   is_done   = false;

    size_t local_tested = 0;
    size_t local_valid  = 0;

    ~PipelineThreadContext() {
        if (ctx) secp256k1_context_destroy(ctx);
    }
};

} // namespace cryptowords
