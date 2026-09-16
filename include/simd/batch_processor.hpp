#pragma once
#include "../config.hpp"
#include "../search/context.hpp"
#include "../search/processor.hpp"
#include "arch.hpp"

#include "../crypto/bip39.hpp"
#include "../crypto/hmac_sha512.hpp"
#include "../crypto/pbkdf2_simd.hpp"
#include "../crypto/sha256.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <vector>

namespace cryptowords {

template <SimdArch Arch, bool AutoDeduce, bool OnlyValids>
class SimdBatchProcessor : public IBatchProcessor {
    static constexpr size_t BATCH_SIZE   = ArchTraits<Arch>::BATCH_SIZE;
    static constexpr size_t C_BATCH_SIZE = ArchTraits<Arch>::C_BATCH_SIZE;

    void process_simd_pbkdf2(PipelineThreadContext& ctx, uint32_t rounds) {
        if constexpr (Arch == SimdArch::SSE) {
            pbkdf2_hmac_sha512_4way_sse(
                ctx.pw + 0*256, ctx.pw_len[0], ctx.pw + 1*256, ctx.pw_len[1],
                ctx.pw + 2*256, ctx.pw_len[2], ctx.pw + 3*256, ctx.pw_len[3],
                ctx.salt_buf, ctx.salt_len, rounds,
                ctx.seed + 0*64, ctx.seed + 1*64, ctx.seed + 2*64, ctx.seed + 3*64
            );
        } else if constexpr (Arch == SimdArch::AVX2) {
            pbkdf2_hmac_sha512_8way_avx2(
                ctx.pw + 0*256, ctx.pw_len[0], ctx.pw + 1*256, ctx.pw_len[1],
                ctx.pw + 2*256, ctx.pw_len[2], ctx.pw + 3*256, ctx.pw_len[3],
                ctx.pw + 4*256, ctx.pw_len[4], ctx.pw + 5*256, ctx.pw_len[5],
                ctx.pw + 6*256, ctx.pw_len[6], ctx.pw + 7*256, ctx.pw_len[7],
                ctx.salt_buf, ctx.salt_len, rounds,
                ctx.seed + 0*64, ctx.seed + 1*64, ctx.seed + 2*64, ctx.seed + 3*64,
                ctx.seed + 4*64, ctx.seed + 5*64, ctx.seed + 6*64, ctx.seed + 7*64
            );
        } else if constexpr (Arch == SimdArch::AVX512) {
            pbkdf2_hmac_sha512_16way_avx512(
                ctx.pw +  0*256, ctx.pw_len[ 0], ctx.pw +  1*256, ctx.pw_len[ 1],
                ctx.pw +  2*256, ctx.pw_len[ 2], ctx.pw +  3*256, ctx.pw_len[ 3],
                ctx.pw +  4*256, ctx.pw_len[ 4], ctx.pw +  5*256, ctx.pw_len[ 5],
                ctx.pw +  6*256, ctx.pw_len[ 6], ctx.pw +  7*256, ctx.pw_len[ 7],
                ctx.pw +  8*256, ctx.pw_len[ 8], ctx.pw +  9*256, ctx.pw_len[ 9],
                ctx.pw + 10*256, ctx.pw_len[10], ctx.pw + 11*256, ctx.pw_len[11],
                ctx.pw + 12*256, ctx.pw_len[12], ctx.pw + 13*256, ctx.pw_len[13],
                ctx.pw + 14*256, ctx.pw_len[14], ctx.pw + 15*256, ctx.pw_len[15],
                ctx.salt_buf, ctx.salt_len, rounds,
                ctx.seed +  0*64, ctx.seed +  1*64, ctx.seed +  2*64, ctx.seed +  3*64,
                ctx.seed +  4*64, ctx.seed +  5*64, ctx.seed +  6*64, ctx.seed +  7*64,
                ctx.seed +  8*64, ctx.seed +  9*64, ctx.seed + 10*64, ctx.seed + 11*64,
                ctx.seed + 12*64, ctx.seed + 13*64, ctx.seed + 14*64, ctx.seed + 15*64
            );
        }
    }

    void process_batch(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                       std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                       std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic, bool is_flush) {

        if (ctx.valid_batch_sz == 0) return;
        const size_t mnemonic_len = opt.base_mnemonic.size();

        for (size_t b = 0; b < ctx.valid_batch_sz; ++b) {
            char* current_pw = ctx.pw + b * 256;
            std::memcpy(current_pw, opt.prefix_str.data(), opt.prefix_str.size());
            char* ptr = current_pw + opt.prefix_str.size();

            for (size_t i = opt.prefix_words; i < mnemonic_len; ++i) {
                const std::string_view w = cfg.wordlist[ctx.valid_batch[b * 24 + i]];
                std::memcpy(ptr, w.data(), w.size());
                ptr += w.size();
                if (i < mnemonic_len - 1) {
                    std::memcpy(ptr, cfg.separator.data(), cfg.separator.size());
                    ptr += cfg.separator.size();
                }
            }
            ctx.pw_len[b] = ptr - current_pw;
        }

        if (ctx.valid_batch_sz == BATCH_SIZE) {
            process_simd_pbkdf2(ctx, cfg.pbkdf2_rounds);
        } else if (is_flush) {
            for (size_t b = 0; b < ctx.valid_batch_sz; ++b) {
                crypto::pbkdf2_hmac_sha512(ctx.pw + b*256, ctx.pw_len[b],
                                           ctx.salt_buf, ctx.salt_len,
                                           cfg.pbkdf2_rounds, ctx.seed + b*64, 64);
            }
        } else {
            return; // Aguarda encher o batch
        }

        for (size_t b = 0; b < ctx.valid_batch_sz; ++b) {
            const bool is_match = (cfg.coin == CoinTarget::BTC)
                ? Bip39Deriver::check_btc_target_from_seed(ctx.ctx, ctx.seed + b*64, ctx.decoded_target, opt.target_fast_hash)
                : Bip39Deriver::check_eth_target_from_seed(ctx.ctx, ctx.seed + b*64, ctx.decoded_target, opt.target_fast_hash);

            if (is_match) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    success = true;
                    result_mnemonic.assign(ctx.valid_batch + b*24,
                                           ctx.valid_batch + b*24 + mnemonic_len);
                }
            }
        }

        ctx.local_valid += ctx.valid_batch_sz;
        if (ctx.local_tested >= 1024) {
            tested_count += ctx.local_tested;
            valid_count  += ctx.local_valid;
            ctx.local_tested = 0;
            ctx.local_valid  = 0;
        }
        ctx.valid_batch_sz = 0;
    }

    void process_checksum_batch(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                                std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                                std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic, bool is_flush) {
        if constexpr (!OnlyValids) return;
        if (ctx.c_batch_sz == 0) return;

        const size_t mnemonic_len  = opt.base_mnemonic.size();
        const size_t checksum_bits = mnemonic_len * 11 / 33;

        if (ctx.c_batch_sz == C_BATCH_SIZE) {
            uint8_t original_checksums[32] = {};

            // ---- Bloco SIMD por arquitetura ----
            if constexpr (Arch == SimdArch::SSE) {
                SHA256_SSE_State s1, s2;
                sha256_init_sse(&s1); sha256_init_sse(&s2);
                alignas(64) uint32_t blocks1[16][4] = {};
                alignas(64) uint32_t blocks2[16][4] = {};

                for (int b = 0; b < 8; ++b) {
                    uint8_t entropy[128] = {};
                    std::memcpy(entropy, opt.base_entropy, 32);
                    const size_t entropy_bits  = mnemonic_len * 11 - checksum_bits;
                    const size_t entropy_bytes = entropy_bits / 8;

                    uint64_t acc = opt.base_acc;
                    size_t bits  = opt.base_bits;
                    size_t b_pos = opt.base_b_pos;

                    for (size_t i = opt.prefix_words; i < mnemonic_len; ++i) {
                        acc = (acc << 11) | (ctx.checksum_batch[b * 24 + i] & 0x7FF);
                        bits += 11;
                        while (bits >= 8) {
                            bits -= 8;
                            if (b_pos < entropy_bytes && b_pos < 64) {
                                entropy[b_pos++] = (acc >> bits) & 0xFF;
                            }
                        }
                        acc &= (1ULL << bits) - 1;
                    }
                    if (bits > 0)
                        original_checksums[b] = static_cast<uint8_t>(acc);
                    entropy[entropy_bytes] = 0x80;

                    uint32_t W_local[16] = {};
                    std::memcpy(W_local, entropy, 64);
                    W_local[15] = __builtin_bswap32(entropy_bits);
                    for (int w = 0; w < 16; ++w) {
                        if (b < 4) blocks1[w][b]   = __builtin_bswap32(W_local[w]);
                        else       blocks2[w][b-4] = __builtin_bswap32(W_local[w]);
                    }
                }
                sha256_transform_sse(&s1, blocks1);
                sha256_transform_sse(&s2, blocks2);

                for (int b = 0; b < 8; ++b) {
                    const uint8_t hash_first_byte = (b < 4)
                        ? static_cast<uint8_t>(s1.state[0][b]   >> 24)
                        : static_cast<uint8_t>(s2.state[0][b-4] >> 24);
                    if constexpr (AutoDeduce) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                           | (hash_first_byte >> (8 - checksum_bits));
                        if (opt.allowed_last_words[syn]) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = ctx.checksum_batch[b * 24 + i];
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        const uint8_t expected = original_checksums[b];
                        if (expected == (hash_first_byte >> (8 - checksum_bits))) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = ctx.checksum_batch[b * 24 + i];
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }

            } else if constexpr (Arch == SimdArch::AVX2) {
                SHA256_AVX2_State s1, s2;
                sha256_init_avx2(&s1); sha256_init_avx2(&s2);
                alignas(64) uint32_t blocks1[16][8] = {};
                alignas(64) uint32_t blocks2[16][8] = {};

                for (int b = 0; b < 16; ++b) {
                    uint8_t entropy[128] = {};
                    std::memcpy(entropy, opt.base_entropy, 32);
                    const size_t entropy_bits  = mnemonic_len * 11 - checksum_bits;
                    const size_t entropy_bytes = entropy_bits / 8;

                    uint64_t acc = opt.base_acc;
                    size_t bits  = opt.base_bits;
                    size_t b_pos = opt.base_b_pos;

                    for (size_t i = opt.prefix_words; i < mnemonic_len; ++i) {
                        acc = (acc << 11) | (ctx.checksum_batch[b * 24 + i] & 0x7FF);
                        bits += 11;
                        while (bits >= 8) {
                            bits -= 8;
                            if (b_pos < entropy_bytes && b_pos < 64) {
                                entropy[b_pos++] = (acc >> bits) & 0xFF;
                            }
                        }
                        acc &= (1ULL << bits) - 1;
                    }
                    if (bits > 0)
                        original_checksums[b] = static_cast<uint8_t>(acc);
                    entropy[entropy_bytes] = 0x80;

                    uint32_t W_local[16] = {};
                    std::memcpy(W_local, entropy, 64);
                    W_local[15] = __builtin_bswap32(entropy_bits);
                    for (int w = 0; w < 16; ++w) {
                        if (b < 8) blocks1[w][b]   = __builtin_bswap32(W_local[w]);
                        else       blocks2[w][b-8] = __builtin_bswap32(W_local[w]);
                    }
                }
                sha256_transform_avx2(&s1, blocks1);
                sha256_transform_avx2(&s2, blocks2);

                for (int b = 0; b < 16; ++b) {
                    const uint8_t hash_first_byte = (b < 8)
                        ? static_cast<uint8_t>(s1.state[0][b]   >> 24)
                        : static_cast<uint8_t>(s2.state[0][b-8] >> 24);
                    // (mesma lógica do ramo SSE, com AutoDeduce)
                    if constexpr (AutoDeduce) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                           | (hash_first_byte >> (8 - checksum_bits));
                        if (opt.allowed_last_words[syn]) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = ctx.checksum_batch[b * 24 + i];
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        const uint8_t expected = original_checksums[b];
                        if (expected == (hash_first_byte >> (8 - checksum_bits))) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = ctx.checksum_batch[b * 24 + i];
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }

            } else if constexpr (Arch == SimdArch::AVX512) {
                SHA256_AVX512_State s1, s2;
                sha256_init_avx512(&s1); sha256_init_avx512(&s2);
                alignas(64) uint32_t blocks1[16][16] = {};
                alignas(64) uint32_t blocks2[16][16] = {};

                for (int b = 0; b < 32; ++b) {
                    uint8_t entropy[128] = {};
                    std::memcpy(entropy, opt.base_entropy, 32);
                    const size_t entropy_bits  = mnemonic_len * 11 - checksum_bits;
                    const size_t entropy_bytes = entropy_bits / 8;

                    uint64_t acc = opt.base_acc;
                    size_t bits  = opt.base_bits;
                    size_t b_pos = opt.base_b_pos;

                    for (size_t i = opt.prefix_words; i < mnemonic_len; ++i) {
                        acc = (acc << 11) | (ctx.checksum_batch[b * 24 + i] & 0x7FF);
                        bits += 11;
                        while (bits >= 8) {
                            bits -= 8;
                            if (b_pos < entropy_bytes && b_pos < 64) {
                                entropy[b_pos++] = (acc >> bits) & 0xFF;
                            }
                        }
                        acc &= (1ULL << bits) - 1;
                    }
                    if (bits > 0)
                        original_checksums[b] = static_cast<uint8_t>(acc);
                    entropy[entropy_bytes] = 0x80;

                    uint32_t W_local[16] = {};
                    std::memcpy(W_local, entropy, 64);
                    W_local[15] = __builtin_bswap32(entropy_bits);
                    for (int w = 0; w < 16; ++w) {
                        if (b < 16) blocks1[w][b]    = __builtin_bswap32(W_local[w]);
                        else        blocks2[w][b-16] = __builtin_bswap32(W_local[w]);
                    }
                }
                sha256_transform_avx512(&s1, blocks1);
                sha256_transform_avx512(&s2, blocks2);

                for (int b = 0; b < 32; ++b) {
                    const uint8_t hash_first_byte = (b < 16)
                        ? static_cast<uint8_t>(s1.state[0][b]    >> 24)
                        : static_cast<uint8_t>(s2.state[0][b-16] >> 24);
                    if constexpr (AutoDeduce) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                           | (hash_first_byte >> (8 - checksum_bits));
                        if (opt.allowed_last_words[syn]) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = ctx.checksum_batch[b * 24 + i];
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        const uint8_t expected = original_checksums[b];
                        if (expected == (hash_first_byte >> (8 - checksum_bits))) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = ctx.checksum_batch[b * 24 + i];
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }
            }
            ctx.c_batch_sz = 0;

        } else if (is_flush) {
            for (size_t b = 0; b < ctx.c_batch_sz; ++b) {
                if constexpr (AutoDeduce) {
                    const size_t num_last_words = size_t{1} << checksum_bits;
                    for (size_t x = 0; x < num_last_words; ++x) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1] | x;
                        if (!opt.allowed_last_words[syn]) continue;

                        std::vector<uint16_t> cand(ctx.checksum_batch + b * 24,
                                                   ctx.checksum_batch + b * 24 + mnemonic_len);
                        cand[mnemonic_len - 1] = syn;
                        if (cryptowords::Bip39Deriver::verify_checksum(cand)) {
                            for (size_t i = 0; i < mnemonic_len; ++i)
                                ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = cand[i];
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                            break;
                        }
                    }
                } else {
                    std::vector<uint16_t> cand(ctx.checksum_batch + b * 24,
                                               ctx.checksum_batch + b * 24 + mnemonic_len);
                    if (cryptowords::Bip39Deriver::verify_checksum(cand)) {
                        for (size_t i = 0; i < mnemonic_len; ++i)
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = cand[i];
                        ++ctx.valid_batch_sz;
                        if (ctx.valid_batch_sz == BATCH_SIZE)
                            process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                          result_mutex, success, result_mnemonic, false);
                    }
                }
            }
            ctx.c_batch_sz = 0;
        }
    }

public:
    void enqueue_and_process(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                             std::atomic<bool>& found, std::atomic<uint64_t>& tested_count,
                             std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                             bool& success, std::vector<uint16_t>& result_mnemonic) override {
        ++ctx.local_tested;
        if (ctx.local_tested >= 1024) {
            tested_count += ctx.local_tested;
            valid_count  += ctx.local_valid;
            ctx.local_tested = 0;
            ctx.local_valid  = 0;
        }

        const size_t mnemonic_len = opt.base_mnemonic.size();

        if constexpr (OnlyValids) {
            std::memcpy(ctx.checksum_batch + ctx.c_batch_sz * 24,
                        ctx.current_ids.data(), mnemonic_len * sizeof(uint16_t));
            ++ctx.c_batch_sz;
            if (ctx.c_batch_sz == C_BATCH_SIZE) {
                process_checksum_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                       result_mutex, success, result_mnemonic, false);
            }
        } else {
            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24,
                        ctx.current_ids.data(), mnemonic_len * sizeof(uint16_t));
            ++ctx.valid_batch_sz;
            if (ctx.valid_batch_sz == BATCH_SIZE) {
                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                              result_mutex, success, result_mnemonic, false);
            }
        }
    }

    void flush(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
               std::atomic<bool>& found, std::atomic<uint64_t>& tested_count,
               std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
               bool& success, std::vector<uint16_t>& result_mnemonic) override {
        if constexpr (OnlyValids) {
            process_checksum_batch(ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic, true);
        }
        process_batch(ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic, true);
        if (ctx.local_tested > 0 || ctx.local_valid > 0) {
            tested_count += ctx.local_tested;
            valid_count  += ctx.local_valid;
            ctx.local_tested = 0;
            ctx.local_valid  = 0;
        }
    }
};

} // namespace cryptowords
