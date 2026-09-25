#pragma once
#include "../config.hpp"
#include "../search/context.hpp"
#include "../search/processor.hpp"
#include "arch.hpp"

#include "../crypto/bip39.hpp"
#include "../crypto/hmac_sha512.hpp"
#include "../crypto/pbkdf2_simd.hpp"
#include "../crypto/sha256.hpp"
#include "../crypto/sha256_shani.hpp"

#include <array>
#include <atomic>
#include <cstdint>
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
                ctx.pw + 0*PW_SLOT_SIZE, ctx.pw_len[0], ctx.pw + 1*PW_SLOT_SIZE, ctx.pw_len[1],
                ctx.pw + 2*PW_SLOT_SIZE, ctx.pw_len[2], ctx.pw + 3*PW_SLOT_SIZE, ctx.pw_len[3],
                ctx.salt_buf, ctx.salt_len, rounds,
                ctx.seed + 0*64, ctx.seed + 1*64, ctx.seed + 2*64, ctx.seed + 3*64,
                ctx.salt_block64,
                ctx.kw_salt
            );
        } else if constexpr (Arch == SimdArch::AVX2) {
            pbkdf2_hmac_sha512_8way_avx2(
                ctx.pw + 0*PW_SLOT_SIZE, ctx.pw_len[0], ctx.pw + 1*PW_SLOT_SIZE, ctx.pw_len[1],
                ctx.pw + 2*PW_SLOT_SIZE, ctx.pw_len[2], ctx.pw + 3*PW_SLOT_SIZE, ctx.pw_len[3],
                ctx.pw + 4*PW_SLOT_SIZE, ctx.pw_len[4], ctx.pw + 5*PW_SLOT_SIZE, ctx.pw_len[5],
                ctx.pw + 6*PW_SLOT_SIZE, ctx.pw_len[6], ctx.pw + 7*PW_SLOT_SIZE, ctx.pw_len[7],
                ctx.salt_buf, ctx.salt_len, rounds,
                ctx.seed + 0*64, ctx.seed + 1*64, ctx.seed + 2*64, ctx.seed + 3*64,
                ctx.seed + 4*64, ctx.seed + 5*64, ctx.seed + 6*64, ctx.seed + 7*64,
                ctx.salt_block64,
                ctx.kw_salt
            );
        } else if constexpr (Arch == SimdArch::AVX512) {
            pbkdf2_hmac_sha512_16way_avx512(
                ctx.pw +  0*PW_SLOT_SIZE, ctx.pw_len[ 0], ctx.pw +  1*PW_SLOT_SIZE, ctx.pw_len[ 1],
                ctx.pw +  2*PW_SLOT_SIZE, ctx.pw_len[ 2], ctx.pw +  3*PW_SLOT_SIZE, ctx.pw_len[ 3],
                ctx.pw +  4*PW_SLOT_SIZE, ctx.pw_len[ 4], ctx.pw +  5*PW_SLOT_SIZE, ctx.pw_len[ 5],
                ctx.pw +  6*PW_SLOT_SIZE, ctx.pw_len[ 6], ctx.pw +  7*PW_SLOT_SIZE, ctx.pw_len[ 7],
                ctx.pw +  8*PW_SLOT_SIZE, ctx.pw_len[ 8], ctx.pw +  9*PW_SLOT_SIZE, ctx.pw_len[ 9],
                ctx.pw + 10*PW_SLOT_SIZE, ctx.pw_len[10], ctx.pw + 11*PW_SLOT_SIZE, ctx.pw_len[11],
                ctx.pw + 12*PW_SLOT_SIZE, ctx.pw_len[12], ctx.pw + 13*PW_SLOT_SIZE, ctx.pw_len[13],
                ctx.pw + 14*PW_SLOT_SIZE, ctx.pw_len[14], ctx.pw + 15*PW_SLOT_SIZE, ctx.pw_len[15],
                ctx.salt_buf, ctx.salt_len, rounds,
                ctx.seed +  0*64, ctx.seed +  1*64, ctx.seed +  2*64, ctx.seed +  3*64,
                ctx.seed +  4*64, ctx.seed +  5*64, ctx.seed +  6*64, ctx.seed +  7*64,
                ctx.seed +  8*64, ctx.seed +  9*64, ctx.seed + 10*64, ctx.seed + 11*64,
                ctx.seed + 12*64, ctx.seed + 13*64, ctx.seed + 14*64, ctx.seed + 15*64,
                ctx.salt_block64,
                ctx.kw_salt
            );
        }
    }

    void process_batch(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                       std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                       std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic, bool is_flush) {

        if (ctx.valid_batch_sz == 0) return;
        const size_t mnemonic_len = opt.base_mnemonic.size();

        const size_t start_slice = (opt.slice0_static_len > 0) ? 1 : 0;
        const size_t num_slices  = opt.slices.size();

        if (__builtin_expect(!ctx.prefix_initialized, 0)) {
            if (opt.slice0_static_len > 0) {
                for (size_t i = 0; i < BATCH_SIZE; ++i) {
                    std::memcpy(ctx.pw + i * PW_SLOT_SIZE, opt.slices[0].text.data(), opt.slice0_static_len);
                }
            }
            ctx.prefix_initialized = true;
        }

        for (size_t b = 0; b < ctx.valid_batch_sz; ++b) {
            char* current_pw = ctx.pw + b * PW_SLOT_SIZE;
            char* ptr = current_pw + opt.slice0_static_len;

            for (size_t s = start_slice; s < num_slices; ++s) {
                const auto& slice = opt.slices[s];
                if (slice.is_variable) {
                    const std::string_view w = cfg.wordlist[ctx.valid_batch[b * 24 + slice.word_idx]];
                    std::memcpy(ptr, w.data(), w.size());
                    ptr += w.size();
                } else {
                    if (slice.text.size() == 1) {
                        *ptr++ = slice.text[0];
                    } else {
                        std::memcpy(ptr, slice.text.data(), slice.text.size());
                        ptr += slice.text.size();
                    }
                }
            }
            ctx.pw_len[b] = ptr - current_pw;
        }

        if (ctx.valid_batch_sz == BATCH_SIZE) {
            process_simd_pbkdf2(ctx, cfg.pbkdf2_rounds);
        } else if (is_flush) {
            for (size_t b = 0; b < ctx.valid_batch_sz; ++b) {
                crypto::pbkdf2_hmac_sha512(ctx.pw + b*PW_SLOT_SIZE, ctx.pw_len[b],
                                           ctx.salt_buf, ctx.salt_len,
                                           cfg.pbkdf2_rounds, ctx.seed + b*64, 64);
            }
        } else {
            return; // Aguarda encher o batch
        }

        for (size_t b = 0; b < ctx.valid_batch_sz; ++b) {
            const bool is_match = (cfg.coin == CoinTarget::BTC)
                ? Bip39Deriver::check_btc_target_from_seed(ctx.ctx, ctx.seed + b*64, ctx.decoded_target, opt.target_fast_hash64)
                : Bip39Deriver::check_eth_target_from_seed(*ctx.ctx, ctx.seed + b*64, ctx.decoded_target, opt.target_fast_hash64);

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
        if (ctx.local_tested >= 2048) {
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
            // ---- Bloco SIMD por arquitetura ----
            if constexpr (Arch == SimdArch::SSE) {
                SHA256_SSE_State s1, s2;
                sha256_init_sse(&s1); sha256_init_sse(&s2);
                alignas(64) std::array<std::array<uint32_t, 16>, 4> blocks1 = {};
                alignas(64) std::array<std::array<uint32_t, 16>, 4> blocks2 = {};

                for (int b = 0; b < 8; ++b) {
                    alignas(64) uint8_t block64[64];
                    std::memcpy(block64, opt.base_block64, 64);
                    for (size_t k = 0; k < opt.unknown_positions.size(); ++k) {
                        detail::set_11bits(block64, opt.unknown_bit_offsets[k],
                                           ctx.checksum_batch[b * 24 + opt.unknown_positions[k]]);
                    }
                    block64[opt.entropy_bytes] = 0x80;

                    const uint32_t* W_local = reinterpret_cast<const uint32_t*>(block64);
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
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        if (opt.expected_checksum == (hash_first_byte >> (8 - checksum_bits))) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }

            } else if constexpr (Arch == SimdArch::AVX2) {
#if defined(__SHA__)
                for (size_t b = 0; b < 16; ++b) {
                    alignas(64) uint8_t block64[64];
                    std::memcpy(block64, opt.base_block64, 64);
                    for (size_t k = 0; k < opt.unknown_positions.size(); ++k) {
                        detail::set_11bits(block64, opt.unknown_bit_offsets[k],
                                           ctx.checksum_batch[b * 24 + opt.unknown_positions[k]]);
                    }
                    block64[opt.entropy_bytes] = 0x80;

                    const uint8_t hash_first_byte = detail::sha256_bip39_first_byte_shani(block64);

                    if constexpr (AutoDeduce) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                           | (hash_first_byte >> (8 - checksum_bits));
                        if (opt.allowed_last_words[syn]) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        if (opt.expected_checksum == (hash_first_byte >> (8 - checksum_bits))) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }
#else
                SHA256_AVX2_State s1, s2;
                sha256_init_avx2(&s1); sha256_init_avx2(&s2);
                alignas(64) uint32_t blocks1[16][8] = {};
                alignas(64) uint32_t blocks2[16][8] = {};

                for (int b = 0; b < 16; ++b) {
                    alignas(64) uint8_t block64[64];
                    std::memcpy(block64, opt.base_block64, 64);
                    for (size_t k = 0; k < opt.unknown_positions.size(); ++k) {
                        detail::set_11bits(block64, opt.unknown_bit_offsets[k],
                                           ctx.checksum_batch[b * 24 + opt.unknown_positions[k]]);
                    }
                    block64[opt.entropy_bytes] = 0x80;

                    const uint32_t* W_local = reinterpret_cast<const uint32_t*>(block64);
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
                    if constexpr (AutoDeduce) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                           | (hash_first_byte >> (8 - checksum_bits));
                        if (opt.allowed_last_words[syn]) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        if (opt.expected_checksum == (hash_first_byte >> (8 - checksum_bits))) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }
#endif

            } else if constexpr (Arch == SimdArch::AVX512) {
#if defined(__SHA__)
                for (size_t b = 0; b < 32; ++b) {
                    alignas(64) uint8_t block64[64];
                    std::memcpy(block64, opt.base_block64, 64);
                    for (size_t k = 0; k < opt.unknown_positions.size(); ++k) {
                        detail::set_11bits(block64, opt.unknown_bit_offsets[k],
                                           ctx.checksum_batch[b * 24 + opt.unknown_positions[k]]);
                    }
                    block64[opt.entropy_bytes] = 0x80;

                    const uint8_t hash_first_byte = detail::sha256_bip39_first_byte_shani(block64);

                    if constexpr (AutoDeduce) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                           | (hash_first_byte >> (8 - checksum_bits));
                        if (opt.allowed_last_words[syn]) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        if (opt.expected_checksum == (hash_first_byte >> (8 - checksum_bits))) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }
#else
                SHA256_AVX512_State s1, s2;
                sha256_init_avx512(&s1); sha256_init_avx512(&s2);
                alignas(64) uint32_t blocks1[16][16] = {};
                alignas(64) uint32_t blocks2[16][16] = {};

                for (int b = 0; b < 32; ++b) {
                    alignas(64) uint8_t block64[64];
                    std::memcpy(block64, opt.base_block64, 64);
                    for (size_t k = 0; k < opt.unknown_positions.size(); ++k) {
                        detail::set_11bits(block64, opt.unknown_bit_offsets[k],
                                           ctx.checksum_batch[b * 24 + opt.unknown_positions[k]]);
                    }
                    block64[opt.entropy_bytes] = 0x80;

                    const uint32_t* W_local = reinterpret_cast<const uint32_t*>(block64);
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
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    } else {
                        if (opt.expected_checksum == (hash_first_byte >> (8 - checksum_bits))) {
                            std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                            ++ctx.valid_batch_sz;
                            if (ctx.valid_batch_sz == BATCH_SIZE)
                                process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                              result_mutex, success, result_mnemonic, false);
                        }
                    }
                }
#endif
            }
            ctx.c_batch_sz = 0;

        } else if (is_flush) {
            for (size_t b = 0; b < ctx.c_batch_sz; ++b) {
#if defined(__SHA__)
                alignas(64) uint8_t block64[64];
                std::memcpy(block64, opt.base_block64, 64);
                for (size_t k = 0; k < opt.unknown_positions.size(); ++k) {
                    detail::set_11bits(block64, opt.unknown_bit_offsets[k],
                                       ctx.checksum_batch[b * 24 + opt.unknown_positions[k]]);
                }
                block64[opt.entropy_bytes] = 0x80;

                const uint8_t hash_first_byte = detail::sha256_bip39_first_byte_shani(block64);

                if constexpr (AutoDeduce) {
                    const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1]
                                       | (hash_first_byte >> (8 - checksum_bits));
                    if (opt.allowed_last_words[syn]) {
                        std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                        ctx.valid_batch[ctx.valid_batch_sz * 24 + mnemonic_len - 1] = syn;
                        ++ctx.valid_batch_sz;
                        if (ctx.valid_batch_sz == BATCH_SIZE)
                            process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                          result_mutex, success, result_mnemonic, false);
                    }
                } else {
                    if (opt.expected_checksum == (hash_first_byte >> (8 - checksum_bits))) {
                        std::memcpy(ctx.valid_batch + ctx.valid_batch_sz * 24, ctx.checksum_batch + b * 24, mnemonic_len * sizeof(uint16_t));
                        ++ctx.valid_batch_sz;
                        if (ctx.valid_batch_sz == BATCH_SIZE)
                            process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                          result_mutex, success, result_mnemonic, false);
                    }
                }
#else
                if constexpr (AutoDeduce) {
                    const size_t num_last_words = size_t{1} << checksum_bits;
                    for (size_t x = 0; x < num_last_words; ++x) {
                        const uint16_t syn = ctx.checksum_batch[b * 24 + mnemonic_len - 1] | x;
                        if (!opt.allowed_last_words[syn]) continue;

                        uint16_t cand[24];
                        for (size_t i = 0; i < mnemonic_len; ++i) cand[i] = ctx.checksum_batch[b * 24 + i];
                        cand[mnemonic_len - 1] = syn;
                        if (cryptowords::Bip39Deriver::verify_checksum(std::span<const uint16_t>(cand, mnemonic_len))) {
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
                    uint16_t cand[24];
                    for (size_t i = 0; i < mnemonic_len; ++i) cand[i] = ctx.checksum_batch[b * 24 + i];
                    if (cryptowords::Bip39Deriver::verify_checksum(std::span<const uint16_t>(cand, mnemonic_len))) {
                        for (size_t i = 0; i < mnemonic_len; ++i)
                            ctx.valid_batch[ctx.valid_batch_sz * 24 + i] = cand[i];
                        ++ctx.valid_batch_sz;
                        if (ctx.valid_batch_sz == BATCH_SIZE)
                            process_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                          result_mutex, success, result_mnemonic, false);
                    }
                }
#endif
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
        if (ctx.local_tested >= 2048) {
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
        if (!found.load(std::memory_order_relaxed)) {
            if constexpr (OnlyValids) {
                process_checksum_batch(ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic, true);
            }
            process_batch(ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic, true);
        }
        if (ctx.local_tested > 0 || ctx.local_valid > 0) {
            tested_count += ctx.local_tested;
            valid_count  += ctx.local_valid;
            ctx.local_tested = 0;
            ctx.local_valid  = 0;
        }
    }
};

} // namespace cryptowords
