#include "../../include/search/odometer.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include <cstring>

namespace cryptowords {

namespace {

static bool refill_streaming_tuples(PipelineThreadContext& ctx, const OptimizedMnemonics& opt, bool is_init) {
    const size_t K = opt.unknown_positions.size();
    if (K < 3) {
        ctx.is_done = true;
        return false;
    }
    const size_t M = K - 1;
    const size_t cs_shift = 8 - opt.checksum_bits;
    const uint8_t expected_cs = opt.expected_checksum;
    const size_t last_u_idx = opt.unknown_positions[M];
    const size_t last_u_bit = opt.unknown_bit_offsets[M];

    while (true) {
        if (!is_init) {
            size_t carry = ctx.step_size;
            for (int i = static_cast<int>(M) - 1; i >= 0 && carry > 0; --i) {
                const size_t w   = opt.wheels[i].size();
                const size_t sum = ctx.outer_state[i] + carry;
                if (sum < w) {
                    ctx.outer_state[i] = sum;
                    carry = 0;
                } else {
                    ctx.outer_state[i] = sum % w;
                    carry = sum / w;
                }
            }
            if (carry > 0) {
                ctx.is_done = true;
                return false;
            }
        }
        is_init = false;

        size_t parity_sum = 0;
        for (size_t i = 0; i < M; ++i) {
            size_t w_size = opt.wheels[i].size();
            size_t eff = (opt.has_gray_code && (parity_sum % 2 != 0)) ? (w_size - 1 - ctx.outer_state[i]) : ctx.outer_state[i];
            parity_sum += ctx.outer_state[i];
            uint16_t w_val = opt.wheels[i][eff];
            cryptowords::detail::set_11bits(ctx.k_block64, opt.unknown_bit_offsets[i], w_val);
            ctx.current_ids[opt.unknown_positions[i]] = w_val;
        }

        // OTM-36: Poda Precoce de Não-Repetição em Streaming (--distinct em K=3)
        if (opt.is_distinct) {
            bool dup = false;
            for (size_t i = 0; i < M; ++i) {
                for (size_t j = i + 1; j < M; ++j) {
                    if (ctx.current_ids[opt.unknown_positions[i]] == ctx.current_ids[opt.unknown_positions[j]]) {
                        dup = true;
                        break;
                    }
                }
                if (dup) break;
            }
            if (dup) continue;
        }

        ctx.k_last_w_count = 0;
        ctx.k_last_w_idx   = 0;

        const size_t byte_pos = last_u_bit / 8;
        const size_t bit_pos  = last_u_bit % 8;
        const uint32_t shift  = 24 - 11 - bit_pos;
        const uint32_t mask   = ~(0x7FFu << shift);

        const uint32_t base_curr = ((static_cast<uint32_t>(ctx.k_block64[byte_pos]) << 16) |
                                    (static_cast<uint32_t>(ctx.k_block64[byte_pos + 1]) << 8) |
                                    (static_cast<uint32_t>(ctx.k_block64[byte_pos + 2]))) & mask;

        if (opt.has_cascade_deduction) {
            ctx.k_block64[opt.entropy_bytes] = 0x80;
#if defined(__SHA__)
            if (byte_pos >= 16 && byte_pos + 2 < 32) {
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
                std::array<uint32_t, 8> init_state = {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                };
                __m128i TMP = _mm_loadu_si128((const __m128i*) &init_state[0]);
                __m128i STATE1 = _mm_loadu_si128((const __m128i*) &init_state[4]);
                TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
                STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
                __m128i STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
                STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */
                __m128i ABEF_SAVE = STATE0;
                __m128i CDGH_SAVE = STATE1;

                __m128i MSG0 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 0));
                MSG0 = _mm_shuffle_epi8(MSG0, MASK);

                __m128i MSG2 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 32));
                MSG2 = _mm_shuffle_epi8(MSG2, MASK);

                __m128i MSG3 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 48));
                MSG3 = _mm_shuffle_epi8(MSG3, MASK);

                // Rounds 0-3
                __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
                STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
                MSG = _mm_shuffle_epi32(MSG, 0x0E);
                STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

                for (uint16_t e_base : opt.wheels[M]) {
                    uint32_t cur = base_curr | ((static_cast<uint32_t>(e_base & 0x7FF)) << shift);
                    ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                    ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                    ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                    uint8_t h = cryptowords::detail::sha256_bip39_msg1_variable_shani(
                        STATE0, STATE1, MSG0, MSG2, MSG3, ABEF_SAVE, CDGH_SAVE, ctx.k_block64 + 16);
                    uint16_t syn = e_base | (h >> cs_shift);
                    if (opt.allowed_last_words[syn]) {
                        bool dup = false;
                        if (opt.is_distinct) {
                            for (size_t i = 0; i < M; ++i) {
                                if (syn == ctx.current_ids[opt.unknown_positions[i]]) {
                                    dup = true;
                                    break;
                                }
                            }
                        }
                        if (!dup) {
                            ctx.k_last_w_list[ctx.k_last_w_count++] = syn;
                        }
                    }
                }
            } else {
                for (uint16_t e_base : opt.wheels[M]) {
                    uint32_t cur = base_curr | ((static_cast<uint32_t>(e_base & 0x7FF)) << shift);
                    ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                    ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                    ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                    uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(ctx.k_block64);
                    uint16_t syn = e_base | (h >> cs_shift);
                    if (opt.allowed_last_words[syn]) {
                        bool dup = false;
                        if (opt.is_distinct) {
                            for (size_t i = 0; i < M; ++i) {
                                if (syn == ctx.current_ids[opt.unknown_positions[i]]) {
                                    dup = true;
                                    break;
                                }
                            }
                        }
                        if (!dup) {
                            ctx.k_last_w_list[ctx.k_last_w_count++] = syn;
                        }
                    }
                }
            }
#else
            for (uint16_t e_base : opt.wheels[M]) {
                uint32_t cur = base_curr | ((static_cast<uint32_t>(e_base & 0x7FF)) << shift);
                ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                uint8_t hash[32];
                crypto::SHA256::hash(ctx.k_block64, opt.entropy_bytes, hash);
                uint8_t h = hash[0];
                uint16_t syn = e_base | (h >> cs_shift);
                if (opt.allowed_last_words[syn]) {
                    bool dup = false;
                    if (opt.is_distinct) {
                        for (size_t i = 0; i < M; ++i) {
                            if (syn == ctx.current_ids[opt.unknown_positions[i]]) {
                                dup = true;
                                break;
                            }
                        }
                    }
                    if (!dup) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn;
                    }
                }
            }
#endif
        } else {
#if defined(__SHA__)
            if (byte_pos >= 16 && byte_pos + 2 < 32) {
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
                std::array<uint32_t, 8> init_state = {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                };
                __m128i TMP = _mm_loadu_si128((const __m128i*) &init_state[0]);
                __m128i STATE1 = _mm_loadu_si128((const __m128i*) &init_state[4]);
                TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
                STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
                __m128i STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
                STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */
                __m128i ABEF_SAVE = STATE0;
                __m128i CDGH_SAVE = STATE1;

                __m128i MSG0 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 0));
                MSG0 = _mm_shuffle_epi8(MSG0, MASK);

                __m128i MSG2 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 32));
                MSG2 = _mm_shuffle_epi8(MSG2, MASK);

                __m128i MSG3 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 48));
                MSG3 = _mm_shuffle_epi8(MSG3, MASK);

                // Rounds 0-3
                __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
                STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
                MSG = _mm_shuffle_epi32(MSG, 0x0E);
                STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

                for (uint16_t w_last : opt.wheels[M]) {
                    if (opt.is_distinct) {
                        bool dup = false;
                        for (size_t i = 0; i < M; ++i) {
                            if (w_last == ctx.current_ids[opt.unknown_positions[i]]) {
                                dup = true;
                                break;
                            }
                        }
                        if (dup) continue;
                    }
                    uint32_t cur = base_curr | ((static_cast<uint32_t>(w_last & 0x7FF)) << shift);
                    ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                    ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                    ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                    uint8_t h = cryptowords::detail::sha256_bip39_msg1_variable_shani(
                        STATE0, STATE1, MSG0, MSG2, MSG3, ABEF_SAVE, CDGH_SAVE, ctx.k_block64 + 16);
                    if ((h >> cs_shift) == expected_cs) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = w_last;
                    }
                }
            } else {
                for (uint16_t w_last : opt.wheels[M]) {
                    if (opt.is_distinct) {
                        bool dup = false;
                        for (size_t i = 0; i < M; ++i) {
                            if (w_last == ctx.current_ids[opt.unknown_positions[i]]) {
                                dup = true;
                                break;
                            }
                        }
                        if (dup) continue;
                    }
                    uint32_t cur = base_curr | ((static_cast<uint32_t>(w_last & 0x7FF)) << shift);
                    ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                    ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                    ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                    uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(ctx.k_block64);
                    if ((h >> cs_shift) == expected_cs) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = w_last;
                    }
                }
            }
#else
            for (uint16_t w_last : opt.wheels[M]) {
                if (opt.is_distinct) {
                    bool dup = false;
                    for (size_t i = 0; i < M; ++i) {
                        if (w_last == ctx.current_ids[opt.unknown_positions[i]]) {
                            dup = true;
                            break;
                        }
                    }
                    if (dup) continue;
                }
                uint32_t cur = base_curr | ((static_cast<uint32_t>(w_last & 0x7FF)) << shift);
                ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                uint8_t hash[32];
                crypto::SHA256::hash(ctx.k_block64, opt.entropy_bytes, hash);
                uint8_t h = hash[0];
                if ((h >> cs_shift) == expected_cs) {
                    ctx.k_last_w_list[ctx.k_last_w_count++] = w_last;
                }
            }
#endif
        }

        if (ctx.k_last_w_count > 0) {
            ctx.current_ids[last_u_idx] = ctx.k_last_w_list[ctx.k_last_w_idx++];
            return true;
        }
    }
}

} // namespace

void GenericOdometer::init_state(PipelineThreadContext& ctx, size_t thread_idx,
                                 size_t num_threads, const OptimizedMnemonics& opt) {
    ctx.thread_idx  = thread_idx;
    ctx.step_size   = num_threads;
    ctx.is_done     = false;
    ctx.current_ids = opt.base_mnemonic;

    if (opt.has_valid_triplets) {
        const size_t total = opt.valid_triplets.size();
        if (is_dynamic_partition_) {
            size_t chunk = (thread_idx == 0) ? (gpu_batch_ > 0 ? gpu_batch_ : 1024) : 256;
            size_t start = next_triplet_idx_.fetch_add(chunk, std::memory_order_relaxed);
            size_t end   = std::min(start + chunk, total);

            ctx.triplet_idx = start;
            ctx.triplet_end = end;
            if (start >= total) {
                ctx.is_done = true;
                return;
            }
        } else {
            const size_t chunk = (total + num_threads - 1) / num_threads;
            const size_t start = thread_idx * chunk;
            const size_t end   = std::min(start + chunk, total);

            ctx.triplet_idx = start;
            ctx.triplet_end = end;
            if (start >= end) {
                ctx.is_done = true;
                return;
            }
        }
        ctx.current_ids[opt.unknown_positions[0]] = opt.valid_triplets[ctx.triplet_idx].w0;
        ctx.current_ids[opt.unknown_positions[1]] = opt.valid_triplets[ctx.triplet_idx].w1;
        ctx.current_ids[opt.unknown_positions[2]] = opt.valid_triplets[ctx.triplet_idx].w2;
        return;
    }

    if (opt.has_valid_pairs) {
        const size_t total = opt.valid_pairs.size();
        if (is_dynamic_partition_) {
            size_t chunk = (thread_idx == 0) ? (gpu_batch_ > 0 ? gpu_batch_ : 1024) : 256;
            size_t start = next_pair_idx_.fetch_add(chunk, std::memory_order_relaxed);
            size_t end   = std::min(start + chunk, total);

            ctx.pair_idx = start;
            ctx.pair_end = end;
            if (start >= total) {
                ctx.is_done = true;
                return;
            }
        } else {
            const size_t chunk = (total + num_threads - 1) / num_threads;
            const size_t start = thread_idx * chunk;
            const size_t end   = std::min(start + chunk, total);

            ctx.pair_idx = start;
            ctx.pair_end = end;
            if (start >= end) {
                ctx.is_done = true;
                return;
            }
        }
        ctx.current_ids[opt.unknown_positions[0]] = opt.valid_pairs[ctx.pair_idx].first;
        ctx.current_ids[opt.unknown_positions[1]] = opt.valid_pairs[ctx.pair_idx].second;
        return;
    }

    if (opt.has_streaming_pruning) {
        const size_t K = opt.unknown_positions.size();
        const size_t M = K - 1;
        ctx.outer_state.assign(M, 0);

        size_t temp = thread_idx;
        for (int i = static_cast<int>(M) - 1; i >= 0; --i) {
            const size_t w = opt.wheels[i].size();
            if (w == 0) { ctx.is_done = true; return; }
            ctx.outer_state[i] = temp % w;
            temp /= w;
        }
        if (temp > 0) { ctx.is_done = true; return; }

        std::memcpy(ctx.k_block64, opt.base_block64, 64);
        ctx.k_last_w_count = 0;
        ctx.k_last_w_idx   = 0;
        if (!refill_streaming_tuples(ctx, opt, true)) {
            ctx.is_done = true;
        }
        return;
    }

    ctx.state.assign(opt.wheels.size(), 0);

    // Distribui o índice da thread em mixed-radix. Zero wheels == estado inválido.
    size_t temp = thread_idx;
    for (int i = static_cast<int>(opt.wheels.size()) - 1; i >= 0; --i) {
        const size_t w = opt.wheels[i].size();
        if (w == 0) { ctx.is_done = true; return; }
        ctx.state[i] = temp % w;
        temp /= w;
    }
    if (temp > 0) { ctx.is_done = true; return; }

    size_t parity_sum = 0;
    for (size_t i = 0; i < opt.wheels.size(); ++i) {
        size_t w_size = opt.wheels[i].size();
        size_t eff = (opt.has_gray_code && (parity_sum % 2 != 0)) ? (w_size - 1 - ctx.state[i]) : ctx.state[i];
        parity_sum += ctx.state[i];
        ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][eff];
    }
}

bool GenericOdometer::advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) {
    if (ctx.is_done) return false;

    if (opt.has_valid_triplets) {
        ++ctx.triplet_idx;
        if (ctx.triplet_idx >= ctx.triplet_end) {
            if (is_dynamic_partition_) {
                const size_t total = opt.valid_triplets.size();
                size_t chunk = (ctx.thread_idx == 0) ? (gpu_batch_ > 0 ? gpu_batch_ : 1024) : 256;
                size_t start = next_triplet_idx_.fetch_add(chunk, std::memory_order_relaxed);
                if (start >= total) {
                    ctx.is_done = true;
                    return false;
                }
                ctx.triplet_idx = start;
                ctx.triplet_end = std::min(start + chunk, total);
            } else {
                ctx.is_done = true;
                return false;
            }
        }
        ctx.current_ids[opt.unknown_positions[0]] = opt.valid_triplets[ctx.triplet_idx].w0;
        ctx.current_ids[opt.unknown_positions[1]] = opt.valid_triplets[ctx.triplet_idx].w1;
        ctx.current_ids[opt.unknown_positions[2]] = opt.valid_triplets[ctx.triplet_idx].w2;
        return true;
    }

    if (opt.has_valid_pairs) {
        ++ctx.pair_idx;
        if (ctx.pair_idx >= ctx.pair_end) {
            if (is_dynamic_partition_) {
                const size_t total = opt.valid_pairs.size();
                size_t chunk = (ctx.thread_idx == 0) ? (gpu_batch_ > 0 ? gpu_batch_ : 1024) : 256;
                size_t start = next_pair_idx_.fetch_add(chunk, std::memory_order_relaxed);
                if (start >= total) {
                    ctx.is_done = true;
                    return false;
                }
                ctx.pair_idx = start;
                ctx.pair_end = std::min(start + chunk, total);
            } else {
                ctx.is_done = true;
                return false;
            }
        }
        ctx.current_ids[opt.unknown_positions[0]] = opt.valid_pairs[ctx.pair_idx].first;
        ctx.current_ids[opt.unknown_positions[1]] = opt.valid_pairs[ctx.pair_idx].second;
        return true;
    }

    if (opt.has_streaming_pruning) {
        if (ctx.k_last_w_idx < ctx.k_last_w_count) {
            ctx.current_ids[opt.unknown_positions.back()] = ctx.k_last_w_list[ctx.k_last_w_idx++];
            return true;
        }
        return refill_streaming_tuples(ctx, opt, false);
    }

    size_t carry = ctx.step_size;
    for (int i = static_cast<int>(opt.wheels.size()) - 1; i >= 0 && carry > 0; --i) {
        const size_t w   = opt.wheels[i].size();
        const size_t sum = ctx.state[i] + carry;

        if (sum < w) {
            ctx.state[i] = sum;
            carry = 0;
        } else {
            ctx.state[i] = sum % w;
            carry        = sum / w;
        }
    }

    if (carry > 0) { ctx.is_done = true; return false; }

    size_t parity_sum = 0;
    for (size_t i = 0; i < opt.wheels.size(); ++i) {
        size_t w_size = opt.wheels[i].size();
        size_t eff = (opt.has_gray_code && (parity_sum % 2 != 0)) ? (w_size - 1 - ctx.state[i]) : ctx.state[i];
        parity_sum += ctx.state[i];
        ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][eff];
    }
    return true;
}

} // namespace cryptowords
