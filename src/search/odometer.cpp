#include "../../include/search/odometer.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include <cstring>
#include <algorithm>
#include <immintrin.h>

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

        alignas(32) uint16_t outer_vals[32];
        std::memset(outer_vals, 0xFF, sizeof(outer_vals));

        size_t parity_sum = 0;
        bool outer_dup = false;
        size_t dup_pos = 0;

        for (size_t i = 0; i < M; ++i) {
            size_t w_size = opt.wheels[i].size();
            size_t eff = (opt.has_gray_code && (parity_sum % 2 != 0)) ? (w_size - 1 - ctx.outer_state[i]) : ctx.outer_state[i];
            parity_sum += ctx.outer_state[i];
            uint16_t w_val = opt.wheels[i][eff];
            outer_vals[i] = w_val;

            if (opt.is_distinct) {
                for (size_t prev = 0; prev < i; ++prev) {
                    if (w_val == outer_vals[prev]) {
                        outer_dup = true;
                        dup_pos = i;
                        break;
                    }
                }
                if (outer_dup) break;
            }

            cryptowords::detail::set_11bits(ctx.k_block64, opt.unknown_bit_offsets[i], w_val);
            ctx.current_ids[opt.unknown_positions[i]] = w_val;
        }

        if (outer_dup) {
            if (dup_pos < M - 1) {
                // OTM-36: Salto Instantâneo de Subárvores (Subtree Skipping)
                for (size_t k = dup_pos + 1; k < M; ++k) {
                    ctx.outer_state[k] = 0;
                }
                size_t carry = 1;
                for (int k = static_cast<int>(dup_pos); k >= 0 && carry > 0; --k) {
                    size_t sum = ctx.outer_state[k] + carry;
                    if (sum < opt.wheels[k].size()) {
                        ctx.outer_state[k] = sum;
                        carry = 0;
                    } else {
                        ctx.outer_state[k] = sum % opt.wheels[k].size();
                        carry = sum / opt.wheels[k].size();
                    }
                }
                if (carry > 0) {
                    ctx.is_done = true;
                    return false;
                }

                if (ctx.step_size > 1) {
                    size_t rem = 0;
                    for (size_t k = 0; k < M; ++k) {
                        rem = (rem * (opt.wheels[k].size() % ctx.step_size) + (ctx.outer_state[k] % ctx.step_size)) % ctx.step_size;
                    }
                    size_t offset = (ctx.thread_idx >= rem) ? (ctx.thread_idx - rem) : (ctx.thread_idx + ctx.step_size - rem);
                    if (offset > 0) {
                        size_t add_carry = offset;
                        for (int k = static_cast<int>(M) - 1; k >= 0 && add_carry > 0; --k) {
                            size_t sum = ctx.outer_state[k] + add_carry;
                            if (sum < opt.wheels[k].size()) {
                                ctx.outer_state[k] = sum;
                                add_carry = 0;
                            } else {
                                ctx.outer_state[k] = sum % opt.wheels[k].size();
                                add_carry = sum / opt.wheels[k].size();
                            }
                        }
                        if (add_carry > 0) {
                            ctx.is_done = true;
                            return false;
                        }
                    }
                }
                is_init = true;
            }
            continue;
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

        const uint16_t u0_val = outer_vals[0];
        const uint16_t u1_val = (M > 1) ? outer_vals[1] : 0xFFFF;
        const uint16_t u2_val = (M > 2) ? outer_vals[2] : 0xFFFF;
        const uint16_t u3_val = (M > 3) ? outer_vals[3] : 0xFFFF;

        auto is_dup = [&](uint16_t w) -> bool {
            if (!opt.is_distinct) return false;
            if (M == 2) return (w == u0_val || w == u1_val);
            if (M == 3) return (w == u0_val || w == u1_val || w == u2_val);
            if (M == 4) return (w == u0_val || w == u1_val || w == u2_val || w == u3_val);
            if (M == 1) return (w == u0_val);
#if defined(__AVX2__)
            __m256i target = _mm256_set1_epi16(static_cast<short>(w));
            __m256i o0 = _mm256_load_si256((const __m256i*)&outer_vals[0]);
            __m256i cmp0 = _mm256_cmpeq_epi16(target, o0);
            if (!_mm256_testz_si256(cmp0, cmp0)) return true;
            if (M > 16) {
                __m256i o1 = _mm256_load_si256((const __m256i*)&outer_vals[16]);
                __m256i cmp1 = _mm256_cmpeq_epi16(target, o1);
                if (!_mm256_testz_si256(cmp1, cmp1)) return true;
            }
            return false;
#elif defined(__SSE2__)
            __m128i target = _mm_set1_epi16(static_cast<short>(w));
            __m128i o0 = _mm_loadu_si128((const __m128i*)&outer_vals[0]);
            __m128i cmp0 = _mm_cmpeq_epi16(target, o0);
            if (_mm_movemask_epi8(cmp0) != 0) return true;
            if (M > 8) {
                __m128i o1 = _mm_loadu_si128((const __m128i*)&outer_vals[8]);
                __m128i cmp1 = _mm_cmpeq_epi16(target, o1);
                if (_mm_movemask_epi8(cmp1) != 0) return true;
            }
            if (M > 16) {
                __m128i o2 = _mm_loadu_si128((const __m128i*)&outer_vals[16]);
                __m128i cmp2 = _mm_cmpeq_epi16(target, o2);
                if (_mm_movemask_epi8(cmp2) != 0) return true;
            }
            return false;
#else
            for (size_t i = 0; i < M; ++i) {
                if (w == outer_vals[i]) return true;
            }
            return false;
#endif
        };

        const size_t word_end_byte = opt.has_cascade_deduction ? byte_pos : (last_u_bit + 10) / 8;
        const bool in_msg0 = (word_end_byte < 16);
        const bool in_msg1 = (byte_pos >= 16 && word_end_byte < 32);

        if (opt.has_cascade_deduction) {
            ctx.k_block64[opt.entropy_bytes] = 0x80;
#if defined(__SHA__)
            if (in_msg1) {
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
                const __m128i ABEF_SAVE = _mm_set_epi32(0x6a09e667, 0xbb67ae85, 0x510e527f, 0x9b05688c);
                __m128i STATE0 = ABEF_SAVE;
                __m128i STATE1 = _mm_set_epi32(0x3c6ef372, 0xa54ff53a, 0x1f83d9ab, 0x5be0cd19);

                __m128i MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*) (ctx.k_block64 + 0)), MASK);
                __m128i MSG2 = _mm_load_si128((const __m128i*) ctx.streaming_msg2);
                __m128i MSG3 = _mm_load_si128((const __m128i*) ctx.streaming_msg3);

                // Rounds 0-3
                __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
                STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
                MSG = _mm_shuffle_epi32(MSG, 0x0E);
                STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

                __m128i clear_mask = _mm_load_si128((const __m128i*)ctx.streaming_clear_mask);
                __m128i base = _mm_loadu_si128((const __m128i*)(ctx.k_block64 + 16));
                __m128i base_cleared = _mm_and_si128(base, clear_mask);
                __m128i base_cleared_shuffled = _mm_shuffle_epi8(base_cleared, MASK);

                __m128i combined_shuf_mask = _mm_load_si128((const __m128i*)ctx.streaming_combined_shuf_mask);
                uint8_t base_masked = ctx.k_block64[byte_pos] & static_cast<uint8_t>(~(((0x7FFu << shift) >> 16) & 0xFF));
                uint32_t v32_base = base_masked;
                __m128i BASE_TOTAL = _mm_or_si128(base_cleared_shuffled,
                                                  _mm_shuffle_epi8(_mm_cvtsi32_si128(v32_base), combined_shuf_mask));

                const auto& wheel = opt.wheels[M];
                const size_t sz = wheel.size();
                const __m128i* word_vecs = reinterpret_cast<const __m128i*>(ctx.streaming_word_vecs);

                size_t idx = 0;
                for (; idx + 1 < sz; idx += 2) {
                    uint16_t ea = wheel[idx];
                    uint16_t eb = wheel[idx + 1];

                    __m128i MSG1_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    __m128i MSG1_B = _mm_or_si128(BASE_TOTAL, word_vecs[idx + 1]);

                    uint8_t ha, hb;
                    cryptowords::detail::sha256_bip39_msg1_variable_shani_x2(
                        STATE0, STATE1, MSG0, MSG2, MSG3, ABEF_SAVE,
                        MSG1_A, MSG1_B, ha, hb);

                    uint16_t syn_a = ea | (ha >> cs_shift);
                    if (opt.allowed_last_words[syn_a] && !is_dup(syn_a)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn_a;
                    }

                    uint16_t syn_b = eb | (hb >> cs_shift);
                    if (opt.allowed_last_words[syn_b] && !is_dup(syn_b)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn_b;
                    }
                }
                if (idx < sz) {
                    uint16_t ea = wheel[idx];
                    __m128i MSG1_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    uint8_t ha = cryptowords::detail::sha256_bip39_msg1_variable_shani_reg(
                        STATE0, STATE1, MSG0, MSG2, MSG3, ABEF_SAVE, MSG1_A);
                    uint16_t syn_a = ea | (ha >> cs_shift);
                    if (opt.allowed_last_words[syn_a] && !is_dup(syn_a)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn_a;
                    }
                }
            } else if (in_msg0) {
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
                __m128i MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*) (ctx.k_block64 + 16)), MASK);
                __m128i MSG2 = _mm_load_si128((const __m128i*) ctx.streaming_msg2);
                __m128i MSG3 = _mm_load_si128((const __m128i*) ctx.streaming_msg3);

                __m128i clear_mask = _mm_load_si128((const __m128i*)ctx.streaming_clear_mask);
                __m128i base = _mm_loadu_si128((const __m128i*)(ctx.k_block64 + 0));
                __m128i base_cleared = _mm_and_si128(base, clear_mask);
                __m128i base_cleared_shuffled = _mm_shuffle_epi8(base_cleared, MASK);

                __m128i combined_shuf_mask = _mm_load_si128((const __m128i*)ctx.streaming_combined_shuf_mask);
                uint8_t base_masked = ctx.k_block64[byte_pos] & static_cast<uint8_t>(~(((0x7FFu << shift) >> 16) & 0xFF));
                uint32_t v32_base = base_masked;
                __m128i BASE_TOTAL = _mm_or_si128(base_cleared_shuffled,
                                                  _mm_shuffle_epi8(_mm_cvtsi32_si128(v32_base), combined_shuf_mask));

                const auto& wheel = opt.wheels[M];
                const size_t sz = wheel.size();
                const __m128i* word_vecs = reinterpret_cast<const __m128i*>(ctx.streaming_word_vecs);

                size_t idx = 0;
                for (; idx + 1 < sz; idx += 2) {
                    uint16_t ea = wheel[idx];
                    uint16_t eb = wheel[idx + 1];

                    __m128i MSG0_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    __m128i MSG0_B = _mm_or_si128(BASE_TOTAL, word_vecs[idx + 1]);

                    uint8_t ha, hb;
                    cryptowords::detail::sha256_bip39_msg0_variable_shani_x2(
                        MSG1, MSG2, MSG3, MSG0_A, MSG0_B, ha, hb);

                    uint16_t syn_a = ea | (ha >> cs_shift);
                    if (opt.allowed_last_words[syn_a] && !is_dup(syn_a)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn_a;
                    }

                    uint16_t syn_b = eb | (hb >> cs_shift);
                    if (opt.allowed_last_words[syn_b] && !is_dup(syn_b)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn_b;
                    }
                }
                if (idx < sz) {
                    uint16_t ea = wheel[idx];
                    __m128i MSG0_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    uint8_t ha = cryptowords::detail::sha256_bip39_msg0_variable_shani_reg(
                        MSG1, MSG2, MSG3, MSG0_A);
                    uint16_t syn_a = ea | (ha >> cs_shift);
                    if (opt.allowed_last_words[syn_a] && !is_dup(syn_a)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn_a;
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
                    if (opt.allowed_last_words[syn] && !is_dup(syn)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = syn;
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
                if (opt.allowed_last_words[syn] && !is_dup(syn)) {
                    ctx.k_last_w_list[ctx.k_last_w_count++] = syn;
                }
            }
#endif
        } else {
#if defined(__SHA__)
            if (in_msg1) {
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
                const __m128i ABEF_SAVE = _mm_set_epi32(0x6a09e667, 0xbb67ae85, 0x510e527f, 0x9b05688c);
                __m128i STATE0 = ABEF_SAVE;
                __m128i STATE1 = _mm_set_epi32(0x3c6ef372, 0xa54ff53a, 0x1f83d9ab, 0x5be0cd19);

                __m128i MSG0 = _mm_loadu_si128((const __m128i*) (ctx.k_block64 + 0));
                MSG0 = _mm_shuffle_epi8(MSG0, MASK);

                __m128i MSG2 = _mm_load_si128((const __m128i*) ctx.streaming_msg2);
                __m128i MSG3 = _mm_load_si128((const __m128i*) ctx.streaming_msg3);

                // Rounds 0-3
                __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
                STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
                MSG = _mm_shuffle_epi32(MSG, 0x0E);
                STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

                __m128i clear_mask = _mm_load_si128((const __m128i*)ctx.streaming_clear_mask);
                __m128i base = _mm_loadu_si128((const __m128i*)(ctx.k_block64 + 16));
                __m128i base_cleared = _mm_and_si128(base, clear_mask);
                __m128i base_cleared_shuffled = _mm_shuffle_epi8(base_cleared, MASK);

                __m128i combined_shuf_mask = _mm_load_si128((const __m128i*)ctx.streaming_combined_shuf_mask);
                uint32_t v32_base = ((base_curr & 0xFF) << 16) | (base_curr & 0xFF00) | ((base_curr >> 16) & 0xFF);
                __m128i BASE_TOTAL = _mm_or_si128(base_cleared_shuffled,
                                                  _mm_shuffle_epi8(_mm_cvtsi32_si128(v32_base), combined_shuf_mask));

                const auto& wheel = opt.wheels[M];
                const size_t sz = wheel.size();
                const __m128i* word_vecs = reinterpret_cast<const __m128i*>(ctx.streaming_word_vecs);

                size_t idx = 0;
                for (; idx + 1 < sz; idx += 2) {
                    uint16_t wa = wheel[idx];
                    uint16_t wb = wheel[idx + 1];

                    __m128i MSG1_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    __m128i MSG1_B = _mm_or_si128(BASE_TOTAL, word_vecs[idx + 1]);

                    uint8_t ha, hb;
                    cryptowords::detail::sha256_bip39_msg1_variable_shani_x2(
                        STATE0, STATE1, MSG0, MSG2, MSG3, ABEF_SAVE,
                        MSG1_A, MSG1_B, ha, hb);

                    if ((ha >> cs_shift) == expected_cs && !is_dup(wa)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = wa;
                    }
                    if ((hb >> cs_shift) == expected_cs && !is_dup(wb)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = wb;
                    }
                }
                if (idx < sz) {
                    uint16_t wa = wheel[idx];
                    __m128i MSG1_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    uint8_t ha = cryptowords::detail::sha256_bip39_msg1_variable_shani_reg(
                        STATE0, STATE1, MSG0, MSG2, MSG3, ABEF_SAVE, MSG1_A);
                    if ((ha >> cs_shift) == expected_cs && !is_dup(wa)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = wa;
                    }
                }
            } else if (in_msg0) {
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
                __m128i MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*) (ctx.k_block64 + 16)), MASK);
                __m128i MSG2 = _mm_load_si128((const __m128i*) ctx.streaming_msg2);
                __m128i MSG3 = _mm_load_si128((const __m128i*) ctx.streaming_msg3);

                __m128i clear_mask = _mm_load_si128((const __m128i*)ctx.streaming_clear_mask);
                __m128i base = _mm_loadu_si128((const __m128i*)(ctx.k_block64 + 0));
                __m128i base_cleared = _mm_and_si128(base, clear_mask);
                __m128i base_cleared_shuffled = _mm_shuffle_epi8(base_cleared, MASK);

                __m128i combined_shuf_mask = _mm_load_si128((const __m128i*)ctx.streaming_combined_shuf_mask);
                uint32_t v32_base = ((base_curr & 0xFF) << 16) | (base_curr & 0xFF00) | ((base_curr >> 16) & 0xFF);
                __m128i BASE_TOTAL = _mm_or_si128(base_cleared_shuffled,
                                                  _mm_shuffle_epi8(_mm_cvtsi32_si128(v32_base), combined_shuf_mask));

                const auto& wheel = opt.wheels[M];
                const size_t sz = wheel.size();
                const __m128i* word_vecs = reinterpret_cast<const __m128i*>(ctx.streaming_word_vecs);

                size_t idx = 0;
                for (; idx + 1 < sz; idx += 2) {
                    uint16_t wa = wheel[idx];
                    uint16_t wb = wheel[idx + 1];

                    __m128i MSG0_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    __m128i MSG0_B = _mm_or_si128(BASE_TOTAL, word_vecs[idx + 1]);

                    uint8_t ha, hb;
                    cryptowords::detail::sha256_bip39_msg0_variable_shani_x2(
                        MSG1, MSG2, MSG3, MSG0_A, MSG0_B, ha, hb);

                    if ((ha >> cs_shift) == expected_cs && !is_dup(wa)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = wa;
                    }
                    if ((hb >> cs_shift) == expected_cs && !is_dup(wb)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = wb;
                    }
                }
                if (idx < sz) {
                    uint16_t wa = wheel[idx];
                    __m128i MSG0_A = _mm_or_si128(BASE_TOTAL, word_vecs[idx]);
                    uint8_t ha = cryptowords::detail::sha256_bip39_msg0_variable_shani_reg(
                        MSG1, MSG2, MSG3, MSG0_A);
                    if ((ha >> cs_shift) == expected_cs && !is_dup(wa)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = wa;
                    }
                }
            } else {
                for (uint16_t w_last : opt.wheels[M]) {
                    uint32_t cur = base_curr | ((static_cast<uint32_t>(w_last & 0x7FF)) << shift);
                    ctx.k_block64[byte_pos]     = static_cast<uint8_t>((cur >> 16) & 0xFF);
                    ctx.k_block64[byte_pos + 1] = static_cast<uint8_t>((cur >> 8) & 0xFF);
                    ctx.k_block64[byte_pos + 2] = static_cast<uint8_t>(cur & 0xFF);

                    uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(ctx.k_block64);
                    if ((h >> cs_shift) == expected_cs && !is_dup(w_last)) {
                        ctx.k_last_w_list[ctx.k_last_w_count++] = w_last;
                    }
                }
            }
#else
            for (uint16_t w_last : opt.wheels[M]) {
                if (opt.is_distinct && is_dup(w_last)) continue;
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

static bool advance_mixed_radix(PipelineThreadContext& ctx, const OptimizedMnemonics& opt, bool is_init) {
    const size_t W_COUNT = opt.wheels.size();
    if (W_COUNT == 0) { ctx.is_done = true; return false; }

    while (true) {
        if (!is_init) {
            size_t carry = ctx.step_size;
            for (int i = static_cast<int>(W_COUNT) - 1; i >= 0 && carry > 0; --i) {
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
        }
        is_init = false;

        size_t parity_sum = 0;
        bool has_dup = false;
        size_t dup_pos = 0;

        for (size_t i = 0; i < W_COUNT; ++i) {
            size_t w_size = opt.wheels[i].size();
            size_t eff = (opt.has_gray_code && (parity_sum % 2 != 0)) ? (w_size - 1 - ctx.state[i]) : ctx.state[i];
            parity_sum += ctx.state[i];
            uint16_t w_val = opt.wheels[i][eff];
            ctx.current_ids[opt.unknown_positions[i]] = w_val;

            if (opt.is_distinct) {
                for (size_t prev = 0; prev < i; ++prev) {
                    if (w_val == ctx.current_ids[opt.unknown_positions[prev]]) {
                        has_dup = true;
                        dup_pos = i;
                        break;
                    }
                }
                if (has_dup) break;
            }
        }

        if (has_dup) {
            if (dup_pos < W_COUNT - 1) {
                for (size_t k = dup_pos + 1; k < W_COUNT; ++k) {
                    ctx.state[k] = 0;
                }
                size_t c = 1;
                for (int k = static_cast<int>(dup_pos); k >= 0 && c > 0; --k) {
                    size_t sum = ctx.state[k] + c;
                    if (sum < opt.wheels[k].size()) {
                        ctx.state[k] = sum;
                        c = 0;
                    } else {
                        ctx.state[k] = sum % opt.wheels[k].size();
                        c = sum / opt.wheels[k].size();
                    }
                }
                if (c > 0) { ctx.is_done = true; return false; }

                if (ctx.step_size > 1) {
                    size_t rem = 0;
                    for (size_t k = 0; k < W_COUNT; ++k) {
                        rem = (rem * (opt.wheels[k].size() % ctx.step_size) + (ctx.state[k] % ctx.step_size)) % ctx.step_size;
                    }
                    size_t offset = (ctx.thread_idx >= rem) ? (ctx.thread_idx - rem) : (ctx.thread_idx + ctx.step_size - rem);
                    if (offset > 0) {
                        size_t add_carry = offset;
                        for (int k = static_cast<int>(W_COUNT) - 1; k >= 0 && add_carry > 0; --k) {
                            size_t sum = ctx.state[k] + add_carry;
                            if (sum < opt.wheels[k].size()) {
                                ctx.state[k] = sum;
                                add_carry = 0;
                            } else {
                                ctx.state[k] = sum % opt.wheels[k].size();
                                add_carry = sum / opt.wheels[k].size();
                            }
                        }
                        if (add_carry > 0) { ctx.is_done = true; return false; }
                    }
                }
                is_init = true;
            }
            continue;
        }

        return true;
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

#if defined(__SHA__)
        if (K >= 3) {
            const size_t last_u_bit = opt.unknown_bit_offsets[M];
            const size_t byte_pos   = last_u_bit / 8;
            const size_t bit_pos    = last_u_bit % 8;
            const uint32_t shift    = 24 - 11 - bit_pos;

            const size_t word_end_byte = opt.has_cascade_deduction ? byte_pos : (last_u_bit + 10) / 8;
            const bool in_msg0 = (word_end_byte < 16);
            const bool in_msg1 = (byte_pos >= 16 && word_end_byte < 32);

            if (in_msg0 || in_msg1) {
                const size_t off = in_msg1 ? (byte_pos - 16) : byte_pos;
                const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

                alignas(16) uint8_t clear_mask_bytes[16];
                alignas(16) int8_t shuf_bytes[16];
                const int num_bytes = opt.has_cascade_deduction ? 1 : 3;
                for (int k = 0; k < 16; ++k) {
                    if (k >= (int)off && k < (int)off + num_bytes) {
                        clear_mask_bytes[k] = 0x00;
                        shuf_bytes[k] = (int8_t)(k - off);
                    } else {
                        clear_mask_bytes[k] = 0xFF;
                        shuf_bytes[k] = (int8_t)0x80;
                    }
                }
                _mm_store_si128((__m128i*)ctx.streaming_clear_mask, _mm_load_si128((const __m128i*)clear_mask_bytes));

                alignas(16) uint8_t mask_bytes[16];
                _mm_store_si128((__m128i*)mask_bytes, MASK);
                alignas(16) int8_t combined_shuf_bytes[16];
                for (int k = 0; k < 16; ++k) {
                    uint8_t src_pos = mask_bytes[k];
                    combined_shuf_bytes[k] = shuf_bytes[src_pos];
                }
                __m128i combined_shuf_mask = _mm_load_si128((const __m128i*)combined_shuf_bytes);
                _mm_store_si128((__m128i*)ctx.streaming_combined_shuf_mask, combined_shuf_mask);

                __m128i pre_msg2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*) (opt.base_block64 + 32)), MASK);
                __m128i pre_msg3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*) (opt.base_block64 + 48)), MASK);
                _mm_store_si128((__m128i*)ctx.streaming_msg2, pre_msg2);
                _mm_store_si128((__m128i*)ctx.streaming_msg3, pre_msg3);

                const auto& wheel = opt.wheels[M];
                __m128i* vecs = reinterpret_cast<__m128i*>(ctx.streaming_word_vecs);
                for (size_t i = 0; i < wheel.size(); ++i) {
                    uint32_t word_shifted = (static_cast<uint32_t>(wheel[i] & 0x7FF)) << shift;
                    uint32_t v32_word = opt.has_cascade_deduction
                        ? ((word_shifted >> 16) & 0xFF)
                        : (((word_shifted & 0xFF) << 16) | (word_shifted & 0xFF00) | ((word_shifted >> 16) & 0xFF));
                    vecs[i] = _mm_shuffle_epi8(_mm_cvtsi32_si128(v32_word), combined_shuf_mask);
                }
                ctx.streaming_vecs_initialized = true;
            }
        }
#endif

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

    if (opt.is_distinct) {
        if (!advance_mixed_radix(ctx, opt, true)) {
            ctx.is_done = true;
        }
    } else {
        size_t parity_sum = 0;
        for (size_t i = 0; i < opt.wheels.size(); ++i) {
            size_t w_size = opt.wheels[i].size();
            size_t eff = (opt.has_gray_code && (parity_sum % 2 != 0)) ? (w_size - 1 - ctx.state[i]) : ctx.state[i];
            parity_sum += ctx.state[i];
            ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][eff];
        }
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

    return advance_mixed_radix(ctx, opt, false);
}

} // namespace cryptowords
