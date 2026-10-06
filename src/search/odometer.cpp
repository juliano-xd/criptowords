#include "../../include/search/odometer.hpp"

#include <immintrin.h>

#include <algorithm>
#include <array>
#include <cstring>

#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include "../../include/search/random_perm.hpp"

// =========================================================================
// FASE 4 — Enumerador de candidatos.
//
// Três classes por modo de enumeração. Cada uma implementa IOdometer sem
// branch em hot path; make_odometer(plan) decide uma vez.
//
//   MixedOdometer       K ≤ 2 ou --checksum ou --invalid_too
//   StreamingOdometer   K ≥ 3 com --only_valids
//   IndexedListOdometer reservado para Pairs/Triplets pré-computados
// =========================================================================

using namespace cryptowords;

namespace cryptowords {
namespace {

// --repeat: verificação defensiva. O odômetro tenta respeitar durante a
// enumeração; este filtro cobre qualquer caminho que escape.
bool satisfies_repeat_constraints(const EnumCursor& cur,
                                  const OptimizedMnemonics& opt) noexcept {
    const uint16_t* const ids   = cur.current_ids.data();
    const size_t*   const u_pos = opt.unknown_positions.data();
    const size_t n_unk = opt.unknown_positions.size();

    for (const auto& [id, required] : opt.repeat_ids_exact) {
        if (required == 0) continue;
        size_t cnt = 0;
        for (size_t i = 0; i < n_unk; ++i)
            if (ids[u_pos[i]] == id) ++cnt;
        if (cnt != static_cast<size_t>(required)) return false;
    }
    return true;
}

// =========================================================================
// MixedOdometer — mixed-radix sobre todos os wheels.
// =========================================================================
class MixedOdometer final : public IOdometer {
    // Avança o cursor e preenche current_ids. is_init permite reuso após
    // seek_linear sem somar step_size.
    static bool step(EnumCursor& cur, const OptimizedMnemonics& opt, bool is_init) {
        const size_t W = opt.wheels.size();
        if (W == 0) { cur.done = true; return false; }

        // Reutilizados entre iterações para evitar alocação.
        alignas(32) std::array<uint16_t, 32> vals{};

        while (true) {
            if (!is_init) {
                size_t carry = cur.step_size;
                for (int i = static_cast<int>(W) - 1; i >= 0 && carry > 0; --i) {
                    const size_t w = opt.wheels[i].size();
                    const size_t sum = cur.state[i] + carry;
                    if (sum < w) { cur.state[i] = sum; carry = 0; }
                    else { cur.state[i] = sum % w; carry = sum / w; }
                }
                if (carry > 0) { cur.done = true; return false; }
            }
            is_init = false;

            size_t parity = 0;
            bool has_dup = false;
            size_t dup_pos = 0;

            for (size_t i = 0; i < W; ++i) {
                const size_t w_size = opt.wheels[i].size();
                const size_t eff = (opt.has_gray_code && (parity % 2 != 0))
                                       ? (w_size - 1 - cur.state[i]) : cur.state[i];
                parity += cur.state[i];
                const uint16_t v = opt.wheels[i][eff];
                vals[i] = v;

                if (opt.is_distinct) {
                    const uint8_t limit = opt.max_count[v];
                    if (limit == 1) {
                        for (size_t prev = 0; prev < i; ++prev)
                            if (v == vals[prev]) { has_dup = true; dup_pos = i; break; }
                    } else if (limit > 1) {
                        uint8_t cnt = 0;
                        for (size_t prev = 0; prev < i; ++prev)
                            if (v == vals[prev] && ++cnt >= limit) { has_dup = true; dup_pos = i; break; }
                    }
                    if (has_dup) break;
                }
            }

            if (has_dup) {
                if (dup_pos >= W - 1) continue;
                for (size_t k = dup_pos + 1; k < W; ++k) cur.state[k] = 0;
                size_t c = 1;
                for (int k = static_cast<int>(dup_pos); k >= 0 && c > 0; --k) {
                    const size_t sum = cur.state[k] + c;
                    if (sum < opt.wheels[k].size()) { cur.state[k] = sum; c = 0; }
                    else { cur.state[k] = sum % opt.wheels[k].size(); c = sum / opt.wheels[k].size(); }
                }
                if (c > 0) { cur.done = true; return false; }

                // Reaplica partição por thread.
                if (cur.step_size > 1) {
                    size_t rem = 0;
                    for (size_t k = 0; k < W; ++k)
                        rem = (rem * (opt.wheels[k].size() % cur.step_size) +
                               (cur.state[k] % cur.step_size)) % cur.step_size;
                    size_t offset = (cur.thread_idx >= rem) ? (cur.thread_idx - rem)
                                                            : (cur.thread_idx + cur.step_size - rem);
                    if (offset > 0) {
                        size_t add = offset;
                        for (int k = static_cast<int>(W) - 1; k >= 0 && add > 0; --k) {
                            const size_t sum = cur.state[k] + add;
                            if (sum < opt.wheels[k].size()) { cur.state[k] = sum; add = 0; }
                            else { cur.state[k] = sum % opt.wheels[k].size(); add = sum / opt.wheels[k].size(); }
                        }
                        if (add > 0) { cur.done = true; return false; }
                    }
                }
                is_init = true;
                continue;
            }

            for (size_t i = 0; i < W; ++i)
                cur.current_ids[opt.unknown_positions[i]] = vals[i];
            return true;
        }
    }

   public:
    void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                    size_t num_threads, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        cur.thread_idx = thread_idx;
        cur.step_size  = num_threads;
        cur.done       = false;
        cur.current_ids = opt.base_mnemonic;

        auto finalize = [&]() {
            if (cur.done) return;
            if (__builtin_expect(opt.repeat_ids_empty_, 1)) return;
            while (!satisfies_repeat_constraints(cur, opt))
                if (!step(cur, opt, false)) { cur.done = true; return; }
        };

        const size_t W = opt.wheels.size();
        cur.state.assign(W, 0);

        size_t temp = thread_idx;
        for (int i = static_cast<int>(W) - 1; i >= 0; --i) {
            const size_t w = opt.wheels[i].size();
            if (w == 0) { cur.done = true; return; }
            cur.state[i] = temp % w;
            temp /= w;
        }
        if (temp > 0) { cur.done = true; return; }

        if (opt.is_distinct) {
            if (!step(cur, opt, true)) cur.done = true;
        } else {
            size_t parity = 0;
            for (size_t i = 0; i < W; ++i) {
                const size_t w_size = opt.wheels[i].size();
                const size_t eff = (opt.has_gray_code && (parity % 2 != 0))
                                       ? (w_size - 1 - cur.state[i]) : cur.state[i];
                parity += cur.state[i];
                cur.current_ids[opt.unknown_positions[i]] = opt.wheels[i][eff];
            }
        }
        finalize();
    }

    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        if (cur.done) return false;
        return step(cur, opt, false);
    }

    uint64_t linear_position(const PipelineThreadContext& ctx,
                             const OptimizedMnemonics& opt) const override {
        const auto& cur = ctx.cursor;
        uint64_t idx = 0;
        for (size_t i = 0; i < opt.wheels.size(); ++i)
            idx = idx * opt.wheels[i].size() + cur.state[i];
        return idx;
    }

    void seek_linear(PipelineThreadContext& ctx, const OptimizedMnemonics& opt,
                     uint64_t idx) override {
        auto& cur = ctx.cursor;
        if (idx >= total_space(opt)) { cur.done = true; return; }

        const size_t W = opt.wheels.size();
        cur.state.assign(W, 0);
        uint64_t tmp = idx;
        for (int i = static_cast<int>(W) - 1; i >= 0; --i) {
            const size_t sz = opt.wheels[i].size();
            cur.state[i] = tmp % sz;
            tmp /= sz;
        }
        for (size_t i = 0; i < W; ++i)
            cur.current_ids[opt.unknown_positions[i]] = opt.wheels[i][cur.state[i]];

        cur.done = false;
        cur.last_candidate_accepted = true;
    }

    uint64_t total_space(const OptimizedMnemonics& opt) const override {
        uint64_t prod = 1;
        for (const auto& w : opt.wheels) prod *= w.size();
        return prod;
    }
};

// =========================================================================
// RandomMixedOdometer — mixed-radix em ordem pseudoaleatória.
//
// Cada thread mantém um contador linear; a cada passo soma `step_size` e
// aplica uma permutação Feistel (bijection sobre [0, N)) para obter o índice
// real. Decodifica em state e popula current_ids. Aplica --distinct e
// --repeat por verificação pós-decodificação.
//
// Save/resume: `linear_position` retorna o contador (não o valor permutado).
// =========================================================================
class RandomMixedOdometer final : public IOdometer {
    Permuter perm_;
    uint64_t total_ = 0;

    // Checa --distinct (max_count) sobre os valores já populados em
    // current_ids. --repeat é checado separadamente por
    // satisfies_repeat_constraints.
    static bool distinct_ok(const EnumCursor& cur, const OptimizedMnemonics& opt) noexcept {
        if (!opt.is_distinct) return true;
        const size_t W = opt.wheels.size();
        alignas(32) std::array<uint16_t, 32> vals{};
        for (size_t i = 0; i < W; ++i) {
            const uint16_t v = cur.current_ids[opt.unknown_positions[i]];
            vals[i] = v;
            const uint8_t limit = opt.max_count[v];
            if (limit == 1) {
                for (size_t prev = 0; prev < i; ++prev)
                    if (v == vals[prev]) return false;
            } else if (limit > 1) {
                uint8_t cnt = 0;
                for (size_t prev = 0; prev < i; ++prev)
                    if (v == vals[prev] && ++cnt >= limit) return false;
            }
        }
        return true;
    }

    static void decode_into_state(EnumCursor& cur, const OptimizedMnemonics& opt,
                                  uint64_t permuted) {
        const size_t W = opt.wheels.size();
        uint64_t tmp = permuted;
        for (int i = static_cast<int>(W) - 1; i >= 0; --i) {
            const size_t sz = opt.wheels[i].size();
            cur.state[i] = tmp % sz;
            tmp /= sz;
        }
        for (size_t i = 0; i < W; ++i)
            cur.current_ids[opt.unknown_positions[i]] = opt.wheels[i][cur.state[i]];
    }

    bool next(EnumCursor& cur, const OptimizedMnemonics& opt, bool is_init) {
        while (true) {
            if (!is_init) {
                cur.linear_counter += cur.step_size;
                if (cur.linear_counter >= total_) { cur.done = true; return false; }
            }
            is_init = false;

            const uint64_t p = perm_.permute(cur.linear_counter);
            decode_into_state(cur, opt, p);

            if (!distinct_ok(cur, opt)) continue;
            if (!satisfies_repeat_constraints(cur, opt)) continue;
            return true;
        }
    }

   public:
    RandomMixedOdometer(uint64_t total, uint64_t seed) noexcept
        : perm_(total, seed), total_(total) {}

    void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                    size_t num_threads, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        cur.thread_idx     = thread_idx;
        cur.step_size      = num_threads;
        cur.done           = false;
        cur.linear_counter = thread_idx;
        cur.current_ids    = opt.base_mnemonic;
        cur.state.assign(opt.wheels.size(), 0);

        if (thread_idx >= total_) { cur.done = true; return; }
        if (!next(cur, opt, true)) cur.done = true;
    }

    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        if (cur.done) return false;
        return next(cur, opt, false);
    }

    uint64_t linear_position(const PipelineThreadContext& ctx,
                             const OptimizedMnemonics&) const override {
        return ctx.cursor.linear_counter;
    }

    void seek_linear(PipelineThreadContext& ctx, const OptimizedMnemonics& opt,
                     uint64_t idx) override {
        auto& cur = ctx.cursor;
        if (idx >= total_) { cur.done = true; return; }
        cur.linear_counter = idx;
        cur.done = false;
        if (!next(cur, opt, true)) cur.done = true;
    }

    uint64_t total_space(const OptimizedMnemonics&) const override {
        return total_;
    }
};

// =========================================================================
// StreamingOdometer — outer wheels + síntese SHA-256 do último slot.
//
// Enumera ∏_{i<K-1} |wheel_i| outer states. Para cada, percorre o wheel da
// última posição sintetizando o checksum via SHA-256 (SHA-NI quando disp.).
// =========================================================================
class StreamingOdometer final : public IOdometer {
    // Prepara vetores de palavra no formato consumido por sha256_bip39_msg*_x2.
    static void setup_word_vecs(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) {
#if defined(__SHA__)
        const size_t M = opt.unknown_positions.size() - 1;
        const size_t last_u_bit = opt.unknown_bit_offsets[M];
        const size_t byte_pos = last_u_bit / 8;
        const size_t word_end_byte = opt.has_cascade_deduction ? byte_pos
                                                                : (last_u_bit + 10) / 8;
        const bool in_msg0 = (word_end_byte < 16);
        const bool in_msg1 = (byte_pos >= 16 && word_end_byte < 32);
        if (!in_msg0 && !in_msg1) return;

        const size_t off = in_msg1 ? (byte_pos - 16) : byte_pos;
        const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL,
                                            0x0405060700010203ULL);

        alignas(16) std::array<uint8_t, 16> clear_bytes{};
        alignas(16) std::array<int8_t, 16>  shuf_bytes{};
        const int nbytes = opt.has_cascade_deduction ? 1 : 3;
        for (int k = 0; k < 16; ++k) {
            if (k >= (int)off && k < (int)off + nbytes) {
                clear_bytes[k] = 0x00;
                shuf_bytes[k]  = static_cast<int8_t>(k - off);
            } else {
                clear_bytes[k] = 0xFF;
                shuf_bytes[k]  = static_cast<int8_t>(0x80);
            }
        }
        _mm_store_si128((__m128i*)ctx.stream.clear_mask.data(),
                        _mm_load_si128((const __m128i*)clear_bytes.data()));

        alignas(16) std::array<uint8_t, 16> mask_bytes{};
        _mm_store_si128((__m128i*)mask_bytes.data(), MASK);
        alignas(16) std::array<int8_t, 16> combined{};
        for (int k = 0; k < 16; ++k)
            combined[k] = shuf_bytes[mask_bytes[k]];
        __m128i shuf_mask = _mm_load_si128((const __m128i*)combined.data());
        _mm_store_si128((__m128i*)ctx.stream.shuf_mask.data(), shuf_mask);

        const __m128i base_hi0 = _mm_loadu_si128((const __m128i*)(opt.base_block64.data() + 32));
        const __m128i base_hi1 = _mm_loadu_si128((const __m128i*)(opt.base_block64.data() + 48));
        _mm_store_si128((__m128i*)ctx.stream.msg2.data(), _mm_shuffle_epi8(base_hi0, MASK));
        _mm_store_si128((__m128i*)ctx.stream.msg3.data(), _mm_shuffle_epi8(base_hi1, MASK));

        const auto& wheel = opt.wheels[M];
        const size_t needed = wheel.size() * 16;
        if (ctx.stream.word_vecs.size() < needed) ctx.stream.word_vecs.resize(needed);

        const size_t bit_pos = last_u_bit % 8;
        const uint32_t shift = 24 - 11 - bit_pos;

        __m128i* vecs = reinterpret_cast<__m128i*>(ctx.stream.word_vecs.data());
        for (size_t i = 0; i < wheel.size(); ++i) {
            const uint32_t word_shifted = (static_cast<uint32_t>(wheel[i] & 0x7FF)) << shift;
            const uint32_t v32 = opt.has_cascade_deduction
                                     ? ((word_shifted >> 16) & 0xFF)
                                     : (((word_shifted & 0xFF) << 16) |
                                        (word_shifted & 0xFF00) |
                                        ((word_shifted >> 16) & 0xFF));
            vecs[i] = _mm_shuffle_epi8(_mm_cvtsi32_si128(v32), shuf_mask);
        }
#endif
    }

    // Reabastece a fila de candidatos válidos para o último slot.
    static bool refill(EnumCursor& cur, PipelineThreadContext& ctx,
                       const OptimizedMnemonics& opt, bool is_init) {
        const size_t K = opt.unknown_positions.size();
        if (K < 2) { cur.done = true; return false; }
        const size_t M = K - 1;

        const size_t cs_shift = 8 - opt.checksum_bits;
        const uint8_t expected_cs = opt.expected_checksum;
        const size_t last_idx = opt.unknown_positions[M];
        const size_t last_bit = opt.unknown_bit_offsets[M];

        const auto& last_wheel = opt.wheels[M];
        const size_t e_bits = 11 - opt.checksum_bits;
        const uint16_t e_mask = static_cast<uint16_t>(((1u << e_bits) - 1) << opt.checksum_bits);

        struct RepeatState { uint16_t id; uint8_t min_cnt; uint8_t outer_cnt; };
        std::vector<RepeatState> repeat_states;
        repeat_states.reserve(opt.repeat_ids_exact.size());

        // Reutilizado entre outer states.
        alignas(32) std::array<uint16_t, 32> outer_vals{};

        while (true) {
            if (!is_init) {
                size_t carry = cur.step_size;
                for (int i = static_cast<int>(M) - 1; i >= 0 && carry > 0; --i) {
                    const size_t w = opt.wheels[i].size();
                    const size_t sum = cur.outer_state[i] + carry;
                    if (sum < w) { cur.outer_state[i] = sum; carry = 0; }
                    else { cur.outer_state[i] = sum % w; carry = sum / w; }
                }
                if (carry > 0) { cur.done = true; return false; }
            }
            is_init = false;

            outer_vals.fill(0xFFFF);
            size_t parity = 0;
            bool outer_dup = false;
            size_t dup_pos = 0;

            for (size_t i = 0; i < M; ++i) {
                const size_t w_size = opt.wheels[i].size();
                const size_t eff = (opt.has_gray_code && (parity % 2 != 0))
                                       ? (w_size - 1 - cur.outer_state[i]) : cur.outer_state[i];
                parity += cur.outer_state[i];
                const uint16_t v = opt.wheels[i][eff];
                outer_vals[i] = v;

                if (opt.is_distinct) {
                    const uint8_t limit = opt.max_count[v];
                    if (limit == 1) {
                        for (size_t prev = 0; prev < i; ++prev)
                            if (v == outer_vals[prev]) { outer_dup = true; dup_pos = i; break; }
                    } else if (limit > 1) {
                        uint8_t cnt = 0;
                        for (size_t prev = 0; prev < i; ++prev)
                            if (v == outer_vals[prev] && ++cnt >= limit) { outer_dup = true; dup_pos = i; break; }
                    }
                    if (outer_dup) break;
                }
            }

            if (outer_dup) {
                if (dup_pos >= M - 1) continue;
                for (size_t k = dup_pos + 1; k < M; ++k) cur.outer_state[k] = 0;
                size_t c = 1;
                for (int k = static_cast<int>(dup_pos); k >= 0 && c > 0; --k) {
                    const size_t sum = cur.outer_state[k] + c;
                    if (sum < opt.wheels[k].size()) { cur.outer_state[k] = sum; c = 0; }
                    else { cur.outer_state[k] = sum % opt.wheels[k].size(); c = sum / opt.wheels[k].size(); }
                }
                if (c > 0) { cur.done = true; return false; }

                if (cur.step_size > 1) {
                    size_t rem = 0;
                    for (size_t k = 0; k < M; ++k)
                        rem = (rem * (opt.wheels[k].size() % cur.step_size) +
                               (cur.outer_state[k] % cur.step_size)) % cur.step_size;
                    size_t offset = (cur.thread_idx >= rem) ? (cur.thread_idx - rem)
                                                            : (cur.thread_idx + cur.step_size - rem);
                    if (offset > 0) {
                        size_t add = offset;
                        for (int k = static_cast<int>(M) - 1; k >= 0 && add > 0; --k) {
                            const size_t sum = cur.outer_state[k] + add;
                            if (sum < opt.wheels[k].size()) { cur.outer_state[k] = sum; add = 0; }
                            else { cur.outer_state[k] = sum % opt.wheels[k].size(); add = sum / opt.wheels[k].size(); }
                        }
                        if (add > 0) { cur.done = true; return false; }
                    }
                }
                is_init = true;
                continue;
            }

            // --repeat: palavras obrigatórias nos outer wheels.
            repeat_states.clear();
            int required_last = -1;
            if (!opt.repeat_ids_empty_) {
                bool impossible = false;
                for (const auto& [id, req] : opt.repeat_ids_exact) {
                    if (req == 0) continue;
                    uint8_t cnt = 0;
                    for (size_t i = 0; i < M; ++i) if (outer_vals[i] == id) ++cnt;
                    if (cnt > req) { impossible = true; break; }
                    if (cnt + 1 < req) { impossible = true; break; }
                    if (cnt + 1 == req) {
                        if (required_last != -1 && required_last != static_cast<int>(id)) {
                            impossible = true; break;
                        }
                        required_last = static_cast<int>(id);
                    }
                    repeat_states.push_back({id, req, cnt});
                }
                if (impossible) continue;
                if (required_last >= 0 &&
                    !last_wheel.contains(static_cast<uint16_t>(required_last)))
                    continue;
            }

            auto last_ok = [&](uint16_t syn) -> bool {
                for (const auto& s : repeat_states)
                    if (syn == s.id && s.outer_cnt >= s.min_cnt) return false;
                return true;
            };

            // Commit outer_vals no k_block64 e current_ids.
            for (size_t i = 0; i < M; ++i) {
                cryptowords::detail::set_11bits(cur.k_block64.data(),
                                                opt.unknown_bit_offsets[i], outer_vals[i]);
                cur.current_ids[opt.unknown_positions[i]] = outer_vals[i];
            }

            cur.k_last_w_count = 0;
            cur.k_last_w_idx = 0;

            const size_t byte_pos = last_bit / 8;
            const size_t bit_pos  = last_bit % 8;
            const uint32_t shift  = 24 - 11 - bit_pos;
            const uint32_t mask   = ~(0x7FFu << shift);

            const uint32_t base_curr =
                ((static_cast<uint32_t>(cur.k_block64[byte_pos]) << 16) |
                 (static_cast<uint32_t>(cur.k_block64[byte_pos + 1]) << 8) |
                 (static_cast<uint32_t>(cur.k_block64[byte_pos + 2]))) & mask;

            const uint16_t u0 = outer_vals[0];
            const uint16_t u1 = (M > 1) ? outer_vals[1] : 0xFFFF;
            const uint16_t u2 = (M > 2) ? outer_vals[2] : 0xFFFF;
            const uint16_t u3 = (M > 3) ? outer_vals[3] : 0xFFFF;

            auto is_dup = [&](uint16_t w) -> bool {
                if (!opt.is_distinct) return false;
                const uint8_t limit = opt.max_count[w];
                if (limit == 0) return true;
                if (limit == 1) {
                    if (M == 1) return (w == u0);
                    if (M == 2) return (w == u0 || w == u1);
                    if (M == 3) return (w == u0 || w == u1 || w == u2);
                    if (M == 4) return (w == u0 || w == u1 || w == u2 || w == u3);
#if defined(__AVX2__)
                    const __m256i target = _mm256_set1_epi16(static_cast<short>(w));
                    const __m256i o0 = _mm256_load_si256((const __m256i*)&outer_vals[0]);
                    if (!_mm256_testz_si256(_mm256_cmpeq_epi16(target, o0),
                                            _mm256_cmpeq_epi16(target, o0))) return true;
                    if (M > 16) {
                        const __m256i o1 = _mm256_load_si256((const __m256i*)&outer_vals[16]);
                        if (!_mm256_testz_si256(_mm256_cmpeq_epi16(target, o1),
                                                _mm256_cmpeq_epi16(target, o1))) return true;
                    }
                    return false;
#else
                    for (size_t i = 0; i < M; ++i) if (w == outer_vals[i]) return true;
                    return false;
#endif
                }
                uint8_t cnt = 0;
                for (size_t i = 0; i < M; ++i)
                    if (w == outer_vals[i] && ++cnt >= limit) return true;
                return false;
            };

            const size_t word_end_byte = opt.has_cascade_deduction
                                             ? byte_pos : (last_bit + 10) / 8;
            const bool in_msg0 = (word_end_byte < 16);
            const bool in_msg1 = (byte_pos >= 16 && word_end_byte < 32);

            // Fast path --repeat: apenas a palavra obrigatória no último slot.
            if (required_last >= 0) {
                const uint16_t want = static_cast<uint16_t>(required_last & e_mask);
                const uint32_t c = base_curr |
                                   ((static_cast<uint32_t>(want & 0x7FF)) << shift);
                cur.k_block64[byte_pos]     = static_cast<uint8_t>((c >> 16) & 0xFF);
                cur.k_block64[byte_pos + 1] = static_cast<uint8_t>((c >> 8) & 0xFF);
                cur.k_block64[byte_pos + 2] = static_cast<uint8_t>(c & 0xFF);

#if defined(__SHA__)
                const uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(cur.k_block64.data());
#else
                alignas(64) std::array<uint8_t, 32> hash{};
                crypto::SHA256::hash(cur.k_block64.data(), opt.entropy_bytes, hash.data());
                const uint8_t h = hash[0];
#endif
                const uint16_t syn = static_cast<uint16_t>(want | (h >> cs_shift));
                if (syn == static_cast<uint16_t>(required_last) &&
                    opt.allowed_last_words.test(syn) && !is_dup(syn))
                    cur.k_last_w_list[cur.k_last_w_count++] = syn;
            }
            // Cascade: todas as entradas do wheel, filtradas por AutoDeduce.
            else if (opt.has_cascade_deduction) {
                cur.k_block64[opt.entropy_bytes] = 0x80;
#if defined(__SHA__)
                if (in_msg0 || in_msg1) {
                    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL,
                                                        0x0405060700010203ULL);
                    const __m128i ABEF_SAVE = _mm_set_epi32(0x6a09e667, 0xbb67ae85,
                                                            0x510e527f, 0x9b05688c);
                    __m128i S0 = ABEF_SAVE;
                    __m128i S1 = _mm_set_epi32(0x3c6ef372, 0xa54ff53a,
                                               0x1f83d9ab, 0x5be0cd19);
                    __m128i MSG0, MSG1, MSG2, MSG3;
                    if (in_msg1) {
                        MSG0 = _mm_shuffle_epi8(
                            _mm_loadu_si128((const __m128i*)(cur.k_block64.data() + 0)), MASK);
                        MSG2 = _mm_load_si128((const __m128i*)ctx.stream.msg2.data());
                        MSG3 = _mm_load_si128((const __m128i*)ctx.stream.msg3.data());
                        __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL,
                                                                         0x71374491428A2F98ULL));
                        S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
                        MSG = _mm_shuffle_epi32(MSG, 0x0E);
                        S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
                    } else {
                        MSG1 = _mm_shuffle_epi8(
                            _mm_loadu_si128((const __m128i*)(cur.k_block64.data() + 16)), MASK);
                        MSG2 = _mm_load_si128((const __m128i*)ctx.stream.msg2.data());
                        MSG3 = _mm_load_si128((const __m128i*)ctx.stream.msg3.data());
                    }
                    __m128i clear = _mm_load_si128((const __m128i*)ctx.stream.clear_mask.data());
                    __m128i base = _mm_loadu_si128(
                        (const __m128i*)(cur.k_block64.data() + (in_msg1 ? 16 : 0)));
                    __m128i base_cleared = _mm_shuffle_epi8(_mm_and_si128(base, clear), MASK);
                    __m128i shuf = _mm_load_si128((const __m128i*)ctx.stream.shuf_mask.data());
                    const uint8_t base_masked = cur.k_block64[byte_pos] &
                        static_cast<uint8_t>(~(((0x7FFu << shift) >> 16) & 0xFF));
                    const __m128i BASE_TOTAL = _mm_or_si128(
                        base_cleared,
                        _mm_shuffle_epi8(_mm_cvtsi32_si128(base_masked), shuf));

                    const auto& wheel = opt.wheels[M];
                    const size_t sz = wheel.size();
                    const __m128i* vecs = reinterpret_cast<const __m128i*>(ctx.stream.word_vecs.data());
                    size_t idx = 0;
                    for (; idx + 1 < sz; idx += 2) {
                        const uint16_t ea = wheel[idx], eb = wheel[idx + 1];
                        const bool ok_a = last_ok(ea);
                        const bool ok_b = last_ok(eb);
                        if (!ok_a && !ok_b) continue;
                        const __m128i MA = _mm_or_si128(BASE_TOTAL, vecs[idx]);
                        const __m128i MB = _mm_or_si128(BASE_TOTAL, vecs[idx + 1]);
                        uint8_t ha, hb;
                        if (in_msg1) {
                            cryptowords::detail::sha256_bip39_msg1_variable_shani_x2(
                                S0, S1, MSG0, MSG2, MSG3, ABEF_SAVE, MA, MB, ha, hb);
                        } else {
                            cryptowords::detail::sha256_bip39_msg0_variable_shani_x2(
                                MSG1, MSG2, MSG3, MA, MB, ha, hb);
                        }
                        const uint16_t sa = ea | (ha >> cs_shift);
                        const uint16_t sb = eb | (hb >> cs_shift);
                        if (ok_a && opt.allowed_last_words.test(sa) && !is_dup(sa))
                            cur.k_last_w_list[cur.k_last_w_count++] = sa;
                        if (ok_b && opt.allowed_last_words.test(sb) && !is_dup(sb))
                            cur.k_last_w_list[cur.k_last_w_count++] = sb;
                    }
                    if (idx < sz) {
                        const uint16_t ea = wheel[idx];
                        if (last_ok(ea)) {
                            const __m128i MA = _mm_or_si128(BASE_TOTAL, vecs[idx]);
                            uint8_t ha;
                            if (in_msg1) {
                                ha = cryptowords::detail::sha256_bip39_msg1_variable_shani_reg(
                                    S0, S1, MSG0, MSG2, MSG3, ABEF_SAVE, MA);
                            } else {
                                ha = cryptowords::detail::sha256_bip39_msg0_variable_shani_reg(
                                    MSG1, MSG2, MSG3, MA);
                            }
                            const uint16_t sa = ea | (ha >> cs_shift);
                            if (opt.allowed_last_words.test(sa) && !is_dup(sa))
                                cur.k_last_w_list[cur.k_last_w_count++] = sa;
                        }
                    }
                } else {
                    for (uint16_t e_base : opt.wheels[M]) {
                        const uint32_t c = base_curr |
                            ((static_cast<uint32_t>(e_base & 0x7FF)) << shift);
                        cur.k_block64[byte_pos]     = static_cast<uint8_t>((c >> 16) & 0xFF);
                        cur.k_block64[byte_pos + 1] = static_cast<uint8_t>((c >> 8) & 0xFF);
                        cur.k_block64[byte_pos + 2] = static_cast<uint8_t>(c & 0xFF);
                        const uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(
                            cur.k_block64.data());
                        const uint16_t syn = e_base | (h >> cs_shift);
                        if (opt.allowed_last_words.test(syn) && !is_dup(syn) && last_ok(syn))
                            cur.k_last_w_list[cur.k_last_w_count++] = syn;
                    }
                }
#else
                (void)in_msg0; (void)in_msg1;
                for (uint16_t e_base : opt.wheels[M]) {
                    const uint32_t c = base_curr |
                        ((static_cast<uint32_t>(e_base & 0x7FF)) << shift);
                    cur.k_block64[byte_pos]     = static_cast<uint8_t>((c >> 16) & 0xFF);
                    cur.k_block64[byte_pos + 1] = static_cast<uint8_t>((c >> 8) & 0xFF);
                    cur.k_block64[byte_pos + 2] = static_cast<uint8_t>(c & 0xFF);
                    alignas(64) std::array<uint8_t, 32> hash{};
                    crypto::SHA256::hash(cur.k_block64.data(), opt.entropy_bytes, hash.data());
                    const uint16_t syn = e_base | (hash[0] >> cs_shift);
                    if (opt.allowed_last_words.test(syn) && !is_dup(syn) && last_ok(syn))
                        cur.k_last_w_list[cur.k_last_w_count++] = syn;
                }
#endif
            }
            // Expected: filtro por checksum fixo (última palavra conhecida).
            else {
#if defined(__SHA__)
                if (in_msg0 || in_msg1) {
                    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL,
                                                        0x0405060700010203ULL);
                    const __m128i ABEF_SAVE = _mm_set_epi32(0x6a09e667, 0xbb67ae85,
                                                            0x510e527f, 0x9b05688c);
                    __m128i S0 = ABEF_SAVE;
                    __m128i S1 = _mm_set_epi32(0x3c6ef372, 0xa54ff53a,
                                               0x1f83d9ab, 0x5be0cd19);
                    __m128i MSG0, MSG1, MSG2, MSG3;
                    if (in_msg1) {
                        MSG0 = _mm_shuffle_epi8(
                            _mm_loadu_si128((const __m128i*)(cur.k_block64.data() + 0)), MASK);
                        MSG2 = _mm_load_si128((const __m128i*)ctx.stream.msg2.data());
                        MSG3 = _mm_load_si128((const __m128i*)ctx.stream.msg3.data());
                        __m128i MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL,
                                                                         0x71374491428A2F98ULL));
                        S1 = _mm_sha256rnds2_epu32(S1, S0, MSG);
                        MSG = _mm_shuffle_epi32(MSG, 0x0E);
                        S0 = _mm_sha256rnds2_epu32(S0, S1, MSG);
                    } else {
                        MSG1 = _mm_shuffle_epi8(
                            _mm_loadu_si128((const __m128i*)(cur.k_block64.data() + 16)), MASK);
                        MSG2 = _mm_load_si128((const __m128i*)ctx.stream.msg2.data());
                        MSG3 = _mm_load_si128((const __m128i*)ctx.stream.msg3.data());
                    }
                    __m128i clear = _mm_load_si128((const __m128i*)ctx.stream.clear_mask.data());
                    __m128i base = _mm_loadu_si128(
                        (const __m128i*)(cur.k_block64.data() + (in_msg1 ? 16 : 0)));
                    __m128i base_cleared = _mm_shuffle_epi8(_mm_and_si128(base, clear), MASK);
                    __m128i shuf = _mm_load_si128((const __m128i*)ctx.stream.shuf_mask.data());
                    const uint32_t v32 = ((base_curr & 0xFF) << 16) |
                                         (base_curr & 0xFF00) |
                                         ((base_curr >> 16) & 0xFF);
                    const __m128i BASE_TOTAL = _mm_or_si128(
                        base_cleared,
                        _mm_shuffle_epi8(_mm_cvtsi32_si128(v32), shuf));

                    const auto& wheel = opt.wheels[M];
                    const size_t sz = wheel.size();
                    const __m128i* vecs = reinterpret_cast<const __m128i*>(ctx.stream.word_vecs.data());
                    size_t idx = 0;
                    for (; idx + 1 < sz; idx += 2) {
                        const uint16_t wa = wheel[idx], wb = wheel[idx + 1];
                        const bool ok_a = last_ok(wa);
                        const bool ok_b = last_ok(wb);
                        if (!ok_a && !ok_b) continue;
                        const __m128i MA = _mm_or_si128(BASE_TOTAL, vecs[idx]);
                        const __m128i MB = _mm_or_si128(BASE_TOTAL, vecs[idx + 1]);
                        uint8_t ha, hb;
                        if (in_msg1) {
                            cryptowords::detail::sha256_bip39_msg1_variable_shani_x2(
                                S0, S1, MSG0, MSG2, MSG3, ABEF_SAVE, MA, MB, ha, hb);
                        } else {
                            cryptowords::detail::sha256_bip39_msg0_variable_shani_x2(
                                MSG1, MSG2, MSG3, MA, MB, ha, hb);
                        }
                        if (ok_a && (ha >> cs_shift) == expected_cs && !is_dup(wa))
                            cur.k_last_w_list[cur.k_last_w_count++] = wa;
                        if (ok_b && (hb >> cs_shift) == expected_cs && !is_dup(wb))
                            cur.k_last_w_list[cur.k_last_w_count++] = wb;
                    }
                    if (idx < sz) {
                        const uint16_t wa = wheel[idx];
                        if (last_ok(wa)) {
                            const __m128i MA = _mm_or_si128(BASE_TOTAL, vecs[idx]);
                            uint8_t ha;
                            if (in_msg1) {
                                ha = cryptowords::detail::sha256_bip39_msg1_variable_shani_reg(
                                    S0, S1, MSG0, MSG2, MSG3, ABEF_SAVE, MA);
                            } else {
                                ha = cryptowords::detail::sha256_bip39_msg0_variable_shani_reg(
                                    MSG1, MSG2, MSG3, MA);
                            }
                            if ((ha >> cs_shift) == expected_cs && !is_dup(wa))
                                cur.k_last_w_list[cur.k_last_w_count++] = wa;
                        }
                    }
                } else {
                    for (uint16_t w_last : opt.wheels[M]) {
                        if (!last_ok(w_last)) continue;
                        const uint32_t c = base_curr |
                            ((static_cast<uint32_t>(w_last & 0x7FF)) << shift);
                        cur.k_block64[byte_pos]     = static_cast<uint8_t>((c >> 16) & 0xFF);
                        cur.k_block64[byte_pos + 1] = static_cast<uint8_t>((c >> 8) & 0xFF);
                        cur.k_block64[byte_pos + 2] = static_cast<uint8_t>(c & 0xFF);
                        const uint8_t h = cryptowords::detail::sha256_bip39_first_byte_shani(
                            cur.k_block64.data());
                        if ((h >> cs_shift) == expected_cs && !is_dup(w_last))
                            cur.k_last_w_list[cur.k_last_w_count++] = w_last;
                    }
                }
#else
                (void)in_msg0; (void)in_msg1;
                for (uint16_t w_last : opt.wheels[M]) {
                    if (!last_ok(w_last)) continue;
                    const uint32_t c = base_curr |
                        ((static_cast<uint32_t>(w_last & 0x7FF)) << shift);
                    cur.k_block64[byte_pos]     = static_cast<uint8_t>((c >> 16) & 0xFF);
                    cur.k_block64[byte_pos + 1] = static_cast<uint8_t>((c >> 8) & 0xFF);
                    cur.k_block64[byte_pos + 2] = static_cast<uint8_t>(c & 0xFF);
                    alignas(64) std::array<uint8_t, 32> hash{};
                    crypto::SHA256::hash(cur.k_block64.data(), opt.entropy_bytes, hash.data());
                    if ((hash[0] >> cs_shift) == expected_cs && !is_dup(w_last))
                        cur.k_last_w_list[cur.k_last_w_count++] = w_last;
                }
#endif
            }

            // Contabiliza rejeições deste outer state.
            if (opt.count_eliminations) {
                const size_t attempts = (required_last >= 0) ? 1 : opt.wheels[M].size();
                if (cur.k_last_w_count < attempts)
                    ctx.counters.local_eliminated += (attempts - cur.k_last_w_count);
            }

            if (cur.k_last_w_count > 0) {
                cur.current_ids[last_idx] = cur.k_last_w_list[cur.k_last_w_idx++];
                return true;
            }
        }
    }

   public:
    void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                    size_t num_threads, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        cur.thread_idx = thread_idx;
        cur.step_size  = num_threads;
        cur.done       = false;
        cur.current_ids = opt.base_mnemonic;

        const size_t M = opt.unknown_positions.size() - 1;
        cur.outer_state.assign(M, 0);

        // Decodifica thread_idx na ordem inversa (state[M-1] = dígito menos
        // significativo) — consistente com linear_position() e seek_linear().
        size_t temp = thread_idx;
        for (int i = static_cast<int>(M) - 1; i >= 0; --i) {
            const size_t w = opt.wheels[i].size();
            if (w == 0) { cur.done = true; return; }
            cur.outer_state[i] = temp % w;
            temp /= w;
        }
        if (temp > 0) { cur.done = true; return; }

        std::memcpy(cur.k_block64.data(), opt.base_block64.data(), 64);
        cur.k_last_w_count = 0;
        cur.k_last_w_idx   = 0;

        setup_word_vecs(ctx, opt);
        if (!refill(cur, ctx, opt, true)) cur.done = true;

        if (!cur.done && !opt.repeat_ids_empty_) {
            while (!satisfies_repeat_constraints(cur, opt))
                if (!advance(ctx, opt)) { cur.done = true; return; }
        }
    }

    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        if (cur.done) return false;
        if (cur.k_last_w_idx < cur.k_last_w_count) {
            cur.current_ids[opt.unknown_positions.back()] =
                cur.k_last_w_list[cur.k_last_w_idx++];
            return true;
        }
        return refill(cur, ctx, opt, false);
    }

    uint64_t linear_position(const PipelineThreadContext& ctx,
                             const OptimizedMnemonics& opt) const override {
        const auto& cur = ctx.cursor;
        const size_t M = opt.unknown_positions.size() - 1;
        uint64_t idx = 0;
        for (size_t i = 0; i < M; ++i)
            idx = idx * opt.wheels[i].size() + cur.outer_state[i];
        return idx;
    }

    void seek_linear(PipelineThreadContext& ctx, const OptimizedMnemonics& opt,
                     uint64_t idx) override {
        auto& cur = ctx.cursor;
        if (idx >= total_space(opt)) { cur.done = true; return; }

        const size_t M = opt.unknown_positions.size() - 1;
        cur.outer_state.assign(M, 0);
        uint64_t tmp = idx;
        for (int i = static_cast<int>(M) - 1; i >= 0; --i) {
            const size_t sz = opt.wheels[i].size();
            cur.outer_state[i] = tmp % sz;
            tmp /= sz;
        }
        std::memcpy(cur.k_block64.data(), opt.base_block64.data(), 64);
        cur.k_last_w_count = 0;
        cur.k_last_w_idx   = 0;

        setup_word_vecs(ctx, opt);
        (void)refill(cur, ctx, opt, true);
    }

    uint64_t total_space(const OptimizedMnemonics& opt) const override {
        const size_t M = opt.unknown_positions.size() - 1;
        uint64_t prod = 1;
        for (size_t i = 0; i < M; ++i) prod *= opt.wheels[i].size();
        return prod;
    }
};

// =========================================================================
// IndexedListOdometer — reservado para Pairs/Triplets pré-computados.
// =========================================================================
class IndexedListOdometer final : public IOdometer {
   public:
    void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                    size_t num_threads, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        cur.thread_idx = thread_idx;
        cur.step_size  = num_threads;
        cur.done       = false;
        cur.current_ids = opt.base_mnemonic;

        if (opt.is_triplets() || opt.is_pairs()) {
            const size_t total = opt.is_triplets() ? opt.valid_triplets.size()
                                                   : opt.valid_pairs.size();
            const size_t chunk = (total + num_threads - 1) / num_threads;
            const size_t start = thread_idx * chunk;
            const size_t end   = std::min(start + chunk, total);
            if (opt.is_triplets()) { cur.triplet_idx = start; cur.triplet_end = end; }
            else                   { cur.pair_idx = start;    cur.pair_end = end; }
            if (start >= end) { cur.done = true; return; }

            if (opt.is_triplets()) {
                cur.current_ids[opt.unknown_positions[0]] = opt.valid_triplets[start].w0;
                cur.current_ids[opt.unknown_positions[1]] = opt.valid_triplets[start].w1;
                cur.current_ids[opt.unknown_positions[2]] = opt.valid_triplets[start].w2;
            } else {
                cur.current_ids[opt.unknown_positions[0]] = opt.valid_pairs[start].first;
                cur.current_ids[opt.unknown_positions[1]] = opt.valid_pairs[start].second;
            }
        } else {
            cur.done = true;
        }
    }

    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override {
        auto& cur = ctx.cursor;
        if (cur.done) return false;

        if (opt.is_triplets()) {
            ++cur.triplet_idx;
            if (cur.triplet_idx >= cur.triplet_end) { cur.done = true; return false; }
            cur.current_ids[opt.unknown_positions[0]] = opt.valid_triplets[cur.triplet_idx].w0;
            cur.current_ids[opt.unknown_positions[1]] = opt.valid_triplets[cur.triplet_idx].w1;
            cur.current_ids[opt.unknown_positions[2]] = opt.valid_triplets[cur.triplet_idx].w2;
            return true;
        }
        if (opt.is_pairs()) {
            ++cur.pair_idx;
            if (cur.pair_idx >= cur.pair_end) { cur.done = true; return false; }
            cur.current_ids[opt.unknown_positions[0]] = opt.valid_pairs[cur.pair_idx].first;
            cur.current_ids[opt.unknown_positions[1]] = opt.valid_pairs[cur.pair_idx].second;
            return true;
        }
        return false;
    }

    uint64_t linear_position(const PipelineThreadContext& ctx,
                             const OptimizedMnemonics& opt) const override {
        const auto& cur = ctx.cursor;
        if (opt.is_triplets()) return cur.triplet_idx;
        if (opt.is_pairs())    return cur.pair_idx;
        return 0;
    }

    void seek_linear(PipelineThreadContext& ctx, const OptimizedMnemonics& opt,
                     uint64_t idx) override {
        auto& cur = ctx.cursor;
        if (opt.is_triplets()) {
            if (idx >= opt.valid_triplets.size()) { cur.done = true; return; }
            cur.triplet_idx = idx;
            cur.triplet_end = opt.valid_triplets.size();
            cur.current_ids[opt.unknown_positions[0]] = opt.valid_triplets[idx].w0;
            cur.current_ids[opt.unknown_positions[1]] = opt.valid_triplets[idx].w1;
            cur.current_ids[opt.unknown_positions[2]] = opt.valid_triplets[idx].w2;
            return;
        }
        if (opt.is_pairs()) {
            if (idx >= opt.valid_pairs.size()) { cur.done = true; return; }
            cur.pair_idx = idx;
            cur.pair_end = opt.valid_pairs.size();
            cur.current_ids[opt.unknown_positions[0]] = opt.valid_pairs[idx].first;
            cur.current_ids[opt.unknown_positions[1]] = opt.valid_pairs[idx].second;
            return;
        }
        cur.done = true;
    }

    uint64_t total_space(const OptimizedMnemonics& opt) const override {
        if (opt.is_triplets()) return opt.valid_triplets.size();
        if (opt.is_pairs())    return opt.valid_pairs.size();
        return 0;
    }
};

}  // namespace

std::unique_ptr<IOdometer> make_odometer(const OptimizedMnemonics& opt) {
    // Em modo random, o espaço é enumerado em Mixed permutado. Streaming
    // e listas pré-computadas caem no caminho permutado (Mixed + filtro
    // runtime).
    if (opt.random) {
        uint64_t total = 1;
        for (const auto& w : opt.wheels) total *= w.size();
        return std::make_unique<RandomMixedOdometer>(total, opt.random_seed);
    }

    switch (opt.mode) {
        case SearchMode::Streaming: return std::make_unique<StreamingOdometer>();
        case SearchMode::Pairs:     return std::make_unique<IndexedListOdometer>();
        case SearchMode::Triplets:  return std::make_unique<IndexedListOdometer>();
        case SearchMode::Mixed:     return std::make_unique<MixedOdometer>();
    }
    return std::make_unique<MixedOdometer>();
}

}  // namespace cryptowords


//0800 400 4673
