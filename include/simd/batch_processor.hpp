#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "../config.hpp"
#include "../crypto/bip39.hpp"
#include "../crypto/hmac_sha512.hpp"
#include "../crypto/pbkdf2_simd.hpp"
#include "../crypto/sha256.hpp"
#include "../crypto/sha256_shani.hpp"
#include "../crypto/cuckoo_filter.hpp"
#include "../search/checkpoint.hpp"
#include "../search/context.hpp"
#include "../search/plan.hpp"
#include "../search/processor.hpp"
#include "arch.hpp"
#include "cpu_features.hpp"

namespace cryptowords {

// =========================================================================
// FASE 4 — Motor de avaliação de candidatos.
//
// Recebe candidatos do odômetro, aplica o filtro de checksum (se houver),
// roda PBKDF2 SIMD no lote sobrevivente, deriva endereço e compara com o
// alvo. `Mode` é um parâmetro de template — o filtro não tem branch runtime.
//
// Fluxo por lote:
//   checksum_batch (C_BATCH_SIZE candidatos) → SHA-256 vetorizado
//       → [rejeitados: ++local_eliminated]
//       → [aprovados: pbkdf2_batch]
//   pbkdf2_batch (BATCH_SIZE candidatos) → PBKDF2 → verificação → reset
// =========================================================================
template <SimdArch Arch, ChecksumMode Mode>
class SimdBatchProcessor : public IBatchProcessor {
    static constexpr size_t BATCH_SIZE   = ArchTraits<Arch>::BATCH_SIZE;
    static constexpr size_t C_BATCH_SIZE = ArchTraits<Arch>::C_BATCH_SIZE;
    static constexpr size_t MAX_WORDS    = MAX_WORDS_PER_MNEMONIC;
    static constexpr bool   UsesFilter   = (Mode != ChecksumMode::None);

    static_assert(BATCH_SIZE <= CandidateBatch::MAX_LANES);
    static_assert(C_BATCH_SIZE <= CandidateBatch::MAX_LANES);
    static_assert(MAX_WORDS >= 24);

    // Working set do PBKDF2 — alocado em stack, vive só durante
    // flush_valid_batch. Sem custo de RAM persistente.
    struct Pbkdf2Work {
        alignas(64) std::array<char, BATCH_SIZE * PW_SLOT_SIZE> pw;
        alignas(64) std::array<uint8_t, BATCH_SIZE * 64> seed;
        std::array<size_t, BATCH_SIZE> pw_len{};
    };

    // ---------------------------------------------------------------------
    // Filtro de checksum. Função pura; a decisão vive em `Mode`.
    // ---------------------------------------------------------------------
    static bool checksum_admits(const OptimizedMnemonics& opt,
                                uint16_t cand_last_word,
                                uint8_t hash_value,
                                uint16_t& syn_out) noexcept {
        switch (Mode) {
            case ChecksumMode::None:
                return true;
            case ChecksumMode::Expected:
                return opt.expected_checksum == hash_value;
            case ChecksumMode::AutoDeduce:
                syn_out = static_cast<uint16_t>(cand_last_word | hash_value);
                return opt.allowed_last_words.test(syn_out);
            case ChecksumMode::UserPattern:
                return opt.allowed_checksum_bits.test(hash_value);
            case ChecksumMode::SelfVerify: {
                const uint16_t stated = static_cast<uint16_t>(
                    cand_last_word & ((1u << opt.checksum_bits) - 1));
                return stated == hash_value;
            }
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // Montagem de frase em work.pw (uma entrada por lane).
    // ---------------------------------------------------------------------
    static void assemble_phrases(Pbkdf2Work& work,
                                 const CandidateBatch& pb,
                                 const OptimizedMnemonics& opt) noexcept {
        const char* const __restrict sb = opt.phrase_static.data();
        const PhraseSegment* const __restrict segs = opt.phrase_segments.data();
        const size_t n_segs  = opt.phrase_n_segments;
        const size_t n_batch = pb.size;

        const char* const __restrict wblob = opt.word_buf[0].data();
        const uint16_t* const __restrict wlen = opt.word_len16.data();

        size_t start_seg = 0;
        size_t prefix_len = 0;
        if (n_segs > 0 && segs[0].word_idx == 0xFFFF) {
            const char* const src = sb + segs[0].static_off;
            const size_t len = segs[0].static_len;
            for (size_t b = 0; b < n_batch; ++b)
                std::memcpy(work.pw.data() + b * PW_SLOT_SIZE, src, len);
            start_seg = 1;
            prefix_len = len;
        }

        for (size_t b = 0; b < n_batch; ++b) {
            char* __restrict p = work.pw.data() + b * PW_SLOT_SIZE + prefix_len;
            char* const base = work.pw.data() + b * PW_SLOT_SIZE;
            const uint16_t* const __restrict ids = pb.ids.data() + b * MAX_WORDS;

            for (size_t s = start_seg; s < n_segs; ++s) {
                const PhraseSegment seg = segs[s];
                if (seg.word_idx != 0xFFFF) {
                    const uint16_t wid = ids[seg.word_idx];
                    std::memcpy(p, wblob + static_cast<size_t>(wid) * 16, 16);
                    p += wlen[wid];
                }
                if (seg.static_len) {
                    std::memcpy(p, sb + seg.static_off, seg.static_len);
                    p += seg.static_len;
                }
            }
            work.pw_len[b] = static_cast<size_t>(p - base);
        }
    }

    // ---------------------------------------------------------------------
    // PBKDF2 SIMD. Dispatch por template (Arch é constexpr).
    // ---------------------------------------------------------------------
    static void run_pbkdf2(Pbkdf2Work& work, const SaltCache& salt,
                           uint32_t rounds, size_t count, bool is_flush) noexcept {
        if (count == BATCH_SIZE) {
            if constexpr (Arch == SimdArch::AVX512) {
                pbkdf2_hmac_sha512_16way_avx512(
                    work.pw.data() +  0 * PW_SLOT_SIZE, work.pw_len[ 0],
                    work.pw.data() +  1 * PW_SLOT_SIZE, work.pw_len[ 1],
                    work.pw.data() +  2 * PW_SLOT_SIZE, work.pw_len[ 2],
                    work.pw.data() +  3 * PW_SLOT_SIZE, work.pw_len[ 3],
                    work.pw.data() +  4 * PW_SLOT_SIZE, work.pw_len[ 4],
                    work.pw.data() +  5 * PW_SLOT_SIZE, work.pw_len[ 5],
                    work.pw.data() +  6 * PW_SLOT_SIZE, work.pw_len[ 6],
                    work.pw.data() +  7 * PW_SLOT_SIZE, work.pw_len[ 7],
                    work.pw.data() +  8 * PW_SLOT_SIZE, work.pw_len[ 8],
                    work.pw.data() +  9 * PW_SLOT_SIZE, work.pw_len[ 9],
                    work.pw.data() + 10 * PW_SLOT_SIZE, work.pw_len[10],
                    work.pw.data() + 11 * PW_SLOT_SIZE, work.pw_len[11],
                    work.pw.data() + 12 * PW_SLOT_SIZE, work.pw_len[12],
                    work.pw.data() + 13 * PW_SLOT_SIZE, work.pw_len[13],
                    work.pw.data() + 14 * PW_SLOT_SIZE, work.pw_len[14],
                    work.pw.data() + 15 * PW_SLOT_SIZE, work.pw_len[15],
                    salt.buf.data(), salt.len, rounds,
                    work.seed.data() +  0 * 64, work.seed.data() +  1 * 64,
                    work.seed.data() +  2 * 64, work.seed.data() +  3 * 64,
                    work.seed.data() +  4 * 64, work.seed.data() +  5 * 64,
                    work.seed.data() +  6 * 64, work.seed.data() +  7 * 64,
                    work.seed.data() +  8 * 64, work.seed.data() +  9 * 64,
                    work.seed.data() + 10 * 64, work.seed.data() + 11 * 64,
                    work.seed.data() + 12 * 64, work.seed.data() + 13 * 64,
                    work.seed.data() + 14 * 64, work.seed.data() + 15 * 64,
                    salt.block64.data(), salt.kw_salt.data(), salt.kw_salt_avx512.data());
            } else if constexpr (Arch == SimdArch::AVX2) {
                pbkdf2_hmac_sha512_8way_avx2(
                    work.pw.data() + 0 * PW_SLOT_SIZE, work.pw_len[0],
                    work.pw.data() + 1 * PW_SLOT_SIZE, work.pw_len[1],
                    work.pw.data() + 2 * PW_SLOT_SIZE, work.pw_len[2],
                    work.pw.data() + 3 * PW_SLOT_SIZE, work.pw_len[3],
                    work.pw.data() + 4 * PW_SLOT_SIZE, work.pw_len[4],
                    work.pw.data() + 5 * PW_SLOT_SIZE, work.pw_len[5],
                    work.pw.data() + 6 * PW_SLOT_SIZE, work.pw_len[6],
                    work.pw.data() + 7 * PW_SLOT_SIZE, work.pw_len[7],
                    salt.buf.data(), salt.len, rounds,
                    work.seed.data() + 0 * 64, work.seed.data() + 1 * 64,
                    work.seed.data() + 2 * 64, work.seed.data() + 3 * 64,
                    work.seed.data() + 4 * 64, work.seed.data() + 5 * 64,
                    work.seed.data() + 6 * 64, work.seed.data() + 7 * 64,
                    salt.block64.data(), salt.kw_salt.data(), salt.kw_salt_avx2.data());
            } else {
                pbkdf2_hmac_sha512_4way_sse(
                    work.pw.data() + 0 * PW_SLOT_SIZE, work.pw_len[0],
                    work.pw.data() + 1 * PW_SLOT_SIZE, work.pw_len[1],
                    work.pw.data() + 2 * PW_SLOT_SIZE, work.pw_len[2],
                    work.pw.data() + 3 * PW_SLOT_SIZE, work.pw_len[3],
                    salt.buf.data(), salt.len, rounds,
                    work.seed.data() + 0 * 64, work.seed.data() + 1 * 64,
                    work.seed.data() + 2 * 64, work.seed.data() + 3 * 64,
                    salt.block64.data(), salt.kw_salt.data(), salt.kw_salt_sse.data());
            }
        } else if (is_flush) {
            // Sobra do último lote — PBKDF2 escalar item por item.
            for (size_t b = 0; b < count; ++b)
                crypto::pbkdf2_hmac_sha512(work.pw.data() + b * PW_SLOT_SIZE,
                                           work.pw_len[b],
                                           salt.buf.data(), salt.len, rounds,
                                           work.seed.data() + b * 64, 64);
        }
    }

    // Verificação do alvo.
    //
    // 3 caminhos:
    //   1. GPU (HIP) para ETH — delega ao engine pós-PBKDF2 (1 alvo).
    //   2. CPU, 1 alvo    — fast path com rejeição de 64 bits.
    //   3. CPU, N alvos   — deriva 20 B, prefiltra com cuckoo (se N ≥ 8),
    //                        compara contra cada target.
    static void verify_targets(Pbkdf2Work& work, const CandidateBatch& pb,
                               PipelineThreadContext& ctx,
                               const AppConfig& cfg, const OptimizedMnemonics& opt,
                               std::atomic<bool>& found, std::mutex& result_mutex,
                               bool& success, std::vector<uint16_t>& result_mnemonic) {
        const size_t n = pb.size;
        const size_t mnemonic_len = opt.base_mnemonic.size();

        // ---- Caminho GPU ----
        const bool gpu_ok = (ctx.gpu.engine != nullptr) &&
                            (cfg.coin == CoinTarget::ETH) &&
                            (cfg.targets.size() <= 1);
        if (gpu_ok) {
            const uint32_t widx = ctx.gpu.write_idx;
            auto& seeds = ctx.gpu.seeds[widx];
            auto& mnems = ctx.gpu.mnems[widx];
            auto& count = ctx.gpu.count[widx];

            for (size_t b = 0; b < n; ++b) {
                std::memcpy(seeds.data() + count * 64, work.seed.data() + b * 64, 64);
                std::memcpy(mnems.data() + count * MAX_WORDS,
                            pb.ids.data() + b * MAX_WORDS,
                            MAX_WORDS * sizeof(uint16_t));
                ++count;
                if (count == GPU_POST_BATCH)
                    flush_gpu(ctx, opt, found, result_mutex, success, result_mnemonic);
            }
            return;
        }

        // ---- Caminho CPU, 1 alvo ----
        if (cfg.targets.size() <= 1) {
            for (size_t b = 0; b < n; ++b) {
                const bool hit = (cfg.coin == CoinTarget::BTC)
                    ? Bip39Deriver::check_btc_target_from_seed(
                          work.seed.data() + b * 64, ctx.decoded_target.data(),
                          opt.target_fast_hash64)
                    : Bip39Deriver::check_eth_target_from_seed(
                          work.seed.data() + b * 64, ctx.decoded_target.data(),
                          opt.target_fast_hash64);
                if (!hit) continue;

                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    success = true;
                    result_mnemonic.assign(pb.ids.data() + b * MAX_WORDS,
                                           pb.ids.data() + b * MAX_WORDS + mnemonic_len);
                }
            }
            return;
        }

        // ---- Caminho CPU, N alvos ----
        const CuckooFilter* cuckoo = cfg.target_cuckoo.get();
        std::array<uint8_t, 20> addr{};
        const bool is_btc = (cfg.coin == CoinTarget::BTC);

        for (size_t b = 0; b < n; ++b) {
            const uint8_t* seed = work.seed.data() + b * 64;
            const bool derived = is_btc
                ? Bip39Deriver::derive_btc_address_bytes(seed, addr.data())
                : Bip39Deriver::derive_eth_address_bytes(seed, addr.data());
            if (!derived) continue;

            // Prefiltro probabilístico (só vale a pena em N ≥ 8).
            if (cuckoo) {
                const uint64_t h = CuckooFilter::hash_key(addr);
                if (!cuckoo->might_contain(h)) continue;
            }

            // Comparação exata contra cada alvo.
            for (const auto& t : cfg.targets) {
                if (std::memcmp(addr.data(), t.data(), 20) != 0) continue;

                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    success = true;
                    result_mnemonic.assign(pb.ids.data() + b * MAX_WORDS,
                                           pb.ids.data() + b * MAX_WORDS + mnemonic_len);
                }
                break;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Preparação do bloco BIP-39 para SHA-256 (K=1..N candidatos).
    // ---------------------------------------------------------------------
    static void setup_filter_block(std::array<uint8_t, 64>& block,
                                   const CandidateBatch& cb, size_t b,
                                   const OptimizedMnemonics& opt) noexcept {
        std::memcpy(block.data(), opt.base_block64.data(), 64);
        const uint16_t* ids = cb.ids.data() + b * MAX_WORDS;
        for (size_t k = 0; k < opt.unknown_positions.size(); ++k)
            detail::set_11bits(block.data(), opt.unknown_bit_offsets[k],
                               ids[opt.unknown_positions[k]]);
        block[opt.entropy_bytes] = 0x80;
    }

    // Adiciona um candidato aprovado ao pbkdf2_batch. AutoDeduce escreve
    // a palavra sintetizada de volta no último slot.
    static void admit_candidate(PipelineThreadContext& ctx,
                                const OptimizedMnemonics& opt,
                                size_t b, uint8_t hash_first_byte) {
        const uint8_t hash_value = static_cast<uint8_t>(
            hash_first_byte >> (8 - opt.checksum_bits));

        const size_t mnemonic_len = opt.base_mnemonic.size();
        const uint16_t last_word =
            ctx.checksum_batch.ids[b * MAX_WORDS + mnemonic_len - 1];

        uint16_t syn = 0;
        if (!checksum_admits(opt, last_word, hash_value, syn)) {
            ++ctx.counters.local_eliminated;
            return;
        }

        auto& pb = ctx.pbkdf2_batch;
        std::memcpy(pb.ids.data() + pb.size * MAX_WORDS,
                    ctx.checksum_batch.ids.data() + b * MAX_WORDS,
                    mnemonic_len * sizeof(uint16_t));
        if constexpr (Mode == ChecksumMode::AutoDeduce)
            pb.ids[pb.size * MAX_WORDS + mnemonic_len - 1] = syn;
        ++pb.size;
    }

    // ---------------------------------------------------------------------
    // Pipeline do lote de checksum: SHA-256 vetorizado → admit_candidate.
    // ---------------------------------------------------------------------
    static void flush_filter_batch(PipelineThreadContext& ctx,
                                   const AppConfig& cfg, const OptimizedMnemonics& opt,
                                   std::atomic<bool>& found,
                                   std::atomic<uint64_t>& tested_count,
                                   std::atomic<uint64_t>& valid_count,
                                   std::mutex& result_mutex, bool& success,
                                   std::vector<uint16_t>& result_mnemonic,
                                   bool is_flush) {
        if constexpr (!UsesFilter) {
            (void)ctx; (void)cfg; (void)opt; (void)found; (void)tested_count;
            (void)valid_count; (void)result_mutex; (void)success;
            (void)result_mnemonic; (void)is_flush;
            return;
        }

        auto& cb = ctx.checksum_batch;
        if (cb.size == 0) return;
        if (found.load(std::memory_order_relaxed)) { cb.size = 0; return; }

        const size_t mnemonic_len  = opt.base_mnemonic.size();
        const size_t checksum_bits = opt.checksum_bits;

        auto process_one = [&](size_t b, uint8_t h) {
            admit_candidate(ctx, opt, b, h);
            if (ctx.pbkdf2_batch.size == BATCH_SIZE)
                flush_valid_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                  result_mutex, success, result_mnemonic, false);
        };

        if (cb.size == C_BATCH_SIZE) {
#if defined(CRYPTOWORDS_HAS_SHANI_INTRINSICS)
            if (cpu::has_sha_ni()) {
                for (size_t b = 0; b < C_BATCH_SIZE; ++b) {
                    alignas(64) std::array<uint8_t, 64> block;
                    setup_filter_block(block, cb, b, opt);
                    const uint8_t h = detail::sha256_bip39_first_byte_shani(block.data());
                    process_one(b, h);
                    if (found.load(std::memory_order_relaxed)) { cb.size = 0; return; }
                }
                cb.size = 0;
                return;
            }
#endif
            // Fallback vetorial (compilado por Arch).
            if constexpr (Arch == SimdArch::AVX512) {
                SHA256_AVX512_State s1, s2;
                sha256_init_avx512(&s1);
                sha256_init_avx512(&s2);
                alignas(64) uint32_t blocks1[16][16]{};
                alignas(64) uint32_t blocks2[16][16]{};
                for (int b = 0; b < 32; ++b) {
                    alignas(64) std::array<uint8_t, 64> block;
                    setup_filter_block(block, cb, b, opt);
                    const uint32_t* W = reinterpret_cast<const uint32_t*>(block.data());
                    for (int w = 0; w < 16; ++w) {
                        if (b < 16) blocks1[w][b]      = __builtin_bswap32(W[w]);
                        else        blocks2[w][b - 16] = __builtin_bswap32(W[w]);
                    }
                }
                sha256_transform_avx512(&s1, blocks1);
                sha256_transform_avx512(&s2, blocks2);
                for (int b = 0; b < 32; ++b) {
                    const uint8_t h = (b < 16) ? static_cast<uint8_t>(s1.state[0][b] >> 24)
                                               : static_cast<uint8_t>(s2.state[0][b - 16] >> 24);
                    process_one(b, h);
                }
            } else if constexpr (Arch == SimdArch::AVX2) {
                SHA256_AVX2_State s1, s2;
                sha256_init_avx2(&s1);
                sha256_init_avx2(&s2);
                alignas(64) uint32_t blocks1[16][8]{};
                alignas(64) uint32_t blocks2[16][8]{};
                for (int b = 0; b < 16; ++b) {
                    alignas(64) std::array<uint8_t, 64> block;
                    setup_filter_block(block, cb, b, opt);
                    const uint32_t* W = reinterpret_cast<const uint32_t*>(block.data());
                    for (int w = 0; w < 16; ++w) {
                        if (b < 8) blocks1[w][b]     = __builtin_bswap32(W[w]);
                        else       blocks2[w][b - 8] = __builtin_bswap32(W[w]);
                    }
                }
                sha256_transform_avx2(&s1, blocks1);
                sha256_transform_avx2(&s2, blocks2);
                for (int b = 0; b < 16; ++b) {
                    const uint8_t h = (b < 8) ? static_cast<uint8_t>(s1.state[0][b] >> 24)
                                              : static_cast<uint8_t>(s2.state[0][b - 8] >> 24);
                    process_one(b, h);
                }
            } else {
                SHA256_SSE_State s1, s2;
                sha256_init_sse(&s1);
                sha256_init_sse(&s2);
                alignas(64) std::array<std::array<uint32_t, 4>, 16> blocks1{};
                alignas(64) std::array<std::array<uint32_t, 4>, 16> blocks2{};
                for (int b = 0; b < 8; ++b) {
                    alignas(64) std::array<uint8_t, 64> block;
                    setup_filter_block(block, cb, b, opt);
                    const uint32_t* W = reinterpret_cast<const uint32_t*>(block.data());
                    for (int w = 0; w < 16; ++w) {
                        if (b < 4) blocks1[w][b]     = __builtin_bswap32(W[w]);
                        else       blocks2[w][b - 4] = __builtin_bswap32(W[w]);
                    }
                }
                sha256_transform_sse(&s1, blocks1);
                sha256_transform_sse(&s2, blocks2);
                for (int b = 0; b < 8; ++b) {
                    const uint8_t h = (b < 4) ? static_cast<uint8_t>(s1.state[0][b] >> 24)
                                              : static_cast<uint8_t>(s2.state[0][b - 4] >> 24);
                    process_one(b, h);
                }
            }
            cb.size = 0;
        } else if (is_flush) {
            for (size_t b = 0; b < cb.size; ++b) {
                alignas(64) std::array<uint8_t, 64> block;
                setup_filter_block(block, cb, b, opt);
                alignas(64) std::array<uint8_t, 32> hash;
                crypto::SHA256::hash(block.data(), opt.entropy_bytes, hash.data());
                process_one(b, hash[0]);
            }
            cb.size = 0;
        }
        (void)mnemonic_len;
        (void)checksum_bits;
    }

    // ---------------------------------------------------------------------
    // Pipeline do lote PBKDF2: assemble → pbkdf2 → verify → bump.
    // ---------------------------------------------------------------------
    static void flush_valid_batch(PipelineThreadContext& ctx,
                                  const AppConfig& cfg, const OptimizedMnemonics& opt,
                                  std::atomic<bool>& found,
                                  std::atomic<uint64_t>& tested_count,
                                  std::atomic<uint64_t>& valid_count,
                                  std::mutex& result_mutex, bool& success,
                                  std::vector<uint16_t>& result_mnemonic,
                                  bool is_flush) {
        auto& pb = ctx.pbkdf2_batch;
        if (pb.size == 0) return;
        if (pb.size < BATCH_SIZE && !is_flush) return;

        // Working set vive só aqui.
        Pbkdf2Work work;
        assemble_phrases(work, pb, opt);
        run_pbkdf2(work, ctx.salt, cfg.pbkdf2_rounds, pb.size, is_flush);
        verify_targets(work, pb, ctx, cfg, opt, found, result_mutex,
                       success, result_mnemonic);

        auto& c = ctx.counters;
        c.local_tested += pb.size;
        c.local_valid  += pb.size;
        c.cumulative_tested += pb.size;
        c.cumulative_valid  += pb.size;
        if (c.local_tested >= 128) {
            tested_count.fetch_add(c.local_tested, std::memory_order_relaxed);
            c.local_tested = 0;
        }
        if (c.local_valid >= 128) {
            valid_count.fetch_add(c.local_valid, std::memory_order_relaxed);
            c.local_valid = 0;
        }
        pb.size = 0;
    }

    // ---------------------------------------------------------------------
    // GPU pós-PBKDF2 — ping-pong de 2 buffers.
    // ---------------------------------------------------------------------
    static void flush_gpu(PipelineThreadContext& ctx, const OptimizedMnemonics& opt,
                          std::atomic<bool>& found, std::mutex& result_mutex,
                          bool& success, std::vector<uint16_t>& result_mnemonic) {
        auto& g = ctx.gpu;
        if (!g.engine || !g.mutex) return;

        const uint32_t widx = g.write_idx;
        if (g.count[widx] == 0) return;

        std::lock_guard<std::mutex> lock(*g.mutex);
        const uint32_t ridx = 1u - widx;

        if (g.inflight[ridx]) {
            (void)g.engine->wait_batch(g.slot);
            const uint32_t hit = g.result[ridx];
            if (hit != 0xFFFFFFFFu && hit < g.count[ridx]) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> rlock(result_mutex);
                    success = true;
                    const uint16_t* base = g.mnems[ridx].data() + hit * MAX_WORDS;
                    result_mnemonic.assign(base, base + opt.base_mnemonic.size());
                }
            }
            g.inflight[ridx] = false;
            g.count[ridx]    = 0;
        }

        g.result[widx] = 0xFFFFFFFFu;
        const bool ok = g.engine->enqueue_post_pbkdf2(
            g.slot, g.seeds[widx], g.count[widx],
            ctx.decoded_target.data(), opt.target_fast_hash64, &g.result[widx]);
        if (ok) {
            g.inflight[widx] = true;
        } else {
            for (uint32_t k = 0; k < g.count[widx]; ++k) {
                const bool hit = Bip39Deriver::check_eth_target_from_seed(
                    g.seeds[widx].data() + k * 64, ctx.decoded_target.data(),
                    opt.target_fast_hash64);
                if (hit) {
                    bool expected = false;
                    if (found.compare_exchange_strong(expected, true)) {
                        std::lock_guard<std::mutex> rlock(result_mutex);
                        success = true;
                        const uint16_t* base = g.mnems[widx].data() + k * MAX_WORDS;
                        result_mnemonic.assign(base, base + opt.base_mnemonic.size());
                    }
                    break;
                }
            }
            g.count[widx] = 0;
        }
        g.write_idx = ridx;
    }

    static void drain_gpu(PipelineThreadContext& ctx, const OptimizedMnemonics& opt,
                          std::atomic<bool>& found, std::mutex& result_mutex,
                          bool& success, std::vector<uint16_t>& result_mnemonic) {
        auto& g = ctx.gpu;
        if (!g.engine || !g.mutex) return;
        std::lock_guard<std::mutex> lock(*g.mutex);
        for (uint32_t i = 0; i < 2; ++i) {
            if (!g.inflight[i]) continue;
            (void)g.engine->wait_batch(g.slot);
            const uint32_t hit = g.result[i];
            if (hit != 0xFFFFFFFFu && hit < g.count[i]) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> rlock(result_mutex);
                    success = true;
                    const uint16_t* base = g.mnems[i].data() + hit * MAX_WORDS;
                    result_mnemonic.assign(base, base + opt.base_mnemonic.size());
                }
            }
            g.inflight[i] = false;
            g.count[i]    = 0;
        }
    }

   public:
    void enqueue_and_process(PipelineThreadContext& ctx, const AppConfig& cfg,
                             const OptimizedMnemonics& opt,
                             std::atomic<bool>& found,
                             std::atomic<uint64_t>& tested_count,
                             std::atomic<uint64_t>& valid_count,
                             std::mutex& result_mutex, bool& success,
                             std::vector<uint16_t>& result_mnemonic) override {
        if (found.load(std::memory_order_relaxed)) return;

        // Cobertura (snapshots de execuções anteriores). Não conta como
        // eliminação de checksum.
        if (__builtin_expect(ctx.coverage_snapshots != nullptr &&
                             !ctx.coverage_snapshots->empty(), 0)) {
            if (covered_by_any(*ctx.coverage_snapshots, ctx.cursor.current_ids)) {
                ctx.cursor.last_candidate_accepted = false;
                return;
            }
        }
        ctx.cursor.last_candidate_accepted = true;

        const size_t mnemonic_len = opt.base_mnemonic.size();

        if constexpr (UsesFilter) {
            auto& cb = ctx.checksum_batch;
            std::memcpy(cb.ids.data() + cb.size * MAX_WORDS,
                        ctx.cursor.current_ids.data(),
                        mnemonic_len * sizeof(uint16_t));
            ++cb.size;
            if (cb.size == C_BATCH_SIZE)
                flush_filter_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                   result_mutex, success, result_mnemonic, false);
        } else {
            auto& pb = ctx.pbkdf2_batch;
            std::memcpy(pb.ids.data() + pb.size * MAX_WORDS,
                        ctx.cursor.current_ids.data(),
                        mnemonic_len * sizeof(uint16_t));
            ++pb.size;
            if (pb.size == BATCH_SIZE)
                flush_valid_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                  result_mutex, success, result_mnemonic, false);
        }
    }

    void flush(PipelineThreadContext& ctx, const AppConfig& cfg,
               const OptimizedMnemonics& opt,
               std::atomic<bool>& found,
               std::atomic<uint64_t>& tested_count,
               std::atomic<uint64_t>& valid_count,
               std::mutex& result_mutex, bool& success,
               std::vector<uint16_t>& result_mnemonic) override {
        if (!found.load(std::memory_order_relaxed)) {
            if constexpr (UsesFilter)
                flush_filter_batch(ctx, cfg, opt, found, tested_count, valid_count,
                                   result_mutex, success, result_mnemonic, true);
            flush_valid_batch(ctx, cfg, opt, found, tested_count, valid_count,
                              result_mutex, success, result_mnemonic, true);
        }

        if (ctx.gpu.engine && ctx.gpu.count[ctx.gpu.write_idx] > 0)
            flush_gpu(ctx, opt, found, result_mutex, success, result_mnemonic);
        drain_gpu(ctx, opt, found, result_mutex, success, result_mnemonic);

        auto& c = ctx.counters;
        if (c.local_tested > 0) {
            tested_count.fetch_add(c.local_tested, std::memory_order_relaxed);
            c.local_tested = 0;
        }
        if (c.local_valid > 0) {
            valid_count.fetch_add(c.local_valid, std::memory_order_relaxed);
            c.local_valid = 0;
        }
    }
};

}  // namespace cryptowords
