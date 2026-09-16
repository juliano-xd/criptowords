#pragma once
#include "../search/context.hpp"
#include "../search/plan.hpp"
#include "../search/processor.hpp"
#include "../crypto/bip39.hpp"
#include "gpu_engine.hpp"
#include <atomic>
#include <cstring>
#include <mutex>
#include <print>

namespace cryptowords {

class GPUBatchProcessor : public IBatchProcessor {
    size_t batch_capacity_ = 0;

public:
    GPUBatchProcessor() {
        batch_capacity_ = GPUEngine::get_instance().get_optimal_batch_size();
    }

    struct GPUContext {
        std::vector<uint16_t> mnem_batch; // [batch_capacity_ * 24]
        std::vector<uint8_t> pw_batch;    // [batch_capacity_ * 128]
        std::vector<uint32_t> pw_lens;    // [batch_capacity_]
        std::vector<uint8_t> seed_out;    // [batch_capacity_ * 64]
        size_t current_count = 0;
    };

    thread_local static GPUContext gpu_ctx;

    void process_gpu_batch(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                           std::atomic<bool>& found, std::atomic<uint64_t>& /*tested_count*/, std::atomic<uint64_t>& /*valid_count*/,
                           std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) {

        if (__builtin_expect(gpu_ctx.current_count == 0, 0)) return;

        GPUEngine& engine = GPUEngine::get_instance();

        bool ok = engine.pbkdf2_batch(gpu_ctx.pw_batch, gpu_ctx.pw_lens, gpu_ctx.seed_out, gpu_ctx.current_count);
        if (__builtin_expect(!ok, 0)) {
            std::println(stderr, "Erro fatal na GPU! Abortando batch...");
            return;
        }

        // A GPU devolveu as Sementes prontas.
        // A CPU faz a derivacao BIP32. Para evitar que 1 unica thread engargale a GPU,
        // o proprio lote eh resolvido pelas 8 threads do Ryzen simultaneamente usando pragmas do OpenMP (se ativado).
        uint8_t* base_seed_ptr = gpu_ctx.seed_out.data();
        uint16_t* base_mnem_ptr = gpu_ctx.mnem_batch.data();

        for (size_t b = 0; b < gpu_ctx.current_count; ++b) {
            if (found.load(std::memory_order_relaxed)) continue;


            bool is_match = false;
            if (cfg.coin == CoinTarget::BTC) {
                is_match = Bip39Deriver::check_btc_target_from_seed(ctx.ctx, base_seed_ptr + b*64, ctx.decoded_target, opt.target_fast_hash);
            } else {
                is_match = Bip39Deriver::check_eth_target_from_seed(ctx.ctx, base_seed_ptr + b*64, ctx.decoded_target, opt.target_fast_hash);
            }

            if (is_match) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    success = true;
                    size_t mlen = opt.base_mnemonic.size();
                    result_mnemonic.assign(base_mnem_ptr + b*24, base_mnem_ptr + b*24 + mlen);
                }

            }
        }

        ctx.local_valid += gpu_ctx.current_count;
        gpu_ctx.current_count = 0;
    }

public:
    void enqueue_and_process(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                             std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                             std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) override {

        ctx.local_tested++;
        if (ctx.local_tested >= 2048) {
            tested_count += ctx.local_tested;
            valid_count += ctx.local_valid;
            ctx.local_valid = 0;
            ctx.local_tested = 0;
        }

        size_t mlen = opt.base_mnemonic.size();

        // No modo GPU, filtramos validade de checksum rapido na CPU antes de mandar pra placa
        if (cfg.only_valids) {
            if (opt.auto_deduce_last_word) {
                bool found_valid = false;
                size_t num_last_words = size_t{1} << opt.checksum_bits;
                uint16_t base_word = ctx.current_ids[mlen - 1];
                for (size_t x = 0; x < num_last_words; ++x) {
                    uint16_t syn = base_word | x;
                    if (!opt.allowed_last_words[syn]) continue;
                    ctx.current_ids[mlen - 1] = syn;
                    if (cryptowords::Bip39Deriver::verify_checksum(std::span<const uint16_t>(ctx.current_ids.data(), mlen))) {
                        found_valid = true;
                        break;
                    }
                }
                if (!found_valid) {
                                        return;
                }
            } else {
                if (!cryptowords::Bip39Deriver::verify_checksum(std::span<const uint16_t>(ctx.current_ids.data(), mlen))) return;
            }
        }


        // Se chegou aqui, a combinacao eh valida. Gera a string.
        if (gpu_ctx.pw_batch.empty()) {
            gpu_ctx.mnem_batch.resize(batch_capacity_ * 24);
            gpu_ctx.pw_batch.resize(batch_capacity_ * 128);
            gpu_ctx.pw_lens.resize(batch_capacity_);
            gpu_ctx.seed_out.resize(batch_capacity_ * 64);
        }

        size_t b = gpu_ctx.current_count;
        std::copy(ctx.current_ids.begin(), ctx.current_ids.begin() + mlen, gpu_ctx.mnem_batch.begin() + b * 24);

        char* ptr = (char*)gpu_ctx.pw_batch.data() + b * 128;
        memcpy(ptr, opt.prefix_str.data(), opt.prefix_str.size());
        char* start_ptr = ptr;
        ptr += opt.prefix_str.size();

        for (size_t i = opt.prefix_words; i < mlen; ++i) {
            const std::string& w = cfg.wordlist[ctx.current_ids[i]];
            memcpy(ptr, w.data(), w.size());
            ptr += w.size();
            if (__builtin_expect(i + 1 < mlen, 1)) {
                memcpy(ptr, cfg.separator.data(), cfg.separator.size());
                ptr += cfg.separator.size();
            }
        }
        gpu_ctx.pw_lens[b] = ptr - start_ptr;

        gpu_ctx.current_count++;

        if (gpu_ctx.current_count == batch_capacity_) {
            process_gpu_batch(ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
        }
    }

    void flush(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
               std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
               std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) override {

        process_gpu_batch(ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic);

        if (ctx.local_tested > 0 || ctx.local_valid > 0) {
            tested_count += ctx.local_tested;
            valid_count += ctx.local_valid;
            ctx.local_tested = 0;
            ctx.local_valid = 0;
        }
    }
};

inline thread_local GPUBatchProcessor::GPUContext GPUBatchProcessor::gpu_ctx;

} // namespace cryptowords
