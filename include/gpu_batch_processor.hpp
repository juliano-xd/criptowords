#pragma once
#include "pipeline_builder.hpp"
#include "app_config.hpp"
#include "search_plan.hpp"
#include "crypto_impl.hpp"
#include "bip39.hpp"
#include "gpu_engine.hpp"
#include <atomic>
#include <mutex>

namespace cryptowords {

class GPUBatchProcessor : public IBatchProcessor {
    size_t batch_capacity_ = 0;

    struct GPUContext {
        std::vector<uint16_t> mnem_batch; // [batch_capacity_ * 24]
        std::vector<uint8_t> pw_batch;    // [batch_capacity_ * 128]
        std::vector<uint32_t> pw_lens;    // [batch_capacity_]
        std::vector<uint8_t> seed_out;    // [batch_capacity_ * 64]
        size_t current_count = 0;
    };

    thread_local static GPUContext gpu_ctx;

    void process_gpu_batch(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                           std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                           std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) {
        
        if (gpu_ctx.current_count == 0) return;
        
        GPUEngine& engine = GPUEngine::get_instance();
        
        // Dispara o monstro OpenCL!
        bool ok = engine.pbkdf2_batch(gpu_ctx.pw_batch, gpu_ctx.pw_lens, gpu_ctx.seed_out, gpu_ctx.current_count);
        if (!ok) {
            std::cerr << "Erro fatal na GPU! Abortando batch...\n";
            return;
        }

        // A GPU devolveu as Sementes prontas. 
        // A CPU faz a derivacao BIP32. Para evitar que 1 unica thread engargale a GPU, 
        // o proprio lote eh resolvido pelas 8 threads do Ryzen simultaneamente usando pragmas do OpenMP (se ativado).
        #pragma omp parallel for
        for (size_t b = 0; b < gpu_ctx.current_count; ++b) {
            if (found.load(std::memory_order_relaxed)) return;
            
            bool is_match = false;
            if (cfg.coin == CoinTarget::BTC) {
                is_match = Bip39Deriver::check_btc_target_from_seed(ctx.ctx, gpu_ctx.seed_out.data() + b*64, ctx.decoded_target);
            } else {
                is_match = Bip39Deriver::check_eth_target_from_seed(ctx.ctx, gpu_ctx.seed_out.data() + b*64, ctx.decoded_target);
            }

            if (is_match) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    success = true;
                    size_t mlen = opt.base_mnemonic.size();
                    result_mnemonic.assign(gpu_ctx.mnem_batch.begin() + b*24, gpu_ctx.mnem_batch.begin() + b*24 + mlen);
                }
                return;
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
        if (ctx.local_tested >= 4096) {
            tested_count += ctx.local_tested;
            valid_count += ctx.local_valid;
            ctx.local_valid = 0;
            ctx.local_tested = 0;
        }

        size_t mlen = opt.base_mnemonic.size();
        
        // No modo GPU, filtramos validade de checksum rapido na CPU antes de mandar pra placa
        if (cfg.only_valids) {
            if (opt.auto_deduce_last_word) {
                // ... Simplificacao, o checksum eh mais complexo ...
            } else {
                if (!cryptowords::Bip39Deriver::verify_checksum(ctx.current_ids)) return;
            }
        }

        // Se chegou aqui, a combinacao eh valida. Gera a string.
        if (batch_capacity_ == 0) batch_capacity_ = GPUEngine::get_instance().get_optimal_batch_size();
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
            std::string_view w = cfg.wordlist[ctx.current_ids[i]];
            memcpy(ptr, w.data(), w.size());
            ptr += w.size();
            if (i < mlen - 1) {
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

thread_local GPUBatchProcessor::GPUContext GPUBatchProcessor::gpu_ctx;

} // namespace cryptowords
