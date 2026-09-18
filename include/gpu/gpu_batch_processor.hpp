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
    size_t batch_capacity_ = 4096;
    size_t slot_size_ = 256;

public:
    explicit GPUBatchProcessor(const AppConfig& cfg) {
        size_t opt_batch = GPUEngine::get_instance().get_optimal_batch_size();
        batch_capacity_ = opt_batch;
        if (batch_capacity_ < 4096) batch_capacity_ = 4096;
        batch_capacity_ = ((batch_capacity_ + 255) / 256) * 256;

        slot_size_ = GPUEngine::get_instance().get_slot_size();
        if (slot_size_ == 0) {
            bool is_cjk = (cfg.language == "ja" || cfg.language == "japanese" ||
                           cfg.language == "ko" || cfg.language == "korean" ||
                           cfg.language.starts_with("zh") || cfg.language.starts_with("chinese") ||
                           cfg.separator == "\xE3\x80\x80");
            slot_size_ = (is_cjk || cfg.mnemonics.size() >= 21) ? 512 : (cfg.mnemonics.size() > 12 ? 256 : 128);
        }
    }

    struct GPUSlotData {
        std::vector<uint16_t> mnem_batch; // [batch_capacity_ * 24]
        std::vector<uint8_t> pw_batch;    // [batch_capacity_ * slot_size_]
        std::vector<uint32_t> pw_lens;    // [batch_capacity_]
        std::vector<uint8_t> seed_out;    // [batch_capacity_ * 64]
        size_t current_count = 0;
        bool in_flight = false;
    };

    struct GPUContext {
        GPUSlotData slots[2];
        size_t active_slot = 0;
    };

    thread_local static GPUContext gpu_ctx;

    void reap_and_verify_slot(size_t slot, PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                              std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                              std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) {
        auto& s_data = gpu_ctx.slots[slot];
        if (!s_data.in_flight || s_data.current_count == 0) return;

        GPUEngine& engine = GPUEngine::get_instance();
        bool ok = engine.wait_batch(slot);
        s_data.in_flight = false;

        if (__builtin_expect(!ok, 0)) {
            std::println(stderr, "Erro fatal na GPU! Abortando batch...");
            s_data.current_count = 0;
            return;
        }

        uint8_t* base_seed_ptr = s_data.seed_out.data();
        uint16_t* base_mnem_ptr = s_data.mnem_batch.data();
        size_t mlen = opt.base_mnemonic.size();

        for (size_t b = 0; b < s_data.current_count; ++b) {
            if (found.load(std::memory_order_relaxed)) break;

            bool is_match = false;
            if (cfg.coin == CoinTarget::BTC) {
                is_match = Bip39Deriver::check_btc_target_from_seed(ctx.ctx, base_seed_ptr + b * 64, ctx.decoded_target, opt.target_fast_hash);
            } else {
                is_match = Bip39Deriver::check_eth_target_from_seed(ctx.ctx, base_seed_ptr + b * 64, ctx.decoded_target, opt.target_fast_hash);
            }

            if (is_match) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    success = true;
                    result_mnemonic.assign(base_mnem_ptr + b * 24, base_mnem_ptr + b * 24 + mlen);
                }
                break;
            }
        }

        tested_count.fetch_add(s_data.current_count, std::memory_order_relaxed);
        valid_count.fetch_add(s_data.current_count, std::memory_order_relaxed);
        s_data.current_count = 0;
    }

public:
    void enqueue_and_process(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                             std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                             std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) override {

        if (found.load(std::memory_order_relaxed)) return;

        size_t mlen = opt.base_mnemonic.size();

        // Se as rodas do otimizador já garantem checksum analítico 100% válido, não re-testamos
        if (cfg.only_valids && !opt.direct_valid_wheels) {
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
                if (!found_valid) return;
            } else {
                if (!cryptowords::Bip39Deriver::verify_checksum(std::span<const uint16_t>(ctx.current_ids.data(), mlen))) return;
            }
        }

        size_t cur_slot = gpu_ctx.active_slot;
        auto& cur_data = gpu_ctx.slots[cur_slot];

        if (cur_data.pw_batch.size() != batch_capacity_ * slot_size_) {
            cur_data.mnem_batch.resize(batch_capacity_ * 24);
            cur_data.pw_batch.resize(batch_capacity_ * slot_size_);
            cur_data.pw_lens.resize(batch_capacity_);
            cur_data.seed_out.resize(batch_capacity_ * 64);
        }

        size_t b = cur_data.current_count;
        std::copy(ctx.current_ids.begin(), ctx.current_ids.begin() + mlen, cur_data.mnem_batch.begin() + b * 24);

        char* ptr = reinterpret_cast<char*>(cur_data.pw_batch.data()) + b * slot_size_;
        std::memcpy(ptr, opt.prefix_str.data(), opt.prefix_str.size());
        char* start_ptr = ptr;
        ptr += opt.prefix_str.size();

        for (size_t i = opt.prefix_words; i < mlen; ++i) {
            const std::string& w = cfg.wordlist[ctx.current_ids[i]];
            std::memcpy(ptr, w.data(), w.size());
            ptr += w.size();
            if (__builtin_expect(i + 1 < mlen, 1)) {
                std::memcpy(ptr, cfg.separator.data(), cfg.separator.size());
                ptr += cfg.separator.size();
            }
        }
        cur_data.pw_lens[b] = static_cast<uint32_t>(ptr - start_ptr);
        cur_data.current_count++;

        if (cur_data.current_count >= batch_capacity_) {
            GPUEngine& engine = GPUEngine::get_instance();
            // 1. Enfileira o lote atual na GPU de forma assíncrona (com cópia DMA encadeada)
            engine.enqueue_batch_async(cur_slot, cur_data.pw_batch, cur_data.pw_lens, static_cast<uint32_t>(cur_data.current_count), cur_data.seed_out.data());
            cur_data.in_flight = true;

            // 2. Alterna para o outro slot
            size_t other_slot = 1 - cur_slot;
            gpu_ctx.active_slot = other_slot;

            // 3. Se o outro slot já estava executando na GPU, colhe e verifica seus alvos agora!
            if (gpu_ctx.slots[other_slot].in_flight) {
                reap_and_verify_slot(other_slot, ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
            }
        }
    }

    void flush(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
               std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
               std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) override {

        size_t cur_slot = gpu_ctx.active_slot;
        auto& cur_data = gpu_ctx.slots[cur_slot];

        // Se a chave já foi encontrada por outra thread, descarta novo lote sem submeter à GPU
        if (found.load(std::memory_order_relaxed)) {
            cur_data.current_count = 0;
        } else if (cur_data.current_count > 0) {
            GPUEngine& engine = GPUEngine::get_instance();
            engine.enqueue_batch_async(cur_slot, cur_data.pw_batch, cur_data.pw_lens, static_cast<uint32_t>(cur_data.current_count), cur_data.seed_out.data());
            cur_data.in_flight = true;
        }

        // Colhe ambos os slots
        for (size_t s = 0; s < 2; ++s) {
            if (gpu_ctx.slots[s].in_flight) {
                reap_and_verify_slot(s, ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
            }
        }
    }
};

inline thread_local GPUBatchProcessor::GPUContext GPUBatchProcessor::gpu_ctx;

} // namespace cryptowords
