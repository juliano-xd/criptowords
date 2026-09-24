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
#include <thread>
#include <condition_variable>

namespace cryptowords {

class GpuVerificationPool {
    struct Job {
        const uint8_t* base_seed_ptr = nullptr;
        const uint16_t* base_mnem_ptr = nullptr;
        size_t mlen = 0;
        const secp256k1_context* ctx = nullptr;
        const uint8_t* decoded_target = nullptr;
        uint32_t target_fast_hash = 0;
        CoinTarget coin = CoinTarget::BTC;
        std::atomic<bool>* found = nullptr;
        std::mutex* result_mutex = nullptr;
        bool* success = nullptr;
        std::vector<uint16_t>* result_mnemonic = nullptr;
        size_t total_keys = 0;
        size_t chunk = 0;
    };

    std::vector<std::thread> workers_;
    std::mutex mu_;
    std::condition_variable cv_work_;
    std::condition_variable cv_done_;
    Job current_job_;
    size_t active_workers_ = 0;
    uint64_t job_id_ = 0;
    bool stop_ = false;

public:
    static GpuVerificationPool& get_instance() {
        static GpuVerificationPool pool;
        return pool;
    }

    GpuVerificationPool() {
        const unsigned int hw = std::thread::hardware_concurrency();
        size_t n = std::clamp(hw, 1u, 128u);
        workers_.reserve(n);
        for (size_t w = 0; w < n; ++w) {
            workers_.emplace_back([this, w]() {
                uint64_t last_id = 0;
                while (true) {
                    Job job;
                    {
                        std::unique_lock<std::mutex> lock(mu_);
                        cv_work_.wait(lock, [this, last_id]() {
                            return stop_ || job_id_ > last_id;
                        });
                        if (stop_) return;
                        last_id = job_id_;
                        job = current_job_;
                    }

                    const size_t start_b = w * job.chunk;
                    const size_t end_b   = std::min(start_b + job.chunk, job.total_keys);

                    if (start_b < end_b) {
                        for (size_t b = start_b; b < end_b; ++b) {
                            if (job.found->load(std::memory_order_relaxed)) break;

                            std::array<u8, 64> seed64;
                            std::memcpy(seed64.data(), job.base_seed_ptr + b * 64, 64);
                            bool is_match = (job.coin == CoinTarget::BTC)
                                ? Bip39Deriver::check_btc_target_from_seed(job.ctx, job.base_seed_ptr + b * 64, job.decoded_target, job.target_fast_hash)
                                : Bip39Deriver::check_eth_target_from_seed(*job.ctx, seed64, job.decoded_target, job.target_fast_hash);

                            if (is_match) {
                                bool expected = false;
                                if (job.found->compare_exchange_strong(expected, true)) {
                                    std::lock_guard<std::mutex> lock(*job.result_mutex);
                                    *job.success = true;
                                    job.result_mnemonic->assign(job.base_mnem_ptr + b * 24, job.base_mnem_ptr + b * 24 + job.mlen);
                                }
                                break;
                            }
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lock(mu_);
                        if (--active_workers_ == 0) {
                            cv_done_.notify_one();
                        }
                    }
                }
            });
        }
    }

    ~GpuVerificationPool() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stop_ = true;
        }
        cv_work_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
    }

    void verify(const uint8_t* base_seed_ptr, const uint16_t* base_mnem_ptr, size_t mlen,
                const secp256k1_context* ctx, const uint8_t* decoded_target, uint32_t target_fast_hash,
                CoinTarget coin, std::atomic<bool>& found, std::mutex& result_mutex,
                bool& success, std::vector<uint16_t>& result_mnemonic, size_t total_keys) {
        if (total_keys == 0) return;
        const size_t num_w = workers_.size();
        if (total_keys <= 2048 || num_w <= 1) {
            for (size_t b = 0; b < total_keys; ++b) {
                if (found.load(std::memory_order_relaxed)) break;
                std::array<u8, 64> seed64;
                std::memcpy(seed64.data(), base_seed_ptr + b * 64, 64);
                bool is_match = (coin == CoinTarget::BTC)
                    ? Bip39Deriver::check_btc_target_from_seed(ctx, base_seed_ptr + b * 64, decoded_target, target_fast_hash)
                    : Bip39Deriver::check_eth_target_from_seed(*ctx, seed64, decoded_target, target_fast_hash);
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
            return;
        }

        std::unique_lock<std::mutex> lock(mu_);
        current_job_.base_seed_ptr = base_seed_ptr;
        current_job_.base_mnem_ptr = base_mnem_ptr;
        current_job_.mlen = mlen;
        current_job_.ctx = ctx;
        current_job_.decoded_target = decoded_target;
        current_job_.target_fast_hash = target_fast_hash;
        current_job_.coin = coin;
        current_job_.found = &found;
        current_job_.result_mutex = &result_mutex;
        current_job_.success = &success;
        current_job_.result_mnemonic = &result_mnemonic;
        current_job_.total_keys = total_keys;
        current_job_.chunk = (total_keys + num_w - 1) / num_w;
        active_workers_ = num_w;
        job_id_++;
        cv_work_.notify_all();

        cv_done_.wait(lock, [this]() {
            return active_workers_ == 0;
        });
    }
};

class GPUBatchProcessor : public IBatchProcessor {
    size_t batch_capacity_ = 4096;
    size_t slot_size_ = 256;

public:
    explicit GPUBatchProcessor(const AppConfig& cfg) {
        size_t opt_batch = GPUEngine::get_instance().get_optimal_batch_size();
        batch_capacity_ = (cfg.gpu_batch > 0) ? cfg.gpu_batch : opt_batch;
        if (batch_capacity_ < 512) batch_capacity_ = 512;
        size_t wg = GPUEngine::get_instance().get_local_work_size();
        if (wg == 0) wg = 64;
        batch_capacity_ = ((batch_capacity_ + wg - 1) / wg) * wg;

        slot_size_ = GPUEngine::get_instance().get_slot_size();
        if (slot_size_ == 0) {
            bool is_cjk = (cfg.language == "ja" || cfg.language == "japanese" ||
                           cfg.language == "ko" || cfg.language == "korean" ||
                           cfg.language.starts_with("zh") || cfg.language.starts_with("chinese") ||
                           cfg.separator == "\xE3\x80\x80");
            slot_size_ = (is_cjk || cfg.mnemonics.size() >= 21) ? 512 : (cfg.mnemonics.size() > 12 ? 256 : 128);
        }

        fast_wl_.resize(cfg.wordlist.size());
        for (size_t i = 0; i < cfg.wordlist.size(); ++i) {
            fast_wl_[i].data = cfg.wordlist[i].data();
            fast_wl_[i].len = static_cast<uint32_t>(cfg.wordlist[i].size());
        }
    }

    struct WordView {
        const char* data = nullptr;
        uint32_t len = 0;
    };
    std::vector<WordView> fast_wl_;

    static constexpr size_t NUM_SLOTS = 3;

    struct GPUSlotData {
        std::vector<uint16_t> mnem_batch; // [batch_capacity_ * 24]
        std::vector<uint8_t> pw_batch;    // [batch_capacity_ * slot_size_]
        std::vector<uint32_t> pw_lens;    // [batch_capacity_]
        std::vector<uint8_t> seed_out;    // [batch_capacity_ * 64]
        size_t current_count = 0;
        bool in_flight = false;
    };

    struct GPUContext {
        GPUSlotData slots[NUM_SLOTS];
        size_t active_slot = 0;
    };

    thread_local static GPUContext gpu_ctx;

    void reap_and_verify_slot(size_t slot, PipelineThreadContext &ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
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

        const size_t total_keys = s_data.current_count;

        GpuVerificationPool::get_instance().verify(
            base_seed_ptr, base_mnem_ptr, mlen, ctx.ctx,
            ctx.decoded_target, opt.target_fast_hash,
            cfg.coin, found, result_mutex, success,
            result_mnemonic, total_keys);

        tested_count.fetch_add(s_data.current_count, std::memory_order_relaxed);
        // Só podemos contar como "checksum OK" as chaves que passaram pelo filtro
        // de enqueue (cfg.only_valids). Com --invalid-too a GPU também processa
        // chaves de checksum inválido; somar current_count incondicionalmente
        // inflava o contador de "chaves válidas" (100% do lote virava válido).
        if (cfg.only_valids) {
            valid_count.fetch_add(s_data.current_count, std::memory_order_relaxed);
        }
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
            if (opt.prefix_words > 0 && !opt.prefix_str.empty()) {
                for (size_t k = 0; k < batch_capacity_; ++k) {
                    std::memcpy(cur_data.pw_batch.data() + k * slot_size_,
                                opt.prefix_str.data(), opt.prefix_str.size());
                }
            }
        }

        size_t b = cur_data.current_count;
        std::memcpy(cur_data.mnem_batch.data() + b * 24, ctx.current_ids.data(), mlen * sizeof(uint16_t));

        char* start_ptr = reinterpret_cast<char*>(cur_data.pw_batch.data()) + b * slot_size_;
        char* ptr = start_ptr;
        if (opt.prefix_words > 0 && !opt.prefix_str.empty()) {
            ptr += opt.prefix_str.size();
        }

        const bool single_byte_sep = (cfg.separator.size() == 1);
        const char sep_c = single_byte_sep ? cfg.separator[0] : ' ';

        for (size_t i = opt.prefix_words; i < mlen; ++i) {
            uint16_t wid = ctx.current_ids[i];
            const auto& wv = fast_wl_[wid];
            std::memcpy(ptr, wv.data, wv.len);
            ptr += wv.len;
            if (__builtin_expect(i + 1 < mlen, 1)) {
                if (single_byte_sep) {
                    *ptr++ = sep_c;
                } else {
                    std::memcpy(ptr, cfg.separator.data(), cfg.separator.size());
                    ptr += cfg.separator.size();
                }
            }
        }
        cur_data.pw_lens[b] = static_cast<uint32_t>(ptr - start_ptr);
        cur_data.current_count++;

        if (cur_data.current_count >= batch_capacity_) {
            GPUEngine& engine = GPUEngine::get_instance();
            // 1. Enfileira o lote atual na GPU de forma assíncrona (com cópia DMA encadeada)
            engine.enqueue_batch_async(cur_slot, cur_data.pw_batch, cur_data.pw_lens, static_cast<uint32_t>(cur_data.current_count), cur_data.seed_out.data());
            cur_data.in_flight = true;

            // 2. Alterna para o próximo slot (Triple-Buffering)
            size_t next_slot = (cur_slot + 1) % NUM_SLOTS;
            gpu_ctx.active_slot = next_slot;

            // 3. Se o próximo slot já estava executando na GPU, colhe e verifica seus alvos agora para liberá-lo!
            if (gpu_ctx.slots[next_slot].in_flight) {
                reap_and_verify_slot(next_slot, ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
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

        // Colhe todos os slots em voo
        for (size_t s = 0; s < NUM_SLOTS; ++s) {
            if (gpu_ctx.slots[s].in_flight) {
                reap_and_verify_slot(s, ctx, cfg, opt, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
            }
        }
    }

};

inline thread_local GPUBatchProcessor::GPUContext GPUBatchProcessor::gpu_ctx;

} // namespace cryptowords
