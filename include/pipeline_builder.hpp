#pragma once
#include "app_config.hpp"
#include "search_plan.hpp"
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <secp256k1.h>
#include <string>

namespace cryptowords {

// ---------------------------------------------------------
// ESTRUTURAS DO PIPELINE
// ---------------------------------------------------------

struct PipelineThreadContext {
    alignas(64) char pw[16 * 256];
    size_t pw_len[16];
    alignas(64) uint8_t seed[16 * 64];
    alignas(64) uint16_t valid_batch[16 * 24];
    size_t valid_batch_sz = 0;

    alignas(64) uint16_t checksum_batch[32 * 24];
    size_t c_batch_sz = 0;

    uint8_t decoded_target[20] = {};
    uint8_t salt_buf[256] = {};
    size_t salt_len = 0;

    secp256k1_context* ctx = nullptr;

    std::vector<size_t> state;
    size_t step_size = 1;
    bool is_done = false;
    std::vector<uint16_t> current_ids;

    size_t local_tested = 0;
    size_t local_valid = 0;

    ~PipelineThreadContext() {
        if (ctx) secp256k1_context_destroy(ctx);
    }
};

// Interfaces internas
class IOdometer {
public:
    virtual ~IOdometer() = default;
    virtual void init_state(PipelineThreadContext& ctx, size_t thread_idx, size_t num_threads, const OptimizedMnemonics& opt) = 0;
    virtual bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) = 0;
};

class IBatchProcessor {
public:
    virtual ~IBatchProcessor() = default;
    virtual void enqueue_and_process(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                                     std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                                     std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) = 0;
    virtual void flush(PipelineThreadContext& ctx, const AppConfig& cfg, const OptimizedMnemonics& opt,
                       std::atomic<bool>& found, std::atomic<uint64_t>& tested_count, std::atomic<uint64_t>& valid_count,
                       std::mutex& result_mutex, bool& success, std::vector<uint16_t>& result_mnemonic) = 0;
};

enum class SimdArch {
    SSE,
    AVX2,
    AVX512
};

// ---------------------------------------------------------
// EXECUTION PIPELINE (O "Compilado" pronto para rodar)
// ---------------------------------------------------------

class ExecutionPipeline {
    const AppConfig& cfg_;
    const OptimizedMnemonics& opt_;
    std::unique_ptr<IOdometer> odometer_;
    std::unique_ptr<IBatchProcessor> processor_;
    SimdArch arch_;

public:
    ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt);

    // Criação e inicialização completa de um Thread Context
    std::unique_ptr<PipelineThreadContext> create_thread_context(size_t thread_idx, size_t num_threads);

    // Delegação para o loop da BruteForceEngine
    inline bool advance(PipelineThreadContext& ctx) { return odometer_->advance(ctx, opt_); }
    inline void process(PipelineThreadContext& ctx, std::atomic<bool>& found, std::atomic<uint64_t>& tested,
                        std::atomic<uint64_t>& valid, std::mutex& mutex, bool& success, std::vector<uint16_t>& result) {
        processor_->enqueue_and_process(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
    }
    inline void flush(PipelineThreadContext& ctx, std::atomic<bool>& found, std::atomic<uint64_t>& tested,
                      std::atomic<uint64_t>& valid, std::mutex& mutex, bool& success, std::vector<uint16_t>& result) {
        processor_->flush(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
    }

    std::string get_architecture_name() const;
    double get_total_combinations() const { return opt_.total_combinations; }
    void verify_and_print_result(const std::vector<uint16_t>& result_mnemonic) const;
};

} // namespace cryptowords
