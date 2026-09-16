#pragma once
#include "../config.hpp"
#include "plan.hpp"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

namespace cryptowords {

struct PipelineThreadContext;

// Um lote de candidatas. Pode ser SIMD ou GPU.
class IBatchProcessor {
public:
    virtual ~IBatchProcessor() = default;

    virtual void enqueue_and_process(PipelineThreadContext& ctx,
                                     const AppConfig& cfg,
                                     const OptimizedMnemonics& opt,
                                     std::atomic<bool>& found,
                                     std::atomic<uint64_t>& tested_count,
                                     std::atomic<uint64_t>& valid_count,
                                     std::mutex& result_mutex,
                                     bool& success,
                                     std::vector<uint16_t>& result_mnemonic) = 0;

    virtual void flush(PipelineThreadContext& ctx,
                       const AppConfig& cfg,
                       const OptimizedMnemonics& opt,
                       std::atomic<bool>& found,
                       std::atomic<uint64_t>& tested_count,
                       std::atomic<uint64_t>& valid_count,
                       std::mutex& result_mutex,
                       bool& success,
                       std::vector<uint16_t>& result_mnemonic) = 0;
};

} // namespace cryptowords
