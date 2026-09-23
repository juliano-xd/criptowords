#pragma once
#include "context.hpp"
#include "odometer.hpp"
#include "processor.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace cryptowords {

// Orquestra odômetro + processador. Não sabe o que é SIMD nem GPU.
class ExecutionPipeline {
public:
    ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt);
    ~ExecutionPipeline();

    std::unique_ptr<PipelineThreadContext> create_thread_context(size_t thread_idx, size_t num_threads);

    bool advance(PipelineThreadContext& ctx) { return odometer_->advance(ctx, opt_); }

    void process(PipelineThreadContext& ctx,
                 std::atomic<bool>& found,
                 std::atomic<uint64_t>& tested,
                 std::atomic<uint64_t>& valid,
                 std::mutex& mutex,
                 bool& success,
                 std::vector<uint16_t>& result);

    void flush(PipelineThreadContext& ctx,
               std::atomic<bool>& found,
               std::atomic<uint64_t>& tested,
               std::atomic<uint64_t>& valid,
               std::mutex& mutex,
               bool& success,
               std::vector<uint16_t>& result);

    const std::string& architecture_name() const noexcept { return arch_name_; }
    double total_combinations() const noexcept { return opt_.total_combinations; }
    double math_combinations() const noexcept { return opt_.math_combinations; }
    const AppConfig& config() const noexcept { return cfg_; }

    void verify_and_print_result(const std::vector<uint16_t>& mnemonic) const;


private:
    const AppConfig&          cfg_;
    const OptimizedMnemonics& opt_;
    std::unique_ptr<IOdometer>       odometer_;
    std::unique_ptr<IBatchProcessor> processor_;
    std::unique_ptr<IBatchProcessor> cpu_processor_;
    std::string                      arch_name_;
};

} // namespace cryptowords
