#pragma once
#include "context.hpp"
#include "plan.hpp"

#include <atomic>

namespace cryptowords {

// Avança a thread pelo espaço de busca (mixed-radix).
class IOdometer {
public:
    virtual ~IOdometer() = default;
    virtual void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                            size_t num_threads, const OptimizedMnemonics& opt) = 0;
    virtual bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) = 0;
};

class GenericOdometer final : public IOdometer {
    std::atomic<size_t> next_pair_idx_{0};
    std::atomic<size_t> next_triplet_idx_{0};
    bool is_dynamic_partition_{false};
    size_t gpu_batch_{1024};

public:
    GenericOdometer() = default;
    explicit GenericOdometer(bool dynamic_partition, size_t gpu_batch = 1024)
        : is_dynamic_partition_(dynamic_partition), gpu_batch_(gpu_batch) {}

    void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                    size_t num_threads, const OptimizedMnemonics& opt) override;
    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override;
};

} // namespace cryptowords
