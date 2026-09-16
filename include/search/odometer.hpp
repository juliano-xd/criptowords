#pragma once
#include "context.hpp"
#include "plan.hpp"

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
public:
    void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                    size_t num_threads, const OptimizedMnemonics& opt) override;
    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override;
};

} // namespace cryptowords
