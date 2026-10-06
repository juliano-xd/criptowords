#pragma once
#include <memory>

#include "context.hpp"
#include "plan.hpp"

namespace cryptowords {

// Interface do enumerador de candidatos.
//
// Cada thread tem o seu IOdometer. Ele emite um mnemônico por vez (via
// `ctx.cursor.current_ids`) até `advance()` retornar false.
class IOdometer {
   public:
    virtual ~IOdometer() = default;

    virtual void init_state(PipelineThreadContext& ctx, size_t thread_idx,
                            size_t num_threads, const OptimizedMnemonics& opt) = 0;
    virtual bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) = 0;

    virtual uint64_t linear_position(const PipelineThreadContext& ctx,
                                     const OptimizedMnemonics& opt) const = 0;
    virtual void seek_linear(PipelineThreadContext& ctx,
                             const OptimizedMnemonics& opt, uint64_t idx) = 0;
    virtual uint64_t total_space(const OptimizedMnemonics& opt) const = 0;
};

// Escolhe a implementação pelo SearchMode resolvido na fase 3.
std::unique_ptr<IOdometer> make_odometer(const OptimizedMnemonics& opt);

}  // namespace cryptowords
