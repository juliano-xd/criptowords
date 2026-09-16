#include "../../include/search/odometer.hpp"

namespace cryptowords {

void GenericOdometer::init_state(PipelineThreadContext& ctx, size_t thread_idx,
                                 size_t num_threads, const OptimizedMnemonics& opt) {
    ctx.step_size   = num_threads;
    ctx.is_done     = false;
    ctx.state.assign(opt.wheels.size(), 0);
    ctx.current_ids = opt.base_mnemonic;

    // Distribui o índice da thread em mixed-radix. Zero wheels == estado inválido.
    size_t temp = thread_idx;
    for (int i = static_cast<int>(opt.wheels.size()) - 1; i >= 0; --i) {
        const size_t w = opt.wheels[i].size();
        if (w == 0) { ctx.is_done = true; return; }
        ctx.state[i] = temp % w;
        temp /= w;
    }
    if (temp > 0) { ctx.is_done = true; return; }

    for (size_t i = 0; i < opt.wheels.size(); ++i) {
        ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][ctx.state[i]];
    }
}

bool GenericOdometer::advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) {
    if (ctx.is_done) return false;

    size_t carry = ctx.step_size;
    for (int i = static_cast<int>(opt.wheels.size()) - 1; i >= 0 && carry > 0; --i) {
        const size_t w   = opt.wheels[i].size();
        const size_t sum = ctx.state[i] + carry;

        if (sum < w) {
            ctx.state[i] = sum;
            carry = 0;
        } else {
            ctx.state[i] = sum % w;
            carry        = sum / w;
        }
        ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][ctx.state[i]];
    }

    if (carry > 0) { ctx.is_done = true; return false; }
    return true;
}

} // namespace cryptowords
