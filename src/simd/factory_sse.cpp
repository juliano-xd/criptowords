#include "../../include/simd/batch_processor.hpp"
#include <memory>

namespace cryptowords::detail {

using P = SimdBatchProcessor<SimdArch::SSE, false, false>;
using PV = SimdBatchProcessor<SimdArch::SSE, false, true>;
using PVD = SimdBatchProcessor<SimdArch::SSE, true,  true>;

std::unique_ptr<IBatchProcessor>
make_simd_processor_sse(const AppConfig& cfg, const OptimizedMnemonics& opt) {
    if (cfg.only_valids && opt.auto_deduce_last_word)
        return std::make_unique<PVD>();
    if (cfg.only_valids)
        return std::make_unique<PV>();
    return std::make_unique<P>();
}

} // namespace cryptowords::detail
