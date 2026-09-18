#include "../../include/simd/batch_processor.hpp"
#include <memory>

namespace cryptowords::detail {

using P = SimdBatchProcessor<SimdArch::AVX2, false, false>;
using PV = SimdBatchProcessor<SimdArch::AVX2, false, true>;
using PVD = SimdBatchProcessor<SimdArch::AVX2, true,  true>;

std::unique_ptr<IBatchProcessor>
make_simd_processor_avx2(const AppConfig& cfg, const OptimizedMnemonics& opt) {
    if (opt.direct_valid_wheels)
        return std::make_unique<P>();
    if (cfg.only_valids && opt.auto_deduce_last_word)
        return std::make_unique<PVD>();
    if (cfg.only_valids)
        return std::make_unique<PV>();
    return std::make_unique<P>();
}

} // namespace cryptowords::detail
