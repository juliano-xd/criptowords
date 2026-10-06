#pragma once
#include <memory>

#include "../../include/simd/batch_processor.hpp"
#include "../../include/simd/factory.hpp"

// 3 arquiteturas × 5 modos = 15 instanciações. O switch é resolvido uma vez
// por execução (no construtor do pipeline).
#define CRYPTOWORDS_DEFINE_SIMD_FACTORY(NAME, ARCH)                                          \
    namespace cryptowords::detail {                                                          \
    std::unique_ptr<IBatchProcessor> make_simd_processor_##NAME(                             \
        const AppConfig& cfg, const OptimizedMnemonics& opt) {                               \
        (void)cfg;                                                                           \
        switch (opt.checksum_mode) {                                                         \
            case ChecksumMode::None:                                                         \
                return std::make_unique<SimdBatchProcessor<ARCH, ChecksumMode::None>>();     \
            case ChecksumMode::Expected:                                                     \
                return std::make_unique<SimdBatchProcessor<ARCH, ChecksumMode::Expected>>(); \
            case ChecksumMode::AutoDeduce:                                                   \
                return std::make_unique<SimdBatchProcessor<ARCH, ChecksumMode::AutoDeduce>>();\
            case ChecksumMode::UserPattern:                                                  \
                return std::make_unique<SimdBatchProcessor<ARCH, ChecksumMode::UserPattern>>();\
            case ChecksumMode::SelfVerify:                                                   \
                return std::make_unique<SimdBatchProcessor<ARCH, ChecksumMode::SelfVerify>>();\
        }                                                                                    \
        return nullptr;                                                                      \
    }                                                                                        \
    }  // namespace cryptowords::detail
