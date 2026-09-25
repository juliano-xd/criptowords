#pragma once
#include "pipeline.hpp"

#include <atomic>
#include <mutex>
#include <vector>

namespace cryptowords {

// Estado compartilhado entre todas as threads. Vive no motor, não em cada worker.
// Cada atomic frequentemente modificado ou lido isolado em cacheline própria (64 bytes)
// para eliminar completamente False Sharing (MESI / MOESI cacheline bouncing).
struct alignas(64) SearchState {
    alignas(64) std::atomic<bool>     found{false};
    alignas(64) std::atomic<bool>     all_done{false};
    alignas(64) std::atomic<uint64_t> tested_count{0};
    std::atomic<uint64_t>             valid_count{0};
    alignas(64) std::mutex            result_mutex;
    bool                              success = false;
    std::vector<uint16_t>             result_mnemonic;
};

class BruteForceEngine {
public:
    static void run(ExecutionPipeline& pipeline, size_t num_threads);

private:
    static void worker(ExecutionPipeline& pipeline, size_t thread_idx,
                       size_t num_threads, SearchState& state);
};

} // namespace cryptowords
