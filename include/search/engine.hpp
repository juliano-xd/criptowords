#pragma once
#include "pipeline.hpp"

#include <atomic>
#include <mutex>
#include <vector>

namespace cryptowords {

// Estado compartilhado entre todas as threads. Vive no motor, não em cada worker.
struct SearchState {
    std::atomic<bool>     found{false};
    std::atomic<bool>     all_done{false};
    std::atomic<uint64_t> tested_count{0};
    std::atomic<uint64_t> valid_count{0};
    std::mutex            result_mutex;
    bool                  success = false;
    std::vector<uint16_t> result_mnemonic;
};

class BruteForceEngine {
public:
    static void run(ExecutionPipeline& pipeline, size_t num_threads);

private:
    static void worker(ExecutionPipeline& pipeline, size_t thread_idx,
                       size_t num_threads, SearchState& state);
};

} // namespace cryptowords
