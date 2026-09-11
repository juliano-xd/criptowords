#pragma once

#include "pipeline_builder.hpp"
#include <atomic>
#include <mutex>
#include <vector>

namespace cryptowords {

class BruteForceEngine {
public:
    static void run(ExecutionPipeline& pipeline, size_t num_threads);

private:
    static void worker_thread(ExecutionPipeline* pipeline, size_t thread_idx, size_t num_threads, 
                              std::atomic<bool>& found, std::atomic<uint64_t>& tested_count,
                              std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                              bool& success, std::vector<uint16_t>& result_mnemonic);
};

} // namespace cryptowords
