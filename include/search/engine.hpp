#pragma once
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "pipeline.hpp"
#include "snapshot.hpp"

namespace cryptowords {

// -------------------------------------------------------------------------
// SearchState — estado global compartilhado entre workers, monitor e
// autosave. Cada contador agrega os valores locais das threads.
//
// `eliminated` só é incrementado quando `plan.count_eliminations` é true
// (i.e., há filtro de checksum ativo). Em --invalid_too sem --checksum,
// permanece 0.
// -------------------------------------------------------------------------
struct alignas(64) SearchState {
    alignas(64) std::atomic<bool> found{false};
    alignas(64) std::atomic<bool> all_done{false};

    alignas(64) std::atomic<uint64_t> tested_count{0};   // chaves submetidas a PBKDF2
    alignas(64) std::atomic<uint64_t> valid_count{0};    // chaves que passaram o checksum
    alignas(64) std::atomic<uint64_t> eliminated{0};     // chaves rejeitadas pelo checksum

    alignas(64) std::mutex result_mutex;
    bool success = false;
    std::vector<uint16_t> result_mnemonic;

    std::vector<std::unique_ptr<ThreadSnapshot>> snapshots;

    // Save/resume: setado pelo signal handler (Ctrl+C/SIGTERM).
    alignas(64) std::atomic<bool> save_requested{false};

    bool     checkpoint_loaded    = false;
    uint64_t checkpoint_start_idx = 0;
    uint64_t checkpoint_total_idx = 0;
};

class BruteForceEngine {
   public:
    static void run(ExecutionPipeline& pipeline, size_t num_threads);

   private:
    static void worker(ExecutionPipeline& pipeline, size_t thread_idx,
                       size_t num_threads, SearchState& state);

    static void save_snapshot(const ExecutionPipeline& pipeline,
                              const SearchState& state,
                              const std::string& path);
};

}  // namespace cryptowords
