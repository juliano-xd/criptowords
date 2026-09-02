#pragma once
#include "app_config.hpp"
#include "gpu_engine.hpp"
#include "search_plan.hpp"
#include <atomic>
#include <mutex>
#include <thread>

class gpu_engine;

class BruteForceEngine {
  public:
    static void run_sequential(const AppConfig& cfg, const OptimizedMnemonics& opt);
    static void run_parallel(const AppConfig& cfg, const OptimizedMnemonics& opt);
    static void run_parallel_avx2(const AppConfig& cfg, const OptimizedMnemonics& opt);
    static void run_parallel_gpu(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                 gpu::Engine& gpu);

  private:
    static void worker_thread(const AppConfig& cfg, const OptimizedMnemonics& opt,
                              size_t start_combo, size_t num_combos, std::atomic<bool>& found,
                              std::atomic<uint64_t>& tested_count,
                              std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                              bool& success, std::vector<uint16_t>& result_mnemonic);

    static void worker_thread_avx2(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                   size_t start_combo, size_t num_combos, std::atomic<bool>& found,
                                   std::atomic<uint64_t>& tested_count,
                                   std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                                   bool& success, std::vector<uint16_t>& result_mnemonic);

    static void worker_thread_gpu(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                  size_t start_combo, size_t num_combos, std::atomic<bool>& found,
                                  std::atomic<uint64_t>& tested_count,
                                  std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                                  bool& success, std::vector<uint16_t>& result_mnemonic);
};
