#include "../../include/search/engine.hpp"
#include "../../include/cli/ui.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <print>
#include <thread>
#include <unordered_set>
#include <vector>
#include <algorithm>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

using namespace cryptowords::ui;

namespace cryptowords {
    namespace {
#if defined(__linux__)
        static std::vector<int> get_physical_cpu_ids() {
            std::vector<int> primary;
            std::vector<int> secondary;
            std::unordered_set<int> seen_core_ids;
            for (int cpu = 0; ; ++cpu) {
                std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/core_id";
                std::ifstream f(path);
                if (!f) break;
                int core_id = -1;
                if (f >> core_id) {
                    if (seen_core_ids.insert(core_id).second) {
                        primary.push_back(cpu);
                    } else {
                        secondary.push_back(cpu);
                    }
                }
            }
            for (int s : secondary) primary.push_back(s);
            if (primary.empty()) {
                const unsigned int total = std::thread::hardware_concurrency();
                for (unsigned int i = 0; i < total; ++i) primary.push_back(static_cast<int>(i));
            } else {
                // Priorizar núcleos de maior silício (Golden Cores / P-Cores) primeiro
                std::vector<std::pair<uint32_t, int>> rated;
                for (int cpu : primary) {
                    uint32_t score = 0;
                    std::string cppc_path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/acpi_cppc/highest_perf";
                    std::ifstream f_c(cppc_path);
                    if (f_c >> score) {}
                    else {
                        std::string f_path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpufreq/cpuinfo_max_freq";
                        std::ifstream f_m(f_path);
                        f_m >> score;
                    }
                    rated.push_back({score, cpu});
                }
                std::stable_sort(rated.begin(), rated.end(), [](const auto& a, const auto& b) {
                    return a.first > b.first;
                });
                for (size_t i = 0; i < primary.size(); ++i) {
                    primary[i] = rated[i].second;
                }
            }
            return primary;
        }
#endif

        void monitor_progress(const SearchState& state, [[maybe_unused]] size_t num_threads,
                              std::chrono::steady_clock::time_point start,
                              double total_comb) {
            auto last = start;
            uint64_t last_n = 0;

            while (!state.found.load(std::memory_order_relaxed) && !state.all_done.load(std::memory_order_relaxed)) {
                for (int s = 0; s < 20; ++s) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    if (state.found.load(std::memory_order_relaxed) || state.all_done.load(std::memory_order_relaxed)) break;
                }
                if (state.found.load(std::memory_order_relaxed) || state.all_done.load(std::memory_order_relaxed)) break;

                const auto now     = std::chrono::steady_clock::now();
                const double dt    = std::chrono::duration<double>(now - last).count();
                const double elap  = std::chrono::duration<double>(now - start).count();
                const uint64_t cur = state.tested_count.load(std::memory_order_relaxed);
                const double spd   = dt > 0 ? static_cast<double>(cur - last_n) / dt : 0.0;

                const double pct = (total_comb > 0)
                    ? std::clamp((static_cast<double>(cur) / total_comb) * 100.0, 0.0, 100.0)
                    : 0.0;

                constexpr int BAR_WIDTH = 20;
                const int filled = std::clamp(static_cast<int>(pct / 5.0), 0, BAR_WIDTH);

                std::string bar;
                for (int i = 0; i < filled; ++i) bar += "█";
                std::string empty;
                for (int i = filled; i < BAR_WIDTH; ++i) empty += "░";

                const double eta_sec = (spd > 1.0 && cur < total_comb)
                    ? (total_comb - cur) / spd
                    : -1.0;

                std::string spd_str = format_speed(spd);
                std::string eta_str = format_eta(eta_sec);
                std::string elap_str = format_eta(elap);
                std::string cur_str = format_num(static_cast<double>(cur));
                std::string tot_str = format_num(total_comb);

                std::fprintf(stderr, "\r\033[2K  [\033[36m%s\033[90m%s\033[0m] \033[1;37m%5.1f%%\033[0m │ \033[1;32m%-11s\033[0m │ \033[33mETA: %-5s\033[0m │ \033[90m%s/%s (%s)\033[0m",
                             bar.c_str(), empty.c_str(),
                             pct,
                             spd_str.c_str(),
                             eta_str.c_str(),
                             cur_str.c_str(), tot_str.c_str(),
                             elap_str.c_str());
                std::fflush(stderr);

                last   = now;
                last_n = cur;
            }
            std::fprintf(stderr, "\r\033[2K");
            std::fflush(stderr);
        }
    } // namespace

        void BruteForceEngine::worker(ExecutionPipeline& pipeline, size_t thread_idx, size_t num_threads, SearchState& state) {
#if defined(__linux__)
        static const auto cpu_ids = get_physical_cpu_ids();
        if (!cpu_ids.empty() && pipeline.config().pin_cores) {
            int target_cpu = cpu_ids[thread_idx % cpu_ids.size()];
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(target_cpu, &cpuset);
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        }
#endif

        auto ctx = pipeline.create_thread_context(thread_idx, num_threads);
        if (!ctx) return;

        while (!state.found.load(std::memory_order_relaxed) && !ctx->is_done) {
            pipeline.process(*ctx, state.found, state.tested_count, state.valid_count, state.result_mutex, state.success, state.result_mnemonic);
            pipeline.advance(*ctx);
        }

        pipeline.flush(*ctx, state.found, state.tested_count, state.valid_count, state.result_mutex, state.success, state.result_mnemonic);
    }

    void BruteForceEngine::run(ExecutionPipeline& pipeline, size_t num_threads) {
        const double total = pipeline.total_combinations();
        if (total < num_threads * 128) num_threads = 1;

        print_box_top("EXECUÇÃO DO MOTOR SIMD", DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Motor SIMD   : \033[1;36m{}\033[0m", pipeline.architecture_name()), DEFAULT_INNER_WIDTH);
        std::string pin_str = pipeline.config().pin_cores ? "\033[1;32mAtivo (Core Pinning Físico)\033[0m" : "\033[90mDesativado\033[0m";
        print_box_line(std::format("Threads      : \033[1;37m{:<4}\033[0m │ Afinidade CPU : {}", num_threads, pin_str), DEFAULT_INNER_WIDTH);
        print_box_bottom(DEFAULT_INNER_WIDTH);
        std::print("\n");


        const auto start = std::chrono::steady_clock::now();
        SearchState state;

        std::vector<std::thread> workers;
        workers.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back(&BruteForceEngine::worker, std::ref(pipeline), i, num_threads, std::ref(state));
        }

        std::thread progress(monitor_progress, std::cref(state), num_threads, start, total);

        for (auto& t : workers) t.join();
        state.all_done.store(true, std::memory_order_relaxed);
        progress.join();
        std::print("\n");

        const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start);
        const double total_sec = elapsed.count();
        const uint64_t total_tested = state.tested_count.load();
        const double avg_spd = (total_sec > 0) ? (static_cast<double>(total_tested) / total_sec) : 0.0;

        print_box_top("ESTATÍSTICAS DA BUSCA", DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Tempo decorrido   : \033[1;37m{:.4f} segundos\033[0m ({})", total_sec, format_eta(total_sec)), DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Velocidade média  : \033[1;32m{}\033[0m", format_speed(avg_spd)), DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Total testado     : {} chaves", format_num(static_cast<double>(total_tested))), DEFAULT_INNER_WIDTH);
        print_box_line(std::format("Checksums OK      : {} chaves válidas", format_num(static_cast<double>(state.valid_count.load()))), DEFAULT_INNER_WIDTH);
        print_box_separator(DEFAULT_INNER_WIDTH);
        if (state.success) {
            print_box_line("Status Final      : \033[1;32m[✓] CHAVE ENCONTRADA COM SUCESSO!\033[0m", DEFAULT_INNER_WIDTH);
        } else {
            print_box_line("Status Final      : \033[1;31m[!] Busca finalizada. Chave não encontrada.\033[0m", DEFAULT_INNER_WIDTH);
        }
        print_box_bottom(DEFAULT_INNER_WIDTH);
        std::print("\n");

        if (state.success) {
            pipeline.verify_and_print_result(state.result_mnemonic);
        } else {
            std::println("\n[!] Busca finalizada. Chave não encontrada.");
        }
    }
} // namespace cryptowords
