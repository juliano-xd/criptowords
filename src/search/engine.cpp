#include "../../include/search/engine.hpp"

#include <chrono>
#include <cstdio>
#include <print>
#include <thread>

namespace cryptowords {
    namespace {
        void print_speed(double keys_per_sec) {
            if (keys_per_sec >= 1e6)      std::fprintf(stderr, "%.2f Mkeys/s", keys_per_sec / 1e6);
            else if (keys_per_sec >= 1e3) std::fprintf(stderr, "%.2f Kkeys/s", keys_per_sec / 1e3);
            else                          std::fprintf(stderr, "%.0f keys/s",   keys_per_sec);
        }

        void monitor_progress(const SearchState& state, size_t num_threads, std::chrono::steady_clock::time_point start) {
            auto last = start;
            uint64_t last_n = 0;

            while (!state.found.load(std::memory_order_relaxed) && !state.all_done.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (state.found.load(std::memory_order_relaxed) || state.all_done.load(std::memory_order_relaxed)) break;

                const auto now     = std::chrono::steady_clock::now();
                const double dt    = std::chrono::duration<double>(now - last).count();
                const double elap  = std::chrono::duration<double>(now - start).count();
                const uint64_t cur = state.tested_count.load(std::memory_order_relaxed);
                const double spd   = dt > 0 ? static_cast<double>(cur - last_n) / dt : 0.0;

                std::fprintf(stderr, "\r  [%6.0fs] ", elap);
                print_speed(spd);
                std::fprintf(stderr, " | Tested: %-10lu | Threads: %zu   ", cur, num_threads);
                std::fflush(stderr);

                last   = now;
                last_n = cur;
            }
            std::fprintf(stderr, "\n");
        }
    } // namespace

    void BruteForceEngine::worker(ExecutionPipeline& pipeline, size_t thread_idx, size_t num_threads, SearchState& state) {
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

        std::println("    [+] Arquitetura: {}", pipeline.architecture_name());
        std::println("    [+] Processes: {}", num_threads);
        std::println("    [+] Total combinações: {:.0f}", total);

        const auto start = std::chrono::steady_clock::now();
        SearchState state;

        std::vector<std::thread> workers;
        workers.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back(&BruteForceEngine::worker, std::ref(pipeline), i, num_threads, std::ref(state));
        }

        std::thread progress(monitor_progress, std::cref(state), num_threads, start);

        for (auto& t : workers) t.join();
        state.all_done.store(true, std::memory_order_relaxed);
        progress.join();

        const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start);

        std::println("\n\n[=] ESTATÍSTICAS DA BUSCA");
        std::println("    [+] Tempo decorrido : {:.4f} segundos", elapsed.count());
        std::println("    [+] Total testado   : {}", state.tested_count.load());
        std::println("    [+] Checksums OK    : {}", state.valid_count.load());

        if (state.success) {
            pipeline.verify_and_print_result(state.result_mnemonic);
        } else {
            std::println("\n[!] Busca finalizada. Chave não encontrada.");
        }
    }
} // namespace cryptowords
