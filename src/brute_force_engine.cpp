#include "../include/brute_force_engine.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>

namespace cryptowords {

void BruteForceEngine::worker_thread(ExecutionPipeline* pipeline, size_t thread_idx, size_t num_threads,
                                     std::atomic<bool>& found, std::atomic<uint64_t>& tested_count,
                                     std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                                     bool& success, std::vector<uint16_t>& result_mnemonic) {

    // O pipeline JIT aloca e configura o estado local L1 otimizado para a thread
    auto ctx = pipeline->create_thread_context(thread_idx, num_threads);

    // Loop de Execução ultra-limpo (sem branch prediction penalty)
    while (!found.load(std::memory_order_relaxed) && !ctx->is_done) {
        pipeline->process(*ctx, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
        pipeline->advance(*ctx);
    }

    // Força o descarregamento do último batch que sobrou no buffer
    pipeline->flush(*ctx, found, tested_count, valid_count, result_mutex, success, result_mnemonic);
}

void BruteForceEngine::run(ExecutionPipeline& pipeline, size_t num_threads) {
    std::cout << "    [+] Arquitetura: " << pipeline.get_architecture_name() << "\n";
    std::cout << "    [+] Threads: " << num_threads << "\n";
    std::cout << "    [+] Total combinações: " << pipeline.get_total_combinations() << "\n";

    size_t total_combos = pipeline.get_total_combinations();
    if (total_combos < num_threads * 128) {
        num_threads = 1;
    }

    std::vector<std::thread> threads;
    std::atomic<bool> found{false};
    std::atomic<uint64_t> tested_count{};
    std::atomic<uint64_t> valid_count{};
    std::mutex result_mutex;
    bool success = false;
    std::vector<uint16_t> result_mnemonic;

    size_t combos_per_thread = total_combos / num_threads;
    size_t remainder = total_combos % num_threads;

    auto start_time = std::chrono::steady_clock::now();
    auto last_time = start_time;
    uint64_t last_tested = 0;
    double current_speed = 0.0;

    size_t current_start = 0;
    for (size_t i = 0; i < num_threads; ++i) {
        size_t combos = combos_per_thread + (i < remainder ? 1 : 0);
        threads.emplace_back(worker_thread, &pipeline, i, num_threads,
                             std::ref(found), std::ref(tested_count), std::ref(valid_count),
                             std::ref(result_mutex), std::ref(success), std::ref(result_mnemonic));
        current_start += combos;
    }

    // Monitoramento da execução
    while (!found) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Medição a cada exato 1 segundo

        uint64_t current_tested = tested_count.load(std::memory_order_relaxed);
        uint64_t current_valid = valid_count.load(std::memory_order_relaxed);

        if (current_tested >= total_combos) {
            break;
        }

        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> window_elapsed = now - last_time;

        if (window_elapsed.count() > 0) {
            current_speed = (double)(current_tested - last_tested) / window_elapsed.count();
        }

        last_time = now;
        last_tested = current_tested;

        std::cout << "\r    [~] Progresso: " << current_tested << " / " << total_combos
                  << " chaves | Validas: " << current_valid
                  << " | Velocidade: " << std::fixed << std::setprecision(2) << current_speed << " chaves/s       " << std::flush;
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> total_elapsed = end_time - start_time;
    double final_speed = total_elapsed.count() > 0 ? (double)tested_count.load() / total_elapsed.count() : 0.0;

    std::cout << "\n\n[=] ESTATÍSTICAS DA BUSCA\n";
    std::cout << "    [+] Tempo decorrido : " << std::fixed << std::setprecision(4) << total_elapsed.count() << " segundos\n";
    std::cout << "    [+] Total testado   : " << tested_count.load() << "\n";
    std::cout << "    [+] Checksums OK    : " << valid_count.load() << "\n";
    std::cout << "    [+] Média Global    : " << std::fixed << std::setprecision(2) << final_speed << " chaves/s\n";

    if (success) {
        pipeline.verify_and_print_result(result_mnemonic);
    } else {
        std::cout << "\n[!] Busca finalizada. Chave não encontrada.\n";
    }
}

} // namespace cryptowords
