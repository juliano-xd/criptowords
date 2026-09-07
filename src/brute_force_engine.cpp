#include "../include/brute_force_engine.hpp"
#include "../include/bip39.hpp"
#include "../include/crypto_mb.hpp"
#include "../include/gpu_engine.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <print>
#include <string>
#include <string_view>
#include <vector>

namespace {

inline size_t calculate_total_combinations(const OptimizedMnemonics& opt) {
    size_t total = 1;
    for (size_t i = 0; i < opt.unknown_positions.size(); ++i) {
        total *= opt.wheels[i].size();
    }
    return total;
}

void decode_combo_index(size_t combo_idx, const size_t* w_sizes, size_t num_unknowns,
                        size_t* out_state) noexcept {
    for (size_t i = num_unknowns; i-- > 0;) {
        out_state[i] = combo_idx % w_sizes[i];
        combo_idx /= w_sizes[i];
    }
}

} // anonymous namespace

void BruteForceEngine::run_sequential(const AppConfig& cfg, const OptimizedMnemonics& opt) {
    const size_t num_unknowns = opt.unknown_positions.size();
    const size_t num_combos = calculate_total_combinations(opt);
    if (num_unknowns == 0)
        return;

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const CoinTarget search_mode = cfg.coin;
    const std::string_view target = cfg.target;
    const std::string_view password = cfg.passphrase;

    std::println("\n[=] INICIANDO BUSCA SEQUENCIAL...");
    std::println("    [+] Target: {}", target);

    std::vector<uint16_t> current_mnemonic_ids = opt.base_mnemonic;

    size_t w_sizes[24];
    size_t w_pos[24];
    const uint16_t* w_ptrs[24];
    size_t state[24] = {0};

    for (size_t i = 0; i < num_unknowns; ++i) {
        w_sizes[i] = opt.wheels[i].size();
        w_pos[i] = opt.unknown_positions[i];
        w_ptrs[i] = opt.wheels[i].data();
        current_mnemonic_ids[w_pos[i]] = w_ptrs[i][0];
    }

    uint16_t* __restrict ids = current_mnemonic_ids.data();

    bool is_finished = false;
    std::atomic<bool> found{false};
    std::atomic<uint64_t> tested_count{0};
    std::atomic<uint64_t> valid_count{0};
    std::string derived_address;

    auto start_time = std::chrono::high_resolution_clock::now();

    std::jthread progress_reporter([&]() {
        while (!found.load(std::memory_order_relaxed) && tested_count.load(std::memory_order_relaxed) < num_combos) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto now = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = now - start_time;
            double speed = (elapsed.count() > 0) ? (static_cast<double>(tested_count.load(std::memory_order_relaxed)) / elapsed.count()) : 0.0;
            if (tested_count.load(std::memory_order_relaxed) < num_combos && !found.load(std::memory_order_relaxed)) {
                std::print("\r    [~] Progresso: {} / {} chaves | Validas: {} | Velocidade: {:.2f} chaves/s   ", tested_count.load(std::memory_order_relaxed), num_combos, valid_count.load(std::memory_order_relaxed), speed);
                std::fflush(stdout);
            }
        }
        std::println("");
    });

    auto advance_odometer = [&]() [[gnu::always_inline]] {
        int i = static_cast<int>(num_unknowns) - 1;
        while (true) {
            size_t next_val = state[i] + 1;
            if (BUILTIN_EXPECT(next_val < w_sizes[i], 1)) {
                state[i] = next_val;
                ids[w_pos[i]] = w_ptrs[i][next_val];
                break;
            }
            state[i] = 0;
            ids[w_pos[i]] = w_ptrs[i][0];
            if (BUILTIN_EXPECT(i == 0, 0)) {
                is_finished = true;
                break;
            }
            i--;
        }
    };

    switch (search_mode) {
    case CoinTarget::BTC: {
        while (!is_finished) {
            tested_count++;
            bool is_valid = (!cfg.only_valids) || cryptowords::Bip39Deriver::verify_checksum(current_mnemonic_ids);
            if (is_valid) {
                valid_count++;
                if (target == cryptowords::Bip39Deriver::derive_btc_address(
                                  ctx, current_mnemonic_ids, cfg.wordlist, password.data(),
                                  password.size())) {
                    found = true;
                    break;
                }
            }
            advance_odometer();
        }
    } break;

    case CoinTarget::ETH: {
        std::string normalized_target(target);
        for (char& c : normalized_target) {
            c = std::tolower(static_cast<unsigned char>(c));
        }

        while (!is_finished) {
            tested_count++;
            bool is_valid = (!cfg.only_valids) || cryptowords::Bip39Deriver::verify_checksum(current_mnemonic_ids);
            if (is_valid) {
                valid_count++;
                derived_address = cryptowords::Bip39Deriver::derive_eth_address(
                    ctx, current_mnemonic_ids, cfg.wordlist, password.data(), password.size());
                if (derived_address == normalized_target) {
                    found = true;
                    break;
                }
            }
            advance_odometer();
        }
    } break;
    }

    secp256k1_context_destroy(ctx);

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    double keys_per_sec =
        (diff.count() > 0) ? (static_cast<double>(tested_count) / diff.count()) : 0.0;

    std::println("\n[=] ESTATÍSTICAS DA BUSCA");
    std::println("    [+] Tempo decorrido : {:.4f} segundos", diff.count());
    std::println("    [+] Total testado   : {}", tested_count.load());
    std::println("    [+] Checksums OK    : {}", valid_count.load());
    std::println("    [+] Velocidade      : {:.2f} chaves/s", keys_per_sec);

    std::println("\n=======================================================");
    if (found) {
        std::string recovered_phrase;
        for (size_t i = 0; i < current_mnemonic_ids.size(); ++i) {
            recovered_phrase += cfg.wordlist[current_mnemonic_ids[i]];
            if (i < current_mnemonic_ids.size() - 1)
                recovered_phrase += " ";
        }

        std::println("[+] SUCESSO! Combinação encontrada:");
        std::println("    -> Mnemonic : {}", recovered_phrase);
        std::println("    -> Target   : {}", target);
    } else {
        std::println("[-] FALHA: O limite de combinações foi atingido.");
        std::println("           Nenhuma frase mnemônica gerou o target fornecido.");
    }
    std::println("=======================================================\n");
}

void BruteForceEngine::worker_thread(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                     size_t start_combo, size_t num_combos,
                                     std::atomic<bool>& found, std::atomic<uint64_t>& tested_count,
                                     std::atomic<uint64_t>& valid_count, std::mutex& result_mutex,
                                     bool& success, std::vector<uint16_t>& result_mnemonic) {
    const size_t num_unknowns = opt.unknown_positions.size();

    thread_local secp256k1_context* ctx = nullptr;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    std::vector<uint16_t> current_mnemonic_ids = opt.base_mnemonic;

    size_t w_sizes[24];
    size_t w_pos[24];
    const uint16_t* w_ptrs[24];

    for (size_t i = 0; i < num_unknowns; ++i) {
        w_sizes[i] = opt.wheels[i].size();
        w_pos[i] = opt.unknown_positions[i];
        w_ptrs[i] = opt.wheels[i].data();
    }

    size_t state[24] = {0};
    decode_combo_index(start_combo, w_sizes, num_unknowns, state);

    for (size_t j = 0; j < num_unknowns; ++j) {
        current_mnemonic_ids[w_pos[j]] = w_ptrs[j][state[j]];
    }

    size_t local_tested = 0;
    size_t local_valid = 0;

    auto advance_local_odometer = [&]() [[gnu::always_inline]] -> bool {
        int i = static_cast<int>(num_unknowns) - 1;
        while (true) {
            size_t next_val = state[i] + 1;
            if (BUILTIN_EXPECT(next_val < w_sizes[i], 1)) {
                state[i] = next_val;
                current_mnemonic_ids[w_pos[i]] = w_ptrs[i][next_val];
                break;
            }
            state[i] = 0;
            current_mnemonic_ids[w_pos[i]] = w_ptrs[i][0];
            if (BUILTIN_EXPECT(i == 0, 0)) {
                return false;
            }
            i--;
        }
        return true;
    };

    const std::string_view password = cfg.passphrase;
    const CoinTarget search_mode = cfg.coin;
    
    std::string target_str(cfg.target);
    if (search_mode == CoinTarget::ETH) {
        for (char& c : target_str) c = std::tolower(static_cast<unsigned char>(c));
    }

    while (local_tested < num_combos) {
        if (found.load(std::memory_order_acquire))
            break;

        local_tested++;
        if ((local_tested % 512) == 0) {
            tested_count.fetch_add(512, std::memory_order_relaxed);
        }

        bool is_valid = (!cfg.only_valids) || cryptowords::Bip39Deriver::verify_checksum(current_mnemonic_ids);
        if (is_valid) {
            local_valid++;

            std::string derived = (search_mode == CoinTarget::BTC) ?
                cryptowords::Bip39Deriver::derive_btc_address(ctx, current_mnemonic_ids, cfg.wordlist, password.data(), password.size()) :
                cryptowords::Bip39Deriver::derive_eth_address(ctx, current_mnemonic_ids, cfg.wordlist, password.data(), password.size());
                
            if (derived == target_str) {
                found.store(true, std::memory_order_release);
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!success) {
                    success = true;
                    result_mnemonic = current_mnemonic_ids;
                }
                break;
            }
        }
        if (!advance_local_odometer())
            break;
    }

    size_t rem = local_tested % 512;
    if (rem > 0) {
        tested_count.fetch_add(rem, std::memory_order_relaxed);
    }
    valid_count.fetch_add(local_valid, std::memory_order_relaxed);
}

void BruteForceEngine::run_parallel(const AppConfig& cfg, const OptimizedMnemonics& opt) {
    const size_t num_unknowns = opt.unknown_positions.size();
    if (num_unknowns == 0)
        return;

    const size_t num_threads = cfg.num_threads > 0 ? cfg.num_threads : 1;
    const size_t total_combinations = calculate_total_combinations(opt);

    if (total_combinations == 0)
        return;

    std::println("\n[=] INICIANDO BUSCA PARALELA...");
    std::println("    [+] Threads: {}", num_threads);
    std::println("    [+] Target: {}", cfg.target);
    std::println("    [+] Total combinações: {}", total_combinations);

    std::atomic<bool> found(false);
    std::atomic<uint64_t> tested_count(0);
    std::atomic<uint64_t> valid_count(0);
    std::mutex result_mutex;
    bool success = false;
    std::vector<uint16_t> result_mnemonic;

    auto start_time = std::chrono::high_resolution_clock::now();

    size_t combos_per_thread = total_combinations / num_threads;
    size_t remaining = total_combinations % num_threads;

    std::vector<std::jthread> workers;
    workers.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * combos_per_thread + std::min(t, remaining);
        size_t count = combos_per_thread + (t < remaining ? 1 : 0);

        if (count == 0)
            continue;

        workers.emplace_back([&, t, start, count]() {
            worker_thread(cfg, opt, start, count, found, tested_count, valid_count, result_mutex,
                          success, result_mnemonic);
        });
    }

    std::jthread progress_reporter([&]() {
        while (!found.load(std::memory_order_relaxed) && tested_count.load(std::memory_order_relaxed) < total_combinations) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t current = tested_count.load(std::memory_order_relaxed);
            auto now = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = now - start_time;
            double speed = (elapsed.count() > 0) ? (static_cast<double>(current) / elapsed.count()) : 0.0;
            if (current < total_combinations && !found.load(std::memory_order_relaxed)) {
                std::print("\r    [~] Progresso: {} / {} chaves | Validas: {} | Velocidade: {:.2f} chaves/s   ", current, total_combinations, valid_count.load(std::memory_order_relaxed), speed);
                std::fflush(stdout);
            }
        }
        std::println("");
    });

    for (auto& w : workers) {
        w.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    uint64_t total_tested = tested_count.load();
    double keys_per_sec =
        (diff.count() > 0) ? (static_cast<double>(total_tested) / diff.count()) : 0.0;

    std::println("\n[=] ESTATÍSTICAS DA BUSCA");
    std::println("    [+] Tempo decorrido : {:.4f} segundos", diff.count());
    std::println("    [+] Total testado   : {}", total_tested);
    std::println("    [+] Checksums OK    : {}", valid_count.load());
    std::println("    [+] Velocidade      : {:.2f} chaves/s", keys_per_sec);

    std::println("\n=======================================================");
    if (success) {
        std::string recovered_phrase;
        for (size_t i = 0; i < result_mnemonic.size(); ++i) {
            recovered_phrase += cfg.wordlist[result_mnemonic[i]];
            if (i < result_mnemonic.size() - 1)
                recovered_phrase += " ";
        }

        std::println("[+] SUCESSO! Combinação encontrada:");
        std::println("    -> Mnemonic : {}", recovered_phrase);
        std::println("    -> Target   : {}", cfg.target);
    } else {
        std::println("[-] FALHA: O limite de combinações foi atingido.");
        std::println("           Nenhuma frase mnemônica gerou o target fornecido.");
    }
    std::println("=======================================================\n");
}

void BruteForceEngine::worker_thread_avx2(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                          size_t start_combo, size_t num_combos,
                                          std::atomic<bool>& found,
                                          std::atomic<uint64_t>& tested_count,
                                          std::atomic<uint64_t>& valid_count,
                                          std::mutex& result_mutex, bool& success,
                                          std::vector<uint16_t>& result_mnemonic) {
    const size_t num_unknowns = opt.unknown_positions.size();

    thread_local secp256k1_context* ctx = nullptr;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    size_t w_sizes[24];
    size_t w_pos[24];
    const uint16_t* w_ptrs[24];

    for (size_t i = 0; i < num_unknowns; ++i) {
        w_sizes[i] = opt.wheels[i].size();
        w_pos[i] = opt.unknown_positions[i];
        w_ptrs[i] = opt.wheels[i].data();
    }

    size_t state[24] = {0};
    decode_combo_index(start_combo, w_sizes, num_unknowns, state);

    std::vector<uint16_t> current_mnemonic_ids = opt.base_mnemonic;
    for (size_t j = 0; j < num_unknowns; ++j) {
        current_mnemonic_ids[w_pos[j]] = w_ptrs[j][state[j]];
    }

    auto advance_local_odometer = [&]() [[gnu::always_inline]] -> bool {
        int i = static_cast<int>(num_unknowns) - 1;
        while (true) {
            size_t next_val = state[i] + 1;
            if (BUILTIN_EXPECT(next_val < w_sizes[i], 1)) {
                state[i] = next_val;
                current_mnemonic_ids[w_pos[i]] = w_ptrs[i][next_val];
                break;
            }
            state[i] = 0;
            current_mnemonic_ids[w_pos[i]] = w_ptrs[i][0];
            if (BUILTIN_EXPECT(i == 0, 0)) {
                return false;
            }
            i--;
        }
        return true;
    };

    const std::string_view password = cfg.passphrase;
    const CoinTarget search_mode = cfg.coin;
    constexpr size_t AVX2_BATCH = 4;

    char pw[AVX2_BATCH][256];
    size_t pw_len[AVX2_BATCH];
    uint8_t seed[AVX2_BATCH][64];

    uint8_t salt_buf[256];
    std::memcpy(salt_buf, "mnemonic", 8);
    size_t salt_len = 8;
    if (!cfg.passphrase.empty()) {
        std::memcpy(salt_buf + 8, cfg.passphrase.data(), cfg.passphrase.size());
        salt_len += cfg.passphrase.size();
    }

    std::string target_str(cfg.target);
    if (search_mode == CoinTarget::ETH) {
        for (char& c : target_str) c = std::tolower(static_cast<unsigned char>(c));
    }

    size_t local_tested = 0;
    size_t local_valid = 0;
    
    std::vector<std::vector<uint16_t>> valid_batch;
    valid_batch.reserve(AVX2_BATCH);

    auto process_batch = [&]() {
        size_t batch_sz = valid_batch.size();
        if (batch_sz == 0) return;
        
        if (batch_sz == AVX2_BATCH) {
            for (size_t b = 0; b < AVX2_BATCH; ++b) {
                pw_len[b] = cryptowords::Bip39Deriver::build_mnemonic_str(valid_batch[b], cfg.wordlist, pw[b]);
                crypto::pbkdf2_hmac_sha512(pw[b], pw_len[b], salt_buf, salt_len, cfg.pbkdf2_rounds, seed[b], 64);
            }
        } else {
            for (size_t b = 0; b < batch_sz; ++b) {
                pw_len[b] = cryptowords::Bip39Deriver::build_mnemonic_str(valid_batch[b], cfg.wordlist, pw[b]);
                crypto::pbkdf2_hmac_sha512(pw[b], pw_len[b], salt_buf, salt_len, cfg.pbkdf2_rounds, seed[b], 64);
            }
        }
        
        for (size_t b = 0; b < batch_sz; ++b) {
            if (found.load(std::memory_order_acquire)) break;
            
            std::string derived = (search_mode == CoinTarget::BTC) ?
                cryptowords::Bip39Deriver::derive_btc_address_from_seed(ctx, seed[b], password.data(), password.size()) :
                cryptowords::Bip39Deriver::derive_eth_address_from_seed(ctx, seed[b], password.data(), password.size());
                
            if (derived == target_str) {
                found.store(true, std::memory_order_release);
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!success) {
                    success = true;
                    result_mnemonic = valid_batch[b];
                }
            }
        }
        valid_batch.clear();
    };

    while (local_tested < num_combos) {
        if (found.load(std::memory_order_acquire)) break;
        
        local_tested++;
        if ((local_tested % 512) == 0) {
            tested_count.fetch_add(512, std::memory_order_relaxed);
        }
        
        bool is_valid = (!cfg.only_valids) || cryptowords::Bip39Deriver::verify_checksum(current_mnemonic_ids);
        
        if (is_valid) {
            local_valid++;
            valid_batch.push_back(current_mnemonic_ids);
            if (valid_batch.size() == AVX2_BATCH) {
                process_batch();
            }
        }
        
        if (!advance_local_odometer()) break;
    }
    process_batch();
    
    size_t rem = local_tested % 512;
    if (rem > 0) {
        tested_count.fetch_add(rem, std::memory_order_relaxed);
    }
    valid_count.fetch_add(local_valid, std::memory_order_relaxed);
}

void BruteForceEngine::run_parallel_avx2(const AppConfig& cfg, const OptimizedMnemonics& opt) {
    const size_t num_unknowns = opt.unknown_positions.size();
    if (num_unknowns == 0)
        return;

    const size_t num_threads = cfg.num_threads > 0 ? cfg.num_threads : 4;
    const size_t total_combinations = calculate_total_combinations(opt);

    if (total_combinations == 0)
        return;

    std::println("\n[=] INICIANDO BUSCA PARALELA AVX2...");
    std::println("    [+] Threads: {}", num_threads);
    std::println("    [+] Target: {}", cfg.target);
    std::println("    [+] Total combinações: {}", total_combinations);

    std::atomic<bool> found(false);
    std::atomic<uint64_t> tested_count(0);
    std::atomic<uint64_t> valid_count(0);
    std::mutex result_mutex;
    bool success = false;
    std::vector<uint16_t> result_mnemonic;

    auto start_time = std::chrono::high_resolution_clock::now();

    size_t combos_per_thread = total_combinations / num_threads;
    size_t remaining = total_combinations % num_threads;

    std::println("    [+] Combos por thread: {}", combos_per_thread);
    std::println("    [+] Combos restantes: {}", remaining);

    std::vector<std::jthread> workers;
    workers.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * combos_per_thread + std::min(t, remaining);
        size_t count = combos_per_thread + (t < remaining ? 1 : 0);

        if (count == 0)
            continue;

        workers.emplace_back([&, t, start, count]() {
            worker_thread_avx2(cfg, opt, start, count, found, tested_count, valid_count,
                               result_mutex, success, result_mnemonic);
        });
    }

    std::jthread progress_reporter([&]() {
        while (!found.load(std::memory_order_relaxed) && tested_count.load(std::memory_order_relaxed) < total_combinations) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t current = tested_count.load(std::memory_order_relaxed);
            auto now = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = now - start_time;
            double speed = (elapsed.count() > 0) ? (static_cast<double>(current) / elapsed.count()) : 0.0;
            if (current < total_combinations && !found.load(std::memory_order_relaxed)) {
                std::print("\r    [~] Progresso: {} / {} chaves | Validas: {} | Velocidade: {:.2f} chaves/s   ", current, total_combinations, valid_count.load(std::memory_order_relaxed), speed);
                std::fflush(stdout);
            }
        }
        std::println("");
    });

    for (auto& w : workers) {
        w.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    uint64_t total_tested = tested_count.load();
    double keys_per_sec =
        (diff.count() > 0) ? (static_cast<double>(total_tested) / diff.count()) : 0.0;

    std::println("\n[=] ESTATÍSTICAS DA BUSCA");
    std::println("    [+] Tempo decorrido : {:.4f} segundos", diff.count());
    std::println("    [+] Total testado   : {}", total_tested);
    std::println("    [+] Checksums OK    : {}", valid_count.load());
    std::println("    [+] Velocidade      : {:.2f} chaves/s", keys_per_sec);

    std::println("\n=======================================================");
    if (success) {
        std::string recovered_phrase;
        for (size_t i = 0; i < result_mnemonic.size(); ++i) {
            recovered_phrase += cfg.wordlist[result_mnemonic[i]];
            if (i < result_mnemonic.size() - 1)
                recovered_phrase += " ";
        }

        std::println("[+] SUCESSO! Combinação encontrada:");
        std::println("    -> Mnemonic : {}", recovered_phrase);
        std::println("    -> Target   : {}", cfg.target);
    } else {
        std::println("[-] FALHA: O limite de combinações foi atingido.");
        std::println("           Nenhuma frase mnemônica gerou o target fornecido.");
    }
    std::println("=======================================================\n");
}

void BruteForceEngine::worker_thread_gpu(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                         size_t start_combo, size_t num_combos,
                                         std::atomic<bool>& found,
                                         std::atomic<uint64_t>& tested_count,
                                         std::atomic<uint64_t>& valid_count,
                                         std::mutex& result_mutex, bool& success,
                                         std::vector<uint16_t>& result_mnemonic) {
    const size_t num_unknowns = opt.unknown_positions.size();

    thread_local secp256k1_context* ctx = nullptr;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    size_t w_sizes[24];
    size_t w_pos[24];
    const uint16_t* w_ptrs[24];

    for (size_t i = 0; i < num_unknowns; ++i) {
        w_sizes[i] = opt.wheels[i].size();
        w_pos[i] = opt.unknown_positions[i];
        w_ptrs[i] = opt.wheels[i].data();
    }

    size_t state[24] = {0};
    decode_combo_index(start_combo, w_sizes, num_unknowns, state);

    std::vector<uint16_t> current_mnemonic_ids = opt.base_mnemonic;
    for (size_t j = 0; j < num_unknowns; ++j) {
        current_mnemonic_ids[w_pos[j]] = w_ptrs[j][state[j]];
    }

    auto advance_local_odometer = [&]() [[gnu::always_inline]] -> bool {
        int i = static_cast<int>(num_unknowns) - 1;
        while (true) {
            size_t next_val = state[i] + 1;
            if (BUILTIN_EXPECT(next_val < w_sizes[i], 1)) {
                state[i] = next_val;
                current_mnemonic_ids[w_pos[i]] = w_ptrs[i][next_val];
                break;
            }
            state[i] = 0;
            current_mnemonic_ids[w_pos[i]] = w_ptrs[i][0];
            if (BUILTIN_EXPECT(i == 0, 0)) {
                return false;
            }
            i--;
        }
        return true;
    };

    const std::string_view password = cfg.passphrase;
    const CoinTarget search_mode = cfg.coin;
    constexpr size_t GPU_BATCH = 16;

    std::string target_str(cfg.target);
    if (search_mode == CoinTarget::ETH) {
        for (char& c : target_str) c = std::tolower(static_cast<unsigned char>(c));
    }

    size_t local_tested = 0;
    size_t local_valid = 0;
    
    std::vector<std::vector<uint16_t>> valid_batch;
    valid_batch.reserve(GPU_BATCH);
    std::vector<std::vector<uint8_t>> seeds;

    auto process_batch = [&]() {
        size_t batch_sz = valid_batch.size();
        if (batch_sz == 0) return;
        
        seeds.resize(batch_sz);
        gpu::Engine* gpu_ptr = static_cast<gpu::Engine*>(cfg.gpu_engine);
        if (!gpu_ptr->pbkdf2_batch_from_ids(valid_batch, cfg.wordlist, cfg.pbkdf2_rounds, seeds)) {
            return;
        }
        
        for (size_t b = 0; b < batch_sz; ++b) {
            if (found.load(std::memory_order_acquire)) break;
            
            std::string derived = (search_mode == CoinTarget::BTC) ?
                cryptowords::Bip39Deriver::derive_btc_address_from_seed(ctx, seeds[b].data(), password.data(), password.size()) :
                cryptowords::Bip39Deriver::derive_eth_address_from_seed(ctx, seeds[b].data(), password.data(), password.size());
                
            if (derived == target_str) {
                found.store(true, std::memory_order_release);
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!success) {
                    success = true;
                    result_mnemonic = valid_batch[b];
                }
            }
        }
        valid_batch.clear();
    };

    while (local_tested < num_combos) {
        if (found.load(std::memory_order_acquire)) break;
        
        local_tested++;
        if ((local_tested % 512) == 0) {
            tested_count.fetch_add(512, std::memory_order_relaxed);
        }
        
        bool is_valid = (!cfg.only_valids) || cryptowords::Bip39Deriver::verify_checksum(current_mnemonic_ids);
        
        if (is_valid) {
            local_valid++;
            valid_batch.push_back(current_mnemonic_ids);
            if (valid_batch.size() == GPU_BATCH) {
                process_batch();
            }
        }
        
        if (!advance_local_odometer()) break;
    }
    process_batch();
    
    size_t rem = local_tested % 512;
    if (rem > 0) {
        tested_count.fetch_add(rem, std::memory_order_relaxed);
    }
    valid_count.fetch_add(local_valid, std::memory_order_relaxed);
}

void BruteForceEngine::run_parallel_gpu(const AppConfig& cfg, const OptimizedMnemonics& opt,
                                        gpu::Engine& gpu) {
    const size_t num_unknowns = opt.unknown_positions.size();
    if (num_unknowns == 0)
        return;

    const size_t num_threads = 1; // GPU é single-threaded por natureza
    const size_t total_combinations = calculate_total_combinations(opt);

    if (total_combinations == 0)
        return;

    std::println("\n[=] INICIANDO BUSCA GPU...");
    std::println("    [+] Device: {}", gpu.device_name());
    std::println("    [+] Total combinações: {}", total_combinations);

    std::atomic<bool> found(false);
    std::atomic<uint64_t> tested_count(0);
    std::atomic<uint64_t> valid_count(0);
    std::mutex result_mutex;
    bool success = false;
    std::vector<uint16_t> result_mnemonic;

    auto start_time = std::chrono::high_resolution_clock::now();

    size_t combos_per_thread = total_combinations / num_threads;
    size_t remaining = total_combinations % num_threads;

    std::vector<std::jthread> workers;
    workers.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        size_t start = t * combos_per_thread + std::min(t, remaining);
        size_t count = combos_per_thread + (t < remaining ? 1 : 0);

        if (count == 0)
            continue;

        workers.emplace_back([&, t, start, count, &gpu]() {
            AppConfig cfg_with_gpu = cfg;
            cfg_with_gpu.gpu_engine = &gpu;
            worker_thread_gpu(cfg_with_gpu, opt, start, count, found, tested_count, valid_count,
                              result_mutex, success, result_mnemonic);
        });
    }

    std::jthread progress_reporter([&]() {
        while (!found.load(std::memory_order_relaxed) && tested_count.load(std::memory_order_relaxed) < total_combinations) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            uint64_t current = tested_count.load(std::memory_order_relaxed);
            auto now = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = now - start_time;
            double speed = (elapsed.count() > 0) ? (static_cast<double>(current) / elapsed.count()) : 0.0;
            if (current < total_combinations && !found.load(std::memory_order_relaxed)) {
                std::print("\r    [~] Progresso: {} / {} chaves | Validas: {} | Velocidade: {:.2f} chaves/s   ", current, total_combinations, valid_count.load(std::memory_order_relaxed), speed);
                std::fflush(stdout);
            }
        }
        std::println("");
    });

    for (auto& w : workers) {
        w.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;
    uint64_t total_tested = tested_count.load();
    double keys_per_sec =
        (diff.count() > 0) ? (static_cast<double>(total_tested) / diff.count()) : 0.0;

    std::println("\n[=] ESTATÍSTICAS DA BUSCA");
    std::println("    [+] Tempo decorrido : {:.4f} segundos", diff.count());
    std::println("    [+] Total testado   : {}", total_tested);
    std::println("    [+] Checksums OK    : {}", valid_count.load());
    std::println("    [+] Velocidade      : {:.2f} chaves/s", keys_per_sec);

    std::println("\n=======================================================");
    if (success) {
        std::string recovered_phrase;
        for (size_t i = 0; i < result_mnemonic.size(); ++i) {
            recovered_phrase += cfg.wordlist[result_mnemonic[i]];
            if (i < result_mnemonic.size() - 1)
                recovered_phrase += " ";
        }

        std::println("[+] SUCESSO! Combinação encontrada:");
        std::println("    -> Mnemonic : {}", recovered_phrase);
        std::println("    -> Target   : {}", cfg.target);
    } else {
        std::println("[-] FALHA: O limite de combinações foi atingido.");
        std::println("           Nenhuma frase mnemônica gerou o target fornecido.");
    }
    std::println("=======================================================\n");
}
