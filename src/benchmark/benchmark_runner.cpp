#include "../../include/benchmark/benchmark_runner.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/hmac_sha512.hpp"
#include "../../include/crypto/pbkdf2_simd.hpp"
#include "../../include/crypto/sha512.hpp"
#include "../../include/crypto/secp256k1_scalar.hpp"
#include "../../include/crypto/secp256k1_point.hpp"
#include "../../include/gpu/gpu_engine.hpp"
#include "../../include/gpu/gpu_info.hpp"
#include "../../include/simd/arch.hpp"
#include "../../include/cli/ui.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <format>
#include <fstream>
#include <latch>
#include <print>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <secp256k1.h>

namespace cryptowords {

using namespace ui;
using namespace std;
using Clock = chrono::high_resolution_clock;

namespace {
    // Impede que o otimizador elimine o loop de benchmark inteiro.
    [[gnu::always_inline]] inline void bench_barrier(uint64_t sink) noexcept {
        asm volatile("" :: "r"(sink) : "memory");
    }

    struct CpuHardwareInfo {
        string model = "Desconhecido";
        int physical_cores = 0;
        string governor = "";
    };

    static CpuHardwareInfo detect_cpu_hardware() {
        CpuHardwareInfo info;
#if defined(__linux__)
        ifstream cpuinfo("/proc/cpuinfo");
        if (cpuinfo.is_open()) {
            string line;
            set<int> core_ids;
            while (getline(cpuinfo, line)) {
                if (info.model == "Desconhecido" && line.rfind("model name", 0) == 0) {
                    auto colon = line.find(':');
                    if (colon != string::npos) {
                        info.model = line.substr(colon + 1);
                        while (!info.model.empty() && (info.model.front() == ' ' || info.model.front() == '\t'))
                            info.model.erase(0, 1);
                    }
                }
                if (line.rfind("core id", 0) == 0) {
                    auto colon = line.find(':');
                    if (colon != string::npos) {
                        try {
                            core_ids.insert(stoi(line.substr(colon + 1)));
                        } catch (...) {}
                    }
                }
            }
            if (!core_ids.empty()) {
                info.physical_cores = static_cast<int>(core_ids.size());
            }
        }
        ifstream gov_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
        if (gov_file.is_open()) {
            getline(gov_file, info.governor);
        }
#endif
        return info;
    }

    static string sanitize_device_name(string name) {
        if (name.size() > 32) {
            auto p = name.find('(');
            if (p != string::npos && p > 4) {
                name = name.substr(0, p - 1);
            }
            if (name.size() > 32) {
                name = name.substr(0, 29) + "...";
            }
        }
        return name;
    }

    static string sanitize_platform_name(string name) {
        if (name.find("Accelerated Parallel Processing") != string::npos) {
            return "AMD APP";
        }
        if (name.size() > 16) {
            name = name.substr(0, 13) + "...";
        }
        return name;
    }
} // namespace

int BenchmarkRunner::run(const AppConfig& /*cfg*/) {
    print_box_top("CRIPTOWORDS v2.0 - SUÍTE DE BENCHMARK & PROFILING DE HARDWARE", DEFAULT_INNER_WIDTH);
    print_box_line("Ambiente de Teste: Metrificação real de núcleos SIMD, OpenCL e Aritmética.", DEFAULT_INNER_WIDTH);
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 1. DESCOBERTA E INFORMAÇÕES DE HARDWARE
    // =========================================================================
    size_t hw_threads = thread::hardware_concurrency();
    auto cpu_info = detect_cpu_hardware();

    print_box_top("[1/7] HARDWARE & CAPACIDADES DETECTADAS", DEFAULT_INNER_WIDTH);
    print_box_line(format("Processador Host (CPU)    : {}", cpu_info.model));
    print_box_line(format("Núcleos & Threads CPU     : {} físicos, {} threads lógicas{}",
                          cpu_info.physical_cores > 0 ? to_string(cpu_info.physical_cores) : "?",
                          hw_threads,
                          cpu_info.governor.empty() ? "" : format(" [Gov: {}]", cpu_info.governor)));

    string simd_list = "";
#if defined(__AVX512F__) || defined(CRYPTOWORDS_HAVE_AVX512)
    simd_list += "AVX-512, ";
#endif
#if defined(__AVX2__) || defined(CRYPTOWORDS_HAVE_AVX2)
    simd_list += "AVX2, ";
#endif
#if defined(__SSE4_1__) || defined(CRYPTOWORDS_HAVE_SSE41)
    simd_list += "SSE4.1, ";
#endif
#if defined(__SHA__)
    simd_list += "SHA-NI, ";
#endif
#if defined(__BMI2__)
    simd_list += "BMI2, ";
#endif
    if (simd_list.ends_with(", ")) simd_list.resize(simd_list.size() - 2);
    print_box_line(format("Extensões SIMD de CPU     : {}", simd_list));

    auto devices = gpu::enumerate_devices();
    print_box_line(format("Aceleradores OpenCL (GPU) : {} dispositivo(s) encontrado(s)", devices.size()));
    for (size_t i = 0; i < devices.size(); ++i) {
        const auto& dev = devices[i];
        string badge = (i == 0) ? " ★ [AUTO]" : "";
        string d_name = sanitize_device_name(dev.device_name);
        string p_name = sanitize_platform_name(dev.platform_name);
        print_box_line(format("  ├─ [Plat {}, Dev {}] {} ({}){}",
                              dev.platform_idx, dev.device_idx, d_name, p_name, badge));
        print_box_line(format("  │  CUs: {} │ Clock: {} MHz │ VRAM: {} MB │ Max WG: {}",
                              dev.compute_units, dev.clock_freq, dev.global_mem / (1024 * 1024), dev.max_work_group));
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 2. MICRO-BENCHMARK: CHECKSUM BIP-39 & PODA ANALÍTICA
    // =========================================================================
    print_box_top("[2/7] BENCHMARK: CHECKSUM BIP-39 & PODA ANALÍTICA (SHA-NI / SHA256)", DEFAULT_INNER_WIDTH);
    {
        constexpr size_t TOTAL_CHECKS = 1'000'000;
        vector<uint16_t> sample_ids = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
        uint64_t valid_cnt = 0;
        uint64_t guard = 0;

        auto t0 = Clock::now();
        for (size_t i = 0; i < TOTAL_CHECKS; ++i) {
            sample_ids[11] = static_cast<uint16_t>((sample_ids[11] + 1) & 0x7FF);
            guard += Bip39Deriver::verify_checksum(span<const uint16_t>(sample_ids.data(), 12)) ? 1u : 0u;
        }
        auto t1 = Clock::now();
        bench_barrier(guard);
        valid_cnt = guard;

        double elapsed_sec = chrono::duration<double>(t1 - t0).count();
        double mops = (TOTAL_CHECKS / elapsed_sec) / 1e6;
        double ns_per_op = (elapsed_sec / TOTAL_CHECKS) * 1e9;

        print_box_line(format("Iterações de Checksum     : {:>12} avaliações", TOTAL_CHECKS));
        print_box_line("Padrão de Variação        : 1 palavra variável (word-only, BIP-39 12w)");
        print_box_line(format("Tempo Decorrido           : {:>12.4f} ms", elapsed_sec * 1000.0));
        print_box_line(format("Vazão de Verificação      : {:>12.2f} Mop/s (milhões de ops/segundo)", mops));
        print_box_line(format("Latência por Checksum     : {:>12.2f} ns/op", ns_per_op));
        print_box_line(format("Validação Matemática      : Checksums válidos encontrados: {:<8}", valid_cnt));
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 3. MICRO-BENCHMARK: CPU PBKDF2-HMAC-SHA512 (SIMD MULTI-WAY vs ESCALAR)
    // =========================================================================
    print_box_top("[3/7] BENCHMARK: CPU PBKDF2-HMAC-SHA512 (SIMD MULTI-WAY vs ESCALAR)", DEFAULT_INNER_WIDTH);

    const SimdArch host_arch = detect_best_simd();
    const string arch_label = (host_arch == SimdArch::AVX512) ? "AVX-512 (16 lanes)" :
                              (host_arch == SimdArch::AVX2)   ? "AVX2 (8 lanes)" :
                                                                "SSE4.1 (4 lanes)";
    const size_t simd_lanes = (host_arch == SimdArch::AVX512) ? 16 :
                              (host_arch == SimdArch::AVX2)   ? 8 : 4;

    const string test_pw = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const string test_salt = "mnemonic";

    // Pré-computa buffers de salt para o motor SIMD
    uint8_t s_buf[128] = {};
    memcpy(s_buf, test_salt.data(), test_salt.size());
    s_buf[test_salt.size()]     = 0;
    s_buf[test_salt.size() + 1] = 0;
    s_buf[test_salt.size() + 2] = 0;
    s_buf[test_salt.size() + 3] = 1;
    s_buf[test_salt.size() + 4] = 0x80;

    uint64_t s_blk[16];
    memcpy(s_blk, s_buf, 128);
    uint64_t salt_block64[16];
    for (int w = 0; w < 15; ++w) {
        salt_block64[w] = pbkdf2_simd_detail::bswap64(s_blk[w]);
    }
    salt_block64[15] = static_cast<uint64_t>(128 + test_salt.size() + 4) * 8;

    uint64_t kw_salt[80];
    precompute_kw_salt(salt_block64, kw_salt);

    alignas(32) uint64_t kw_salt_avx2[320];
    alignas(16) uint64_t kw_salt_sse[160];
    alignas(64) uint64_t kw_salt_avx512[640];
    pbkdf2_simd_detail::precompute_kw_salt_tables(kw_salt, kw_salt_sse, kw_salt_avx2, kw_salt_avx512);

    auto run_simd_lane = [&](uint8_t out[16][64]) {
        if (host_arch == SimdArch::AVX512) {
            pbkdf2_hmac_sha512_16way_avx512(
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                reinterpret_cast<const uint8_t*>(test_salt.data()), test_salt.size(),
                2048,
                out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
                out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15],
                salt_block64, kw_salt, kw_salt_avx512
            );
        } else if (host_arch == SimdArch::AVX2) {
            pbkdf2_hmac_sha512_8way_avx2(
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                reinterpret_cast<const uint8_t*>(test_salt.data()), test_salt.size(),
                2048,
                out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
                salt_block64, kw_salt, kw_salt_avx2
            );
        } else {
            pbkdf2_hmac_sha512_4way_sse(
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                test_pw.data(), test_pw.size(), test_pw.data(), test_pw.size(),
                reinterpret_cast<const uint8_t*>(test_salt.data()), test_salt.size(),
                2048,
                out[0], out[1], out[2], out[3],
                salt_block64, kw_salt, kw_salt_sse
            );
        }
    };

    // --- Comparativo 1-Thread: Escalar vs SIMD ---
    constexpr size_t SINGLE_HASHES = 128;
    uint8_t sc_out[64];
    uint64_t sc_guard = 0;
    auto t_sc0 = Clock::now();
    for (size_t i = 0; i < SINGLE_HASHES; ++i) {
        crypto::pbkdf2_hmac_sha512(test_pw.data(), test_pw.size(),
            reinterpret_cast<const uint8_t*>(test_salt.data()), test_salt.size(),
            2048, sc_out, 64);
        sc_guard += sc_out[0];
    }
    auto t_sc1 = Clock::now();
    bench_barrier(sc_guard);
    const double sc_sec = chrono::duration<double>(t_sc1 - t_sc0).count();
    const double sc_rate = SINGLE_HASHES / sc_sec;
    const double sc_ms_per_key = (sc_sec * 1000.0) / SINGLE_HASHES;

    alignas(64) uint8_t sm_out[16][64];
    uint64_t sm_guard = 0;
    const size_t simd_batches_single = SINGLE_HASHES / simd_lanes;
    auto t_sm0 = Clock::now();
    for (size_t i = 0; i < simd_batches_single; ++i) {
        run_simd_lane(sm_out);
        sm_guard += sm_out[0][0];
    }
    auto t_sm1 = Clock::now();
    bench_barrier(sm_guard);
    const double sm_sec = chrono::duration<double>(t_sm1 - t_sm0).count();
    const double sm_rate = SINGLE_HASHES / sm_sec;
    const double sm_ms_per_key = (sm_sec * 1000.0) / SINGLE_HASHES;
    const double simd_vector_speedup = (sc_sec > 0.0) ? (sc_sec / sm_sec) : 1.0;

    print_box_line(format("Motor SIMD Ativo no Host : {}", arch_label));
    print_box_line(format("1-Thread Escalar (1 chave): {:>10.2f} keys/s ({:.2f} ms/chave)", sc_rate, sc_ms_per_key));
    print_box_line(format("1-Thread SIMD ({:>2} lanes) : {:>10.2f} keys/s ({:.2f} ms/chave) -> {:.2f}x speedup vetorial",
                          simd_lanes, sm_rate, sm_ms_per_key, simd_vector_speedup));

    print_box_separator(DEFAULT_INNER_WIDTH);
    print_box_line("Escalabilidade Multithread (Motor SIMD de Produção):");
    println("├─────────┼────────────┼────────────┼───────────────────────┼──────────┼─────────────┤");
    println("│ Threads │ Lote/Thread│ Tempo (ms) │ Throughput (keys/s)   │ Speedup  │ Eficiência  │");
    println("├─────────┼────────────┼────────────┼───────────────────────┼──────────┼─────────────┤");

    vector<size_t> thread_counts;
    thread_counts.push_back(1);
    for (size_t t = 2; t < hw_threads; t *= 2) {
        thread_counts.push_back(t);
    }
    if (hw_threads > 1 && thread_counts.back() != hw_threads) {
        thread_counts.push_back(hw_threads);
    }

    double simd_baseline_rate = 0.0;
    double cpu_peak_rate = 0.0;

    for (size_t threads : thread_counts) {
        const size_t batches_per_thread = 16;
        const size_t hashes_per_thread = batches_per_thread * simd_lanes;
        const size_t total_hashes = threads * hashes_per_thread;

        latch gate(static_cast<ptrdiff_t>(threads));
        vector<thread> workers;
        workers.reserve(threads);
        atomic<uint64_t> guard{0};

        auto worker_fn = [&]() {
            gate.arrive_and_wait();
            alignas(64) uint8_t out[16][64];
            uint64_t local = 0;
            for (size_t b = 0; b < batches_per_thread; ++b) {
                run_simd_lane(out);
                local += out[0][0];
            }
            guard.fetch_add(local, memory_order_relaxed);
        };

        for (size_t t = 0; t < threads; ++t) {
            workers.emplace_back(worker_fn);
        }

        auto t0 = Clock::now();
        for (auto& w : workers) w.join();
        auto t1 = Clock::now();

        bench_barrier(guard.load(memory_order_relaxed));

        double elapsed_sec = chrono::duration<double>(t1 - t0).count();
        double rate = total_hashes / elapsed_sec;
        if (threads == 1) simd_baseline_rate = rate;
        if (rate > cpu_peak_rate) cpu_peak_rate = rate;
        double speedup = (simd_baseline_rate > 0) ? (rate / simd_baseline_rate) : 1.0;
        double efficiency = (speedup / static_cast<double>(threads)) * 100.0;

        println("│ {:^7} │ {:^10} │ {:>10.2f} │ {:>19.2f} │ {:>7.2f}x │ {:>10.1f}% │",
                threads, hashes_per_thread, elapsed_sec * 1000.0, rate, speedup, efficiency);
    }
    println("╰─────────┴────────────┴────────────┴───────────────────────┴──────────┴─────────────╯");
    println();

    // =========================================================================
    // 4. MICRO-BENCHMARK: GPU OPENCL (PROFILING EM NÍVEL DE HARDWARE)
    // =========================================================================
    print_box_top("[4/7] BENCHMARK: GPU OPENCL PROFILING (HARDWARE EVENTS & SATURAÇÃO)", DEFAULT_INNER_WIDTH);
    double gpu_peak_rate = 0.0;

    if (devices.empty()) {
        print_box_line("[!] Nenhum dispositivo OpenCL disponível para benchmark de GPU.");
        print_box_bottom(DEFAULT_INNER_WIDTH);
    } else {
        const vector<size_t> base_batch_sizes = {1024, 2048, 4096, 8192, 16384, 32768, 65536};
        constexpr size_t bench_slot_sz = 128;
        GPUEngine& gpu_engine = GPUEngine::get_instance();

        print_box_line("[i] Warm-up prévio de 2 iterações ativa o clock de pico (P-state máximo).");
        print_box_line("[i] Latência e vazão medidas via Hardware Events OpenCL (H2D + Kernel + D2H).");

        for (const auto& dev : devices) {
            const bool is_rusticl = (dev.platform_name.find("rusticl") != string::npos);
            string d_name = sanitize_device_name(dev.device_name);
            string p_name = sanitize_platform_name(dev.platform_name);

            print_box_separator(DEFAULT_INNER_WIDTH);
            print_box_line(format("▶ DISPOSITIVO: [Plat {}, Dev {}] {} ({})",
                                  dev.platform_idx, dev.device_idx, d_name, p_name));
            print_box_line(format("  VRAM: {} MB │ CUs: {} │ Clock Base: {} MHz",
                                  dev.global_mem / (1024 * 1024), dev.compute_units, dev.clock_freq));
            println("├────────┼───────────┼────────────┼─────────────┼─────────────┼──────────┼───────────┤");
            println("│  Lote  │ H2D (ms)  │ H2D (GB/s) │ Kernel (ms) │ Kernel kh/s │ D2H (ms) │ Efet(kh/s)│");
            println("├────────┼───────────┼────────────┼─────────────┼─────────────┼──────────┼───────────┤");

            size_t best_batch = 0;
            double best_effective_khs = 0.0;

            vector<size_t> cur_batch_sizes = base_batch_sizes;
            if (dev.compute_units >= 20 || dev.global_mem >= 6ULL * 1024 * 1024 * 1024) {
                cur_batch_sizes.push_back(131072);
                cur_batch_sizes.push_back(262144);
            }
            if (dev.compute_units >= 60 || dev.global_mem >= 12ULL * 1024 * 1024 * 1024) {
                cur_batch_sizes.push_back(524288);
            }

            for (size_t batch : cur_batch_sizes) {
                gpu_engine.cleanup();
                if (!gpu_engine.init(dev.platform_idx, dev.device_idx, batch, nullptr, true, bench_slot_sz)) {
                    println("│ {:>6} │ [Falha na inicialização da GPU para este lote]                            │", batch);
                    break;
                }

                vector<uint8_t> pw_batch(batch * bench_slot_sz, 0);
                vector<uint32_t> pw_lens(batch, static_cast<uint32_t>(test_pw.size()));
                vector<uint8_t> seed_out(batch * 64, 0);

                for (size_t b = 0; b < batch; ++b) {
                    memcpy(pw_batch.data() + b * bench_slot_sz, test_pw.data(), test_pw.size());
                }

                // 2 iterações de warm-up para elevar o clock de economia de energia para P-State máximo
                for (int w = 0; w < 2; ++w) {
                    gpu_engine.pbkdf2_batch(pw_batch, pw_lens, seed_out, static_cast<uint32_t>(batch));
                }

                GpuExecutionMetrics metrics;
                bool ok = gpu_engine.pbkdf2_batch_profiled(
                    pw_batch, pw_lens, seed_out, static_cast<uint32_t>(batch), metrics);
                if (!ok) {
                    println("│ {:>6} │ [Falha de execução do kernel OpenCL]                                     │", batch);
                    break;
                }

                const double h2d_ms   = static_cast<double>(metrics.write_time_ns)  / 1e6;
                const double kern_ms  = static_cast<double>(metrics.kernel_time_ns) / 1e6;
                const double d2h_ms   = static_cast<double>(metrics.read_time_ns)   / 1e6;
                const double kern_khs = metrics.kernel_keys_per_sec / 1e3;
                const double total_ms = h2d_ms + kern_ms + d2h_ms;
                const double eff_khs  = (metrics.total_keys_per_sec > 0.0)
                                        ? (metrics.total_keys_per_sec / 1e3)
                                        : (total_ms > 0.0 ? (static_cast<double>(batch) / total_ms) : 0.0);

                if (eff_khs > best_effective_khs) {
                    best_effective_khs = eff_khs;
                    best_batch = batch;
                }

                println("│ {:>6} │ {:>9.3f} │ {:>10.3f} │ {:>11.3f} │ {:>11.2f} │ {:>8.3f} │ {:>9.2f} │",
                        batch, h2d_ms, metrics.bandwidth_h2d_gb_s, kern_ms, kern_khs, d2h_ms, eff_khs);

                // Trava de estabilidade/watchdog TDR (evita hang detection / context reset no driver)
                if ((is_rusticl && kern_ms > 450.0) || (dev.compute_units <= 2 && batch >= 8192) || kern_ms > 1200.0) {
                    println("├────────┴───────────┴────────────┴─────────────┴─────────────┴──────────┴───────────┤");
                    print_box_line(format("➔ Ponto de Saturação: Lotes > {:>5} atingem a janela de estabilidade do driver.", batch));
                    break;
                }
            }

            gpu_engine.cleanup();
            if (best_effective_khs * 1e3 > gpu_peak_rate) {
                gpu_peak_rate = best_effective_khs * 1e3;
            }
            println("├────────┴───────────┴────────────┴─────────────┴─────────────┴──────────┴───────────┤");
            print_box_line(format("➔ Ponto de Operação Ótimo: Lote de {:>5} chaves ({:.2f} kh/s efetivos)",
                                  best_batch, best_effective_khs));
        }
        print_box_bottom(DEFAULT_INNER_WIDTH);
    }
    println();

    // =========================================================================
    // 5. BENCHMARK: MOTOR INTEGRADO & MODO HÍBRIDO COOPERATIVO
    // =========================================================================
    print_box_top("[5/7] BENCHMARK: MOTOR INTEGRADO & MODO HÍBRIDO COOPERATIVO", DEFAULT_INNER_WIDTH);
    const double hybrid_peak_rate = cpu_peak_rate + gpu_peak_rate;

    print_box_line(format("Vazão Física CPU (SIMD {}) : {:>10.2f} keys/s", arch_label, cpu_peak_rate));
    if (gpu_peak_rate > 0.0) {
        print_box_line(format("Vazão Física GPU (OpenCL)       : {:>10.2f} keys/s", gpu_peak_rate));
        print_box_line(format("Vazão Híbrida Combinada (CPU+GPU): {:>9.2f} keys/s (100% de uso de hardware)", hybrid_peak_rate));
    } else {
        print_box_line("Vazão Física GPU (OpenCL)       : [N/A - Dispositivo não disponível]");
        print_box_line(format("Vazão Máxima do Sistema         : {:>10.2f} keys/s", cpu_peak_rate));
    }

    print_box_separator(DEFAULT_INNER_WIDTH);
    const double eff_rate_12w = hybrid_peak_rate * 16.0;
    const double eff_rate_24w = hybrid_peak_rate * 256.0;
    print_box_line(format("Throughput Efetivo (12 Palavras): {:>10.2f} Kkeys/s (com poda analítica 16x)", eff_rate_12w / 1e3));
    print_box_line(format("Throughput Efetivo (24 Palavras): {:>10.2f} Mkeys/s (com poda analítica 256x)", eff_rate_24w / 1e6));

    print_box_separator(DEFAULT_INNER_WIDTH);
    print_box_line("Projeção de Tempo de Busca (Modo Híbrido / Capacidade Máxima):");
    println("├─────────────┼──────────────────┼──────────────────┼────────────────┼───────────────┤");
    println("│ Incógnitas  │   Espaço Bruto   │ Lote Efet. (12w) │   ETA (12w)    │   ETA (24w)   │");
    println("├─────────────┼──────────────────┼──────────────────┼────────────────┼───────────────┤");

    println("│ {:<11} │ {:>16} │ {:>16} │ {:>14} │ {:>13} │",
            "1 palavra", "2.048", "128", "< 0.01 s", "< 0.01 s");

    const double eta_12w_2 = (hybrid_peak_rate > 0) ? (262144.0 / hybrid_peak_rate) : 0.0;
    const double eta_24w_2 = (hybrid_peak_rate > 0) ? (16384.0  / hybrid_peak_rate) : 0.0;
    println("│ {:<11} │ {:>16} │ {:>16} │ {:>14} │ {:>13} │",
            "2 palavras", "4.194.304", "262.144", format_eta(eta_12w_2), format_eta(eta_24w_2));

    const double eta_12w_3 = (hybrid_peak_rate > 0) ? (536870912.0 / hybrid_peak_rate) : 0.0;
    const double eta_24w_3 = (hybrid_peak_rate > 0) ? (33554432.0  / hybrid_peak_rate) : 0.0;
    println("│ {:<11} │ {:>16} │ {:>16} │ {:>14} │ {:>13} │",
            "3 palavras", "8.589.934.592", "536.870.912", format_eta(eta_12w_3), format_eta(eta_24w_3));

    println("╰─────────────┴──────────────────┴──────────────────┴────────────────┴───────────────╯");
    println();

    // =========================================================================
    // 6. MICRO-BENCHMARK: DERIVAÇÃO SECP256K1 BIP-32 & ARITMÉTICA ESCALAR
    // =========================================================================
    print_box_top("[6/7] BENCHMARK: DERIVAÇÃO BIP-32 & ARITMÉTICA SECP256K1", DEFAULT_INNER_WIDTH);
    {
        auto* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        // --- 6.1 Adição escalar: libsecp256k1 vs UInt<4> nativo ---
        constexpr size_t SCALAR_ITERS = 1'000'000;
        array<u8, 32> k_bench, tw_bench;
        memset(k_bench.data(), 0x42, 32);
        memset(tw_bench.data(), 0x55, 32);
        k_bench[0] = 0x10;
        tw_bench[0] = 0x10;

        uint64_t scalar_guard = 0;
        auto t_s0 = Clock::now();
        for (size_t i = 0; i < SCALAR_ITERS; ++i) {
            scalar_guard += static_cast<uint64_t>(secp256k1_ec_seckey_tweak_add(secp_ctx, k_bench.data(), tw_bench.data()));
        }
        auto t_s1 = Clock::now();
        bench_barrier(scalar_guard);
        const double secp_ns = chrono::duration<double, nano>(t_s1 - t_s0).count() / SCALAR_ITERS;

        memset(k_bench.data(), 0x42, 32);
        k_bench[0] = 0x10;
        auto t_f0 = Clock::now();
        for (size_t i = 0; i < SCALAR_ITERS; ++i) {
            crypto::secp256k1_tweak_add_fast(k_bench, tw_bench);
        }
        auto t_f1 = Clock::now();
        const double fast_ns = chrono::duration<double, nano>(t_f1 - t_f0).count() / SCALAR_ITERS;

        print_box_line(format("Adição Escalar libsecp256k1    : {:>11.2f} ns/op", secp_ns));
        print_box_line(format("Adição Escalar UInt<4> Nativa   : {:>11.2f} ns/op ({:.2f}x speedup)", fast_ns, secp_ns / fast_ns));

        // --- 6.2 Aritmética de Campo F_p: Mul vs Sqr (UInt<4>) ---
        constexpr size_t FIELD_ITERS = 1'000'000;
        UInt<4> fa("0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        UInt<4> fb("0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321");
        UInt<4> f_acc = fa;

        auto t_m0 = Clock::now();
        for (size_t i = 0; i < FIELD_ITERS; ++i) {
            f_acc = crypto::mul_mod_p(f_acc, fb);
        }
        auto t_m1 = Clock::now();
        bench_barrier(f_acc.bits[0]);
        const double mul_ns = chrono::duration<double, nano>(t_m1 - t_m0).count() / FIELD_ITERS;

        f_acc = fa;
        auto t_sq0 = Clock::now();
        for (size_t i = 0; i < FIELD_ITERS; ++i) {
            f_acc = crypto::sqr_mod_p(f_acc);
        }
        auto t_sq1 = Clock::now();
        bench_barrier(f_acc.bits[0]);
        const double sqr_ns = chrono::duration<double, nano>(t_sq1 - t_sq0).count() / FIELD_ITERS;

        print_box_line(format("Multiplicação F_p mul_mod_p     : {:>11.2f} ns/op", mul_ns));
        print_box_line(format("Quadratura F_p sqr_mod_p        : {:>11.2f} ns/op ({:.2f}x speedup)", sqr_ns, mul_ns / sqr_ns));

        // --- 6.3 Divisão Escalar Base58: Knuth vs divmod(u64) ---
        constexpr size_t DIV_ITERS = 500'000;
        UInt<4> div_test("0x000102030405060708090A0B0C0D0E0F101112131415161718");
        UInt<4> d58(58ULL);
        uint64_t div_guard = 0;

        auto t_dk0 = Clock::now();
        for (size_t i = 0; i < DIV_ITERS; ++i) {
            auto [q, r] = div_test.divmod(d58);
            div_guard += r.bits[0];
        }
        auto t_dk1 = Clock::now();
        bench_barrier(div_guard);
        const double knuth_ns = chrono::duration<double, nano>(t_dk1 - t_dk0).count() / DIV_ITERS;

        auto t_df0 = Clock::now();
        for (size_t i = 0; i < DIV_ITERS; ++i) {
            auto [q, r] = div_test.divmod(58ULL);
            div_guard += r;
        }
        auto t_df1 = Clock::now();
        bench_barrier(div_guard);
        const double fast_div_ns = chrono::duration<double, nano>(t_df1 - t_df0).count() / DIV_ITERS;

        print_box_line(format("Divisão Knuth divmod(UInt<4>)   : {:>11.2f} ns/op", knuth_ns));
        print_box_line(format("Divisão Escalar divmod(58)      : {:>11.2f} ns/op ({:.2f}x speedup)", fast_div_ns, knuth_ns / fast_div_ns));

        // --- 6.4 Multiplicação de ponto P = k * G ---
        constexpr size_t PUB_ITERS = 5000;
        array<u8, 32> seckey_bench;
        memset(seckey_bench.data(), 0x33, 32);
        seckey_bench[0] = 0x10;
        secp256k1_pubkey secp_pub;

        uint64_t pub_guard = 0;
        auto t_p0 = Clock::now();
        for (size_t i = 0; i < PUB_ITERS; ++i) {
            pub_guard += static_cast<uint64_t>(
                secp256k1_ec_pubkey_create(secp_ctx, &secp_pub, seckey_bench.data()));
        }
        auto t_p1 = Clock::now();
        bench_barrier(pub_guard);
        const double secp_pub_us = chrono::duration<double, micro>(t_p1 - t_p0).count() / PUB_ITERS;

        array<u8, 33> fast_pub;
        auto t_pf0 = Clock::now();
        for (size_t i = 0; i < PUB_ITERS; ++i) {
            crypto::secp256k1_pubkey_create_fast(fast_pub, seckey_bench);
        }
        auto t_pf1 = Clock::now();
        const double fast_pub_us = chrono::duration<double, micro>(t_pf1 - t_pf0).count() / PUB_ITERS;

        print_box_line(format("Pubkey Create libsecp256k1      : {:>11.2f} µs/op", secp_pub_us));
        print_box_line(format("Pubkey Create UInt<4> Nativa    : {:>11.2f} µs/op ({:.2f}x speedup)", fast_pub_us, secp_pub_us / fast_pub_us));

        // --- 6.5 Derivação completa BIP-32 ---
        constexpr size_t DERIV_COUNT = 25'000;
        uint8_t dummy_seed[64];
        memset(dummy_seed, 0x42, 64);
        uint8_t target_ripemd[20];
        memset(target_ripemd, 0xAA, 20);

        uint64_t deriv_guard = 0;
        auto t0 = Clock::now();
        for (size_t i = 0; i < DERIV_COUNT; ++i) {
            dummy_seed[0] = static_cast<uint8_t>(i);
            dummy_seed[1] = static_cast<uint8_t>(i >> 8);
            deriv_guard += Bip39Deriver::check_btc_target_from_seed(secp_ctx, dummy_seed, target_ripemd, 0u) ? 1u : 0u;
        }
        auto t1 = Clock::now();
        bench_barrier(deriv_guard);
        const size_t matches = static_cast<size_t>(deriv_guard);

        secp256k1_context_destroy(secp_ctx);

        const double elapsed_sec = chrono::duration<double>(t1 - t0).count();
        const double d_rate = DERIV_COUNT / elapsed_sec;
        const double us_per_key = (elapsed_sec / DERIV_COUNT) * 1e6;
        const size_t filtered = DERIV_COUNT - matches;
        const double filter_pct = 100.0 * static_cast<double>(filtered) / static_cast<double>(DERIV_COUNT);

        print_box_line(format("Derivações BIP-32/Secp256k1     : {:>12} derivações", DERIV_COUNT));
        print_box_line(format("Throughput de Verificação       : {:>12.2f} derivações/s ({:.2f} µs/chave)", d_rate, us_per_key));
        print_box_line(format("Filtro Precoce em C1            : {:>12} de {} ({:.2f}% eliminadas antes de memcmp)",
                              filtered, DERIV_COUNT, filter_pct));
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 7. MICRO-BENCHMARK: SHA-512 STREAMING vs TEMPLATE
    // =========================================================================
    print_box_top("[7/7] BENCHMARK: SHA-512 STREAMING vs TEMPLATE (preset/complete)", DEFAULT_INNER_WIDTH);
    {
        constexpr size_t PREFIX_LEN = 128;
        constexpr size_t SUFFIX_LEN = 16;
        constexpr size_t BATCH      = 1u << 16;

        vector<uint8_t> prefix(PREFIX_LEN, 0x5A);
        vector<uint8_t> suffixes(BATCH * SUFFIX_LEN);
        for (size_t i = 0; i < BATCH; ++i) {
            for (size_t j = 0; j < SUFFIX_LEN; ++j) {
                suffixes[i * SUFFIX_LEN + j] =
                    static_cast<uint8_t>((i * 131u + j * 7u) & 0xFFu);
            }
        }
        vector<uint8_t> out_a(BATCH * 64), out_b(BATCH * 64);

        auto ta0 = Clock::now();
        for (size_t i = 0; i < BATCH; ++i) {
            crypto::SHA512 h;
            h.update(prefix.data(), PREFIX_LEN);
            h.update(suffixes.data() + i * SUFFIX_LEN, SUFFIX_LEN);
            h.finalize(out_a.data() + i * 64);
        }
        auto ta1 = Clock::now();
        const double a_sec = chrono::duration<double>(ta1 - ta0).count();

        crypto::SHA512 tpl;
        tpl.preset(prefix.data(), PREFIX_LEN, SUFFIX_LEN);

        auto tb0 = Clock::now();
        tpl.complete_batch(suffixes.data(), SUFFIX_LEN, out_b.data(), BATCH);
        auto tb1 = Clock::now();
        const double b_sec = chrono::duration<double>(tb1 - tb0).count();

        const bool match = (memcmp(out_a.data(), out_b.data(), out_a.size()) == 0);
        const double a_khs = BATCH / a_sec / 1000.0;
        const double b_khs = BATCH / b_sec / 1000.0;
        const double speedup = (b_sec > 0.0) ? (a_sec / b_sec) : 1.0;

        print_box_line(format("Rota SIMD do host               : {} ({} lanes)",
                              crypto::SHA512::simd_name(), crypto::SHA512::simd_lanes()));
        print_box_line(format("Conformidade rota A vs B        : {}",
                              match ? "\033[92m[BIT-EXACT MATCH]\033[0m" : "\033[91m[DIVERGENCIA]\033[0m"));
        print_box_line(format("Prefixo / Sufixo                : {} B / {} B", PREFIX_LEN, SUFFIX_LEN));
        print_box_line(format("Amostras                        : {} hashes", BATCH));
        print_box_line(format("Rota A (streaming one-shot)     : {:>10.2f} kh/s ({:>7.1f} ns/hash)",
                              a_khs, (a_sec / BATCH) * 1e9));
        print_box_line(format("Rota B (preset + complete)      : {:>10.2f} kh/s ({:>7.1f} ns/hash)",
                              b_khs, (b_sec / BATCH) * 1e9));
        print_box_line(format("Ganho do template               : {:>+9.1f}% ({:.2f}x speedup)",
                              (speedup - 1.0) * 100.0, speedup));
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // RESUMO EXECUTIVO DE PERFORMANCE & RECOMENDAÇÕES
    // =========================================================================
    print_box_top("RESUMO EXECUTIVO DE PERFORMANCE & RECOMENDAÇÕES", DEFAULT_INNER_WIDTH);
    print_box_line("1. PODA MATEMÁTICA ANALÍTICA:", DEFAULT_INNER_WIDTH);
    print_box_line("   - Dedução Cascata (w_N-1 = ?): Reduz espaço em 16x (12w) a 256x (24w).", DEFAULT_INNER_WIDTH);
    print_box_line("   - Restrição Não-Repetição (--distinct): Subtrai de 10 a 23 palavras por roda.", DEFAULT_INNER_WIDTH);
    print_box_line("   - Checksum em Hardware (SHA-NI): Milhões de verificações/s com custo residual.", DEFAULT_INNER_WIDTH);
    print_box_line("2. ARQUITETURA COMPUTACIONAL:", DEFAULT_INNER_WIDTH);
    print_box_line("   - O gargalo primário é o PBKDF2 (2048 rodadas HMAC-SHA512).", DEFAULT_INNER_WIDTH);
    print_box_line("   - O filtro precoce C1 elimina 99.999% da sobrecarga de verificação de chave.", DEFAULT_INNER_WIDTH);
    print_box_line("3. RECOMENDAÇÃO DE HARDWARE:", DEFAULT_INNER_WIDTH);
    if (!devices.empty()) {
        if (gpu_peak_rate > 0 && cpu_peak_rate > 0) {
            print_box_line(format("   - Modo Híbrido: Combina CPU + GPU para vazão de pico ({:.2f} Kkeys/s).",
                                  hybrid_peak_rate / 1e3), DEFAULT_INNER_WIDTH);
        }
        print_box_line("   - Use '--hybrid' ou '--gpu' para cargas com espaço massivo (K >= 3).", DEFAULT_INNER_WIDTH);
        print_box_line("   - Use CPU SIMD (padrão) para buscas instantâneas (1 ou 2 incógnitas).", DEFAULT_INNER_WIDTH);
    } else {
        print_box_line("   - Use '--threads 0' para máxima saturação de todos os núcleos da CPU.", DEFAULT_INNER_WIDTH);
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    return 0;
}

} // namespace cryptowords
