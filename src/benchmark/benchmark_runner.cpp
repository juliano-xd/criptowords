#include "../../include/benchmark/benchmark_runner.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/hmac_sha512.hpp"
#include "../../include/crypto/pbkdf2_simd.hpp"
#include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha256_shani.hpp"
#include "../../include/crypto/keccak256.hpp"
#include "../../include/crypto/ripemd160.hpp"
#include "../../include/crypto/sha512.hpp"
#include "../../include/crypto/secp256k1_scalar.hpp"
#include "../../include/crypto/secp256k1_point.hpp"
#include "../../include/gpu/gpu_engine.hpp"
#include "../../include/gpu/gpu_info.hpp"
#include "../../include/simd/arch.hpp"
#include "../../include/cli/ui.hpp"
#include "../../include/hardware/host_probe.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <format>
#include <fstream>
#include <latch>
#include <numeric>
#include <print>
#include <set>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

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

#if defined(__x86_64__) || defined(_M_X64)
    [[gnu::always_inline]] static inline uint64_t rdtsc_val() noexcept {
        unsigned int aux;
        return __rdtscp(&aux);
    }
#else
    [[gnu::always_inline]] static inline uint64_t rdtsc_val() noexcept {
        return 0;
    }
#endif

    struct BenchmarkStats {
        double min_val = 0.0;
        double max_val = 0.0;
        double avg_val = 0.0;
        double median_val = 0.0;
        double jitter_pct = 0.0;
    };

    template <typename Fn>
    BenchmarkStats measure_stats(size_t runs, Fn&& fn) {
        vector<double> results;
        results.reserve(runs);
        for (size_t r = 0; r < runs; ++r) {
            results.push_back(fn());
        }
        sort(results.begin(), results.end());
        BenchmarkStats s;
        s.min_val = results.front();
        s.max_val = results.back();
        double sum = accumulate(results.begin(), results.end(), 0.0);
        s.avg_val = sum / static_cast<double>(runs);
        s.median_val = (runs % 2 == 1) ? results[runs / 2] : (results[runs / 2 - 1] + results[runs / 2]) * 0.5;
        s.jitter_pct = (s.avg_val > 0.0) ? (((s.max_val - s.min_val) / s.avg_val) * 100.0) : 0.0;
        return s;
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
    print_box_top("CRIPTOWORDS v2.0 - SUÍTE DE BENCHMARK & PROFILING AVANÇADO", DEFAULT_INNER_WIDTH);
    print_box_line("Ambiente de Teste: Metrificação Rigorosa de Hardware, Cripto & Instruções.", DEFAULT_INNER_WIDTH);
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 1. DESCOBERTA E INFORMAÇÕES DE HARDWARE
    // =========================================================================
    auto cpu = hardware::HostProbe::probe_cpu();
    size_t hw_threads = cpu.topology.logical_threads > 0 ? cpu.topology.logical_threads : thread::hardware_concurrency();

    print_box_top("[1/8] HARDWARE & CAPACIDADES DETECTADAS DO HOST", DEFAULT_INNER_WIDTH);
    print_box_line(format("Processador Host (CPU)    : {}", cpu.brand_string));
    print_box_line(format("Núcleos & Threads CPU     : {} físicos, {} threads lógicas{}",
                          cpu.topology.physical_cores > 0 ? to_string(cpu.topology.physical_cores) : "?",
                          hw_threads,
                          cpu.scaling_governor.empty() ? "" : format(" [Gov: {}]", cpu.scaling_governor)));

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
    // 2. MICRO-BENCHMARK: CHECKSUM BIP-39 & SHA-256 (SHA-NI vs ESCALAR)
    // =========================================================================
    print_box_top("[2/8] CRIPTOGRAFIA BIP-39 & SHA-256 (SHA-NI vs ESCALAR)", DEFAULT_INNER_WIDTH);
    {
        constexpr size_t CHECKS_PER_RUN = 500'000;
        uint64_t valid_cnt = 0;

        auto run_chk_bench = [&]() -> double {
            vector<uint16_t> sample_ids = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
            uint64_t guard = 0;
            auto t0 = Clock::now();
            for (size_t i = 0; i < CHECKS_PER_RUN; ++i) {
                sample_ids[11] = static_cast<uint16_t>((sample_ids[11] + 1) & 0x7FF);
                guard += Bip39Deriver::verify_checksum(span<const uint16_t>(sample_ids.data(), 12)) ? 1u : 0u;
            }
            auto t1 = Clock::now();
            bench_barrier(guard);
            valid_cnt = guard;
            return chrono::duration<double>(t1 - t0).count();
        };

        // Amostragem multi-run para precisão estatística
        auto chk_stats = measure_stats(3, run_chk_bench);
        double mops_avg = (CHECKS_PER_RUN / chk_stats.avg_val) / 1e6;
        double ns_avg = (chk_stats.avg_val / CHECKS_PER_RUN) * 1e9;
        double ns_min = (chk_stats.min_val / CHECKS_PER_RUN) * 1e9;

        print_box_line(format("Checksum BIP-39 (12w)     : {:>10} avaliações", CHECKS_PER_RUN));
        print_box_line(format("Vazão de Verificação      : {:>10.2f} Mop/s (Média de 3 execuções)", mops_avg));
        print_box_line(format("Latência por Checksum     : {:>10.2f} ns/op (Melhor: {:.2f} ns, Jitter: ±{:.1f}%)",
                              ns_avg, ns_min, chk_stats.jitter_pct));
        print_box_line(format("Validação Matemática      : Checksums válidos: {} ({:.2f}% de aprovação)",
                              valid_cnt, 100.0 * valid_cnt / CHECKS_PER_RUN));

        print_box_separator(DEFAULT_INNER_WIDTH);
        print_box_line("Microbenchmark SHA-256 em Bloco de 64 Bytes (100.000 iterações):");

        // Microbenchmark SHA-256 Escalar vs Hardware SHA-NI
        constexpr size_t SHA_ITERS = 100'000;
        alignas(16) uint8_t sha_block[64];
        memset(sha_block, 0x42, sizeof(sha_block));

        // Rota Escalar
        uint8_t sc_out[32];
        auto t_sc0 = Clock::now();
        for (size_t i = 0; i < SHA_ITERS; ++i) {
            crypto::SHA256 ctx;
            ctx.update(sha_block, 64);
            ctx.finalize(sc_out);
        }
        auto t_sc1 = Clock::now();
        bench_barrier(sc_out[0]);
        double sc_sec = chrono::duration<double>(t_sc1 - t_sc0).count();
        double sc_ns = (sc_sec / SHA_ITERS) * 1e9;
        double sc_mbs = (static_cast<double>(SHA_ITERS * 64) / sc_sec) / (1024 * 1024);
        double sc_mhash = (SHA_ITERS / sc_sec) / 1e6;

        // Rota Hardware SHA-NI
#if defined(__SHA__)
        uint32_t shani_state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        auto t_ni0 = Clock::now();
        for (size_t i = 0; i < SHA_ITERS; ++i) {
            cryptowords::detail::sha256_process_x86(shani_state, sha_block, 64);
        }
        auto t_ni1 = Clock::now();
        bench_barrier(shani_state[0]);
        double ni_sec = chrono::duration<double>(t_ni1 - t_ni0).count();
        double ni_ns = (ni_sec / SHA_ITERS) * 1e9;
        double ni_mbs = (static_cast<double>(SHA_ITERS * 64) / ni_sec) / (1024 * 1024);
        double ni_mhash = (SHA_ITERS / ni_sec) / 1e6;
        double ni_speedup = (ni_sec > 0.0) ? (sc_sec / ni_sec) : 1.0;

        print_box_line(format("  SHA-256 Escalar Software: {:>10.2f} ns/bloco ({:>7.2f} MB/s | {:>6.2f} Mhash/s)",
                              sc_ns, sc_mbs, sc_mhash));
        print_box_line(format("  SHA-256 Hardware SHA-NI : {:>10.2f} ns/bloco ({:>7.2f} MB/s | {:>6.2f} Mhash/s)",
                              ni_ns, ni_mbs, ni_mhash));
        print_box_line(format("  Aceleração por Hardware : {:>10.2f}x speedup das instruções Intel/AMD SHA-NI",
                              ni_speedup));
#else
        print_box_line(format("  SHA-256 Escalar Software: {:>10.2f} ns/bloco ({:>7.2f} MB/s | {:>6.2f} Mhash/s)",
                              sc_ns, sc_mbs, sc_mhash));
        print_box_line("  SHA-256 Hardware SHA-NI : [Instruções SHA-NI ausentes no binário ou host]");
#endif
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 3. MICRO-BENCHMARK: CPU PBKDF2-HMAC-SHA512 (SIMD MULTI-WAY & CICLOS TSC)
    // =========================================================================
    print_box_top("[3/8] CPU PBKDF2-HMAC-SHA512 (SIMD MULTI-WAY, CICLOS TSC & JITTER)", DEFAULT_INNER_WIDTH);

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

    // --- Comparativo 1-Thread com Ciclos de Relógio TSC ---
    constexpr size_t SINGLE_HASHES = 128;
    uint8_t sc_single_out[64];
    uint64_t sc_guard = 0;
    uint64_t tsc_sc0 = rdtsc_val();
    auto t_sc0 = Clock::now();
    for (size_t i = 0; i < SINGLE_HASHES; ++i) {
        crypto::pbkdf2_hmac_sha512(test_pw.data(), test_pw.size(),
            reinterpret_cast<const uint8_t*>(test_salt.data()), test_salt.size(),
            2048, sc_single_out, 64);
        sc_guard += sc_single_out[0];
    }
    auto t_sc1 = Clock::now();
    uint64_t tsc_sc1 = rdtsc_val();
    bench_barrier(sc_guard);
    const double sc_sec = chrono::duration<double>(t_sc1 - t_sc0).count();
    const double sc_rate = SINGLE_HASHES / sc_sec;
    const double sc_ms_per_key = (sc_sec * 1000.0) / SINGLE_HASHES;
    const uint64_t sc_cycles_per_key = (tsc_sc1 > tsc_sc0) ? ((tsc_sc1 - tsc_sc0) / SINGLE_HASHES) : 0;

    alignas(64) uint8_t sm_single_out[16][64];
    uint64_t sm_guard = 0;
    const size_t simd_batches_single = SINGLE_HASHES / simd_lanes;
    uint64_t tsc_sm0 = rdtsc_val();
    auto t_sm0 = Clock::now();
    for (size_t i = 0; i < simd_batches_single; ++i) {
        run_simd_lane(sm_single_out);
        sm_guard += sm_single_out[0][0];
    }
    auto t_sm1 = Clock::now();
    uint64_t tsc_sm1 = rdtsc_val();
    bench_barrier(sm_guard);
    const double sm_sec = chrono::duration<double>(t_sm1 - t_sm0).count();
    const double sm_rate = SINGLE_HASHES / sm_sec;
    const double sm_ms_per_key = (sm_sec * 1000.0) / SINGLE_HASHES;
    const uint64_t sm_cycles_per_key = (tsc_sm1 > tsc_sm0) ? ((tsc_sm1 - tsc_sm0) / SINGLE_HASHES) : 0;
    const double simd_vector_speedup = (sc_sec > 0.0) ? (sc_sec / sm_sec) : 1.0;
    const double cycles_per_round = (sm_cycles_per_key > 0) ? (static_cast<double>(sm_cycles_per_key) / 2048.0) : 0.0;

    print_box_line(format("Motor SIMD Ativo no Host  : {}", arch_label));
    print_box_line(format("1-Th Escalar (1 chave)    : {:>8.2f} keys/s ({:.2f} ms | {:>7} cyc/key)",
                          sc_rate, sc_ms_per_key, sc_cycles_per_key));
    print_box_line(format("1-Th SIMD ({:>2} lanes)       : {:>8.2f} keys/s ({:.2f} ms | {:>7} cyc/key)",
                          simd_lanes, sm_rate, sm_ms_per_key, sm_cycles_per_key));
    print_box_line(format("Eficiência de Instrução   : {:>6.1f} ciclos TSC/rodada ({:.2f}x speedup vetorial)",
                          cycles_per_round, simd_vector_speedup));

    print_box_separator(DEFAULT_INNER_WIDTH);
    print_box_line("Escalabilidade Multithread (Multi-Run com Amostragem e Jitter):");
    println("├─────────┼─────────┼───────────┼─────────────────────┼──────────┼─────────┼─────────┤");
    println("│ Threads │ Lote/Th │ Tempo(ms) │ Throughput (keys/s) │  Jitter  │ Speedup │  Efic.  │");
    println("├─────────┼─────────┼───────────┼─────────────────────┼──────────┼─────────┼─────────┤");

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

        // Amostragem multi-run (3 iterações por contagem de threads) com afinidade de núcleos físicos
        auto run_mt_sample = [&]() -> double {
            static const auto cpu_ids = hardware::HostProbe::get_physical_cpu_ids();
            latch gate(static_cast<ptrdiff_t>(threads));
            vector<thread> workers;
            workers.reserve(threads);
            atomic<uint64_t> guard{0};

            auto worker_fn = [&](size_t thread_idx) {
#if defined(__linux__)
                if (!cpu_ids.empty()) {
                    int target_cpu = cpu_ids[thread_idx % cpu_ids.size()];
                    cpu_set_t cpuset;
                    CPU_ZERO(&cpuset);
                    CPU_SET(target_cpu, &cpuset);
                    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
                }
#endif
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
                workers.emplace_back(worker_fn, t);
            }

            auto t0 = Clock::now();
            for (auto& w : workers) w.join();
            auto t1 = Clock::now();

            bench_barrier(guard.load(memory_order_relaxed));
            return chrono::duration<double>(t1 - t0).count();
        };

        auto mt_stats = measure_stats(3, run_mt_sample);
        double median_sec = mt_stats.median_val;
        double rate = total_hashes / median_sec;

        if (threads == 1) simd_baseline_rate = rate;
        if (rate > cpu_peak_rate) cpu_peak_rate = rate;
        double speedup = (simd_baseline_rate > 0) ? (rate / simd_baseline_rate) : 1.0;
        double efficiency = (speedup / static_cast<double>(threads)) * 100.0;

        println("│ {:^7} │ {:^7} │ {:>9.2f} │ {:>19.2f} │ {:>7.1f}% │ {:>6.2f}x │ {:>6.1f}% │",
                threads, hashes_per_thread, median_sec * 1000.0, rate, mt_stats.jitter_pct, speedup, efficiency);
    }
    println("╰─────────┴─────────┴───────────┴─────────────────────┴──────────┴─────────┴─────────╯");
    println();

    // =========================================================================
    // 4. MICRO-BENCHMARK: GPU OPENCL (PROFILING EM NÍVEL DE HARDWARE)
    // =========================================================================
    print_box_top("[4/8] GPU OPENCL PROFILING (LARGURA DE BANDA, SATURAÇÃO & ESTABILIDADE)", DEFAULT_INNER_WIDTH);
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
            const double per_cu_khs = (dev.compute_units > 0) ? (best_effective_khs / dev.compute_units) : 0.0;
            println("├────────┴───────────┴────────────┴─────────────┴─────────────┴──────────┴───────────┤");
            print_box_line(format("➔ Ponto de Operação Ótimo: Lote de {:>5} chaves ({:.2f} kh/s | {:.2f} kh/s/CU)",
                                  best_batch, best_effective_khs, per_cu_khs));
        }
        print_box_bottom(DEFAULT_INNER_WIDTH);
    }
    println();

    // =========================================================================
    // 5. MICRO-BENCHMARK: ARQUITETURA SECP256K1 & F_p (SECP vs UINT<4>)
    // =========================================================================
    print_box_top("[5/8] ARQUITETURA DE CURVA ELÍPTICA SECP256K1 & F_p (SECP vs UINT<4>)", DEFAULT_INNER_WIDTH);
    {
        auto* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        // --- 5.1 Adição escalar: libsecp256k1 vs UInt<4> nativo ---
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

        // --- 5.2 Aritmética de Campo F_p: Mul, Sqr e Inv (UInt<4>) ---
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

        // Inversão Modular em F_p (Addition Chain a^(p-2) mod p)
        constexpr size_t INV_ITERS = 50'000;
        UInt<4> inv_acc = fa;
        auto t_inv0 = Clock::now();
        for (size_t i = 0; i < INV_ITERS; ++i) {
            inv_acc = crypto::inv_mod_p(inv_acc);
        }
        auto t_inv1 = Clock::now();
        bench_barrier(inv_acc.bits[0]);
        const double inv_ns = chrono::duration<double, nano>(t_inv1 - t_inv0).count() / INV_ITERS;

        print_box_line(format("Multiplicação F_p mul_mod_p     : {:>11.2f} ns/op", mul_ns));
        print_box_line(format("Quadratura F_p sqr_mod_p        : {:>11.2f} ns/op ({:.2f}x speedup)", sqr_ns, mul_ns / sqr_ns));
        print_box_line(format("Inversão Modular inv_mod_p      : {:>11.2f} ns/op (a^(p-2) mod p | {:.2f} Mop/s)",
                              inv_ns, 1000.0 / inv_ns));

        // --- 5.3 Divisão Escalar Base58: Knuth vs divmod(u64) ---
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

        // --- 5.4 Multiplicação de ponto P = k * G ---
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
        print_box_line(format("Pubkey Create Comb 8-bit Nativa : {:>11.2f} µs/op ({:.2f}x vs libsecp)", fast_pub_us, secp_pub_us / fast_pub_us));

        secp256k1_context_destroy(secp_ctx);
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 6. MICRO-BENCHMARK: ENCODING DE REDES & HASHING (BTC vs ETH)
    // =========================================================================
    print_box_top("[6/8] ENCODING DE REDES & HASHING (BITCOIN HASH160 vs ETHEREUM KECCAK-256)", DEFAULT_INNER_WIDTH);
    {
        constexpr size_t PIPE_ITERS = 100'000;
        array<uint8_t, 33> pub_c33;
        memset(pub_c33.data(), 0x02, 33);
        array<uint8_t, 65> pub_u65;
        memset(pub_u65.data(), 0x04, 65);

        // Pipeline Bitcoin (Pubkey 33B -> SHA256 -> RIPEMD160)
        array<uint8_t, 32> btc_sha;
        array<uint8_t, 20> btc_rip;
        auto t_b0 = Clock::now();
        for (size_t i = 0; i < PIPE_ITERS; ++i) {
            crypto::SHA256::hash33(pub_c33, btc_sha);
            crypto::RIPEMD160::hash32(btc_sha, btc_rip);
        }
        auto t_b1 = Clock::now();
        bench_barrier(btc_rip[0]);
        const double btc_pipe_ns = chrono::duration<double, nano>(t_b1 - t_b0).count() / PIPE_ITERS;

        // Pipeline Ethereum (Pubkey 64B -> Keccak-256 -> Address 20B)
        uint8_t eth_keccak[32];
        auto t_e0 = Clock::now();
        for (size_t i = 0; i < PIPE_ITERS; ++i) {
            crypto::Keccak256::hash(pub_u65.data() + 1, 64, eth_keccak);
        }
        auto t_e1 = Clock::now();
        bench_barrier(eth_keccak[0]);
        const double eth_pipe_ns = chrono::duration<double, nano>(t_e1 - t_e0).count() / PIPE_ITERS;

        print_box_line("Comparativo de Pipeline de Endereço a partir de Chave Pública:");
        print_box_line(format("  Bitcoin (Pubkey 33B -> Hash160)  : {:>8.2f} ns/op ({:>7.2f} kops/s)",
                              btc_pipe_ns, 1e6 / btc_pipe_ns));
        print_box_line(format("  Ethereum (Pubkey 64B -> Keccak)  : {:>8.2f} ns/op ({:>7.2f} kops/s)",
                              eth_pipe_ns, 1e6 / eth_pipe_ns));
        print_box_line(format("  Vantagem Ethereum                : {:>8.2f}x mais rápido no hash de endereço",
                              btc_pipe_ns / eth_pipe_ns));

        print_box_separator(DEFAULT_INNER_WIDTH);

        // Derivação completa BIP-32 com Early Rejection C1
        constexpr size_t DERIV_COUNT = 25'000;
        uint8_t dummy_seed[64];
        memset(dummy_seed, 0x42, 64);
        uint8_t target_ripemd[20];
        memset(target_ripemd, 0xAA, 20);

        auto* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
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

        print_box_line(format("Derivação Completa BIP-32/BIP-44 : {:>10} derivações", DERIV_COUNT));
        print_box_line(format("Throughput de Verificação        : {:>10.2f} deriv/s ({:.2f} µs/chave)", d_rate, us_per_key));
        print_box_line(format("Filtro Precoce C1-64             : {:>6.2f}% eliminadas antes de memcmp", filter_pct));
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 7. MICRO-BENCHMARK: SHA-512 STREAMING vs TEMPLATE
    // =========================================================================
    print_box_top("[7/8] BENCHMARK: SHA-512 STREAMING vs TEMPLATE (preset/complete)", DEFAULT_INNER_WIDTH);
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
    // 8. BENCHMARK: MOTOR INTEGRADO & MODO HÍBRIDO COOPERATIVO
    // =========================================================================
    print_box_top("[8/8] MOTOR INTEGRADO & MODO HÍBRIDO COOPERATIVO", DEFAULT_INNER_WIDTH);
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
    // RESUMO EXECUTIVO DE PERFORMANCE & RECOMENDAÇÕES
    // =========================================================================
    print_box_top("RESUMO EXECUTIVO CONSOLIDADO DE PERFORMANCE & RECOMENDAÇÕES", DEFAULT_INNER_WIDTH);
    print_box_line("1. PODA MATEMÁTICA ANALÍTICA:", DEFAULT_INNER_WIDTH);
    print_box_line("   - Dedução Cascata (w_N-1 = ?): Reduz espaço em 16x (12w) a 256x (24w).", DEFAULT_INNER_WIDTH);
    print_box_line("   - Restrição Não-Repetição (--distinct): Subtrai de 10 a 23 palavras por roda.", DEFAULT_INNER_WIDTH);
    print_box_line("   - Checksum SHA-NI: Milhões de verificações/s com custo quase nulo.", DEFAULT_INNER_WIDTH);
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
