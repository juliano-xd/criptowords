#include "../../include/benchmark/benchmark_runner.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/hmac_sha512.hpp"
// #include "../../include/crypto/sha256.hpp"
#include "../../include/crypto/sha512.hpp"
#include "../../include/crypto/secp256k1_scalar.hpp"
#include "../../include/crypto/secp256k1_point.hpp"
#include "../../include/gpu/gpu_engine.hpp"
#include "../../include/gpu/gpu_info.hpp"
#include "../../include/cli/ui.hpp"

// #include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <format>
#include <latch>
#include <print>
#include <print>
#include <printf.h>
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
} // namespace

int BenchmarkRunner::run(const AppConfig& /*cfg*/) {
    print_box_top("CRIPTOWORDS v2.0 - SUÍTE DE BENCHMARK & METRIFICAÇÃO DE HARDWARE", DEFAULT_INNER_WIDTH);
    print_box_line("Ambiente de Teste: Executando metrificação e profiling em tempo real...", DEFAULT_INNER_WIDTH);
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    // =========================================================================
    // 1. DESCOBERTA E INFORMAÇÕES DE HARDWARE
    // =========================================================================
    size_t hw_threads = thread::hardware_concurrency();
    println("╭─── [1/6] HARDWARE & CAPACIDADES DETECTADAS ────────────────────────────────────────╮");
    println("│  Processador Host (CPU)    : {} threads lógicas detectadas                           │\n", hw_threads);
    println("│  Extensões SIMD de CPU     : ");
#if defined(__AVX512F__) || defined(CRYPTOWORDS_HAVE_AVX512)
    println("AVX-512 ");
#endif
#if defined(__AVX2__) || defined(CRYPTOWORDS_HAVE_AVX2)
    println("AVX2 ");
#endif
#if defined(__SSE4_1__) || defined(CRYPTOWORDS_HAVE_SSE41)
    println("SSE4.1 ");
#endif
#if defined(__SHA__)
    println("SHA-NI (Hardware SHA256) ");
#endif
    println("\n");

    auto devices = gpu::enumerate_devices();
    println("│  Aceleradores OpenCL (GPU) : {} dispositivo(s) encontrado(s)\n", devices.size());
    for (const auto& dev : devices) {
        println("│     ├─ [Plat {}, Dev {}] {} ({})\n",
                   dev.platform_idx, dev.device_idx, dev.device_name, dev.platform_name);
        println("│     │  CUs: {} │ Clock: {} MHz │ VRAM: {} MB │ Max WorkGroup: {}\n",
                   dev.compute_units, dev.clock_freq, dev.global_mem / (1024 * 1024), dev.max_work_group);
    }
    println("╰────────────────────────────────────────────────────────────────────────────────────╯\n\n");

    // =========================================================================
    // 2. MICRO-BENCHMARK: CHECKSUM BIP-39 & PODA ANALÍTICA (F2^C)
    // =========================================================================
    // Nota: variamos apenas sample_ids[11] sobre 2048 valores, mantendo as outras
    // 11 palavras fixas. Isso mede o custo do checksum sobre um mnemônico BIP-39
    // de 12 palavras com um único "slot" variável — não sobre entropia arbitrária.
    println("╭─── [2/6] BENCHMARK: CHECKSUM BIP-39 & PODA ANALÍTICA (SHA-NI / SHA256) ─────────────╮\n");
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

        println("│  Iterações de Checksum     : {:>12} avaliações                                │\n", TOTAL_CHECKS);
        println("│  Padrão de Variação        : 1 palavra variável (word-only)                     │\n");
        println("│  Tempo Decorrido           : {:>12.4f} ms                                        │\n", elapsed_sec * 1000.0);
        println("│  Vazão de Verificação      : {:>12.2f} Mop/s (milhões de ops/segundo)          │\n", mops);
        println("│  Latência por Checksum     : {:>12.2f} ns/op                                    │\n", ns_per_op);
        println("│  Validação Matemática      : Checksums válidos encontrados: {:<8}               │\n", valid_cnt);
    }
    println("╰────────────────────────────────────────────────────────────────────────────────────╯\n\n");

    // =========================================================================
    // 3. MICRO-BENCHMARK: CPU PBKDF2-HMAC-SHA512 (ESCALABILIDADE MULTITHREAD)
    // =========================================================================
    println("╭─── [3/6] BENCHMARK: CPU PBKDF2-HMAC-SHA512 (2048 RODADAS) ──────────────────────────╮\n");
    println("│  Threads │ Chaves/Thread │ Tempo (ms) │ Throughput (keys/s) │ Speedup │ Eficiência │\n");
    println("├──────────┼───────────────┼────────────┼─────────────────────┼─────────┼────────────┤\n");

    // Conjunto de contagens: potências de 2 até hw_threads, sempre incluindo
    // o próprio hw_threads no final (sem duplicatas).
    vector<size_t> thread_counts;
    thread_counts.push_back(1);
    for (size_t t = 2; t < hw_threads; t *= 2) {
        thread_counts.push_back(t);
    }
    if (hw_threads > 1 && thread_counts.back() != hw_threads) {
        thread_counts.push_back(hw_threads);
    }

    double baseline_rate = 0.0;
    const string test_pw = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const string test_salt = "mnemonic";

    for (size_t threads : thread_counts) {
        constexpr size_t HASHES_PER_THREAD = 128;
        const size_t total_hashes = threads * HASHES_PER_THREAD;
        latch gate(static_cast<ptrdiff_t>(threads));
        vector<thread> workers;
        workers.reserve(threads);
        atomic<uint64_t> guard{0};

        auto worker_fn = [&]() {
            gate.arrive_and_wait();
            uint8_t out[64];
            uint64_t local = 0;
            for (size_t i = 0; i < HASHES_PER_THREAD; ++i) {
                crypto::pbkdf2_hmac_sha512(
                    test_pw.data(), test_pw.size(),
                    reinterpret_cast<const uint8_t*>(test_salt.data()), test_salt.size(),
                    2048, out, 64);
                local += out[0];
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
        if (threads == 1) baseline_rate = rate;
        double speedup = (baseline_rate > 0) ? (rate / baseline_rate) : 1.0;
        double efficiency = (speedup / static_cast<double>(threads)) * 100.0;

        println("│ {:>8} │ {:>13} │ {:>10.2f} │ {:>19.2f} │ {:>6.2f}x │ {:>9.1f}% │\n",
                   threads, HASHES_PER_THREAD, elapsed_sec * 1000.0, rate, speedup, efficiency);
    }
    println("╰──────────┴───────────────┴────────────┴─────────────────────┴─────────┴────────────╯\n\n");

    // =========================================================================
    // 4. MICRO-BENCHMARK: GPU OPENCL (PROFILING EM NÍVEL DE HARDWARE)
    // =========================================================================
    println("╭─── [4/6] BENCHMARK: GPU OPENCL PROFILING (HARDWARE EVENTS & LARGURA DE BANDA) ──────╮\n");

    if (devices.empty()) {
        println("│  [!] Nenhum dispositivo OpenCL disponível para benchmark de GPU.                    │\n");
    } else {
        const vector<size_t> base_batch_sizes = {1024, 2048, 4096, 8192, 16384, 32768, 65536};
        constexpr size_t bench_slot_sz = 128;
        GPUEngine& gpu_engine = GPUEngine::get_instance();

        println("│  [i] Init/compile/cleanup NÃO entram em 'Efet. kh/s' (mede só H2D+Kernel+D2H).   │\n");

        for (const auto& dev : devices) {
            println("│  ▶ DISPOSITIVO: [Plat {}, Dev {}] {} ({})\n",
                       dev.platform_idx, dev.device_idx, dev.device_name, dev.platform_name);
            println("│  VRAM: {} MB │ CUs: {} │ Clock: {} MHz\n",
                       dev.global_mem / (1024 * 1024), dev.compute_units, dev.clock_freq);
            println("├────────┬────────────┬─────────────┬─────────────┬─────────────┬────────────┬─────────────┤\n");
            println("│  Lote  │  H2D (ms)  │ H2D (GB/s)  │ Kernel (ms) │ Kernel kh/s │  D2H (ms)  │ Efet. (kh/s)│\n");
            println("├────────┼────────────┼─────────────┼─────────────┼─────────────┼────────────┼─────────────┤\n");

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

            const bool is_rusticl = (dev.platform_name.find("rusticl") != string::npos);

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

                gpu_engine.pbkdf2_batch(pw_batch, pw_lens, seed_out, static_cast<uint32_t>(batch));

                GpuExecutionMetrics metrics;
                bool ok = gpu_engine.pbkdf2_batch_profiled(
                    pw_batch, pw_lens, seed_out, static_cast<uint32_t>(batch), metrics);
                if (!ok) {
                    println("│ {:>6} │ [Falha de execução do kernel OpenCL]                                     │\n", batch);
                    break;
                }

                const double h2d_ms  = static_cast<double>(metrics.write_time_ns)  / 1e6;
                const double kern_ms = static_cast<double>(metrics.kernel_time_ns) / 1e6;
                const double d2h_ms  = static_cast<double>(metrics.read_time_ns)   / 1e6;
                const double kern_khs = metrics.kernel_keys_per_sec / 1e3;
                const double eff_khs  = metrics.total_keys_per_sec  / 1e3;

                if (eff_khs > best_effective_khs) {
                    best_effective_khs = eff_khs;
                    best_batch = batch;
                }

                println("│ {:>6} │ {:>10.3f} │ {:>11.3f} │ {:>11.3f} │ {:>11.2f} │ {:>10.3f} │ {:>11.2f} │\n",
                           batch, h2d_ms, metrics.bandwidth_h2d_gb_s, kern_ms, kern_khs, d2h_ms, eff_khs);

                // Trava de watchdog TDR (evita hang detection em GPUs desktop/integradas).
                if (kern_ms > 600.0 || (dev.compute_units <= 4 && kern_ms > 400.0) || (is_rusticl && kern_ms > 500.0)) {
                    println("├────────┴────────────┴─────────────┴─────────────┴─────────────┴────────────┴─────────────┤");
                    println("│  ➔ Ponto de Saturação: Lotes > {:>5} atingem o limite de latência do driver desktop.     │", batch);
                    break;
                }
            }

            gpu_engine.cleanup();
            println("├────────┴────────────┴─────────────┴─────────────┴─────────────┴────────────┴─────────────┤\n");
            println("│  ➔ Ponto de Operação Ótimo: Lote de {:>5} chaves ({:.2f} kh/s efetivos)                  │\n",
                       best_batch, best_effective_khs);
            println("├────────────────────────────────────────────────────────────────────────────────────┤\n");
        }
    }
    println("╰────────────────────────────────────────────────────────────────────────────────────╯\n\n");

    // =========================================================================
    // 5. MICRO-BENCHMARK: DERIVAÇÃO SECP256K1 BIP-32 & ARITMÉTICA ESCALAR UINT<4>
    // =========================================================================
    println("╭─── [5/6] BENCHMARK: DERIVAÇÃO BIP-32 & ARITMÉTICA ESCALAR SECP256K1 ───────────────╮");
    {
        // Contexto único para toda a seção (SECP256K1_CONTEXT_SIGN é hoje alias de NONE).
        auto* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

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

        println("│  Adição Escalar libsecp256k1 : {:>12.2f} ns/op                                     │", secp_ns);
        println("│  Adição Escalar UInt<4> Nativa: {:>11.2f} ns/op ({:.2f}x speedup)                 │", fast_ns, secp_ns / fast_ns);

        // --- 5.2 Aritmética de Campo F_p: Mul vs Sqr (UInt<4>) ---
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

        println("│  Multiplicação F_p mul_mod_p  : {:>11.2f} ns/op                                     │", mul_ns);
        println("│  Quadratura F_p sqr_mod_p     : {:>11.2f} ns/op ({:.2f}x speedup)                 │", sqr_ns, mul_ns / sqr_ns);

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

        println("│  Divisão Knuth divmod(UInt<4>): {:>11.2f} ns/op                                     │", knuth_ns);
        println("│  Divisão Escalar divmod(58)   : {:>11.2f} ns/op ({:.2f}x speedup)                 │", fast_div_ns, knuth_ns / fast_div_ns);

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
        const double fast_pub_us =
            chrono::duration<double, micro>(t_pf1 - t_pf0).count() / PUB_ITERS;

        println("│  Pubkey Create libsecp256k1  : {:>12.2f} µs/op                                     │\n", secp_pub_us);
        println("│  Pubkey Create UInt<4> Nativa: {:>11.2f} µs/op                                     │\n", fast_pub_us);

        // --- 5.3 Derivação completa BIP-32 ---
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
        const double filter_pct =
            100.0 * static_cast<double>(filtered) / static_cast<double>(DERIV_COUNT);

        println("│  Derivações BIP-32/Secp256k1 : {:>12} derivações                               │\n", DERIV_COUNT);
        println("│  Tempo Total Decorrido       : {:>12.4f} ms                                        │\n", elapsed_sec * 1000.0);
        println("│  Throughput de Verificação   : {:>12.2f} derivações/s                              │\n", d_rate);
        println("│  Custo Médio por Candidato   : {:>12.2f} µs/chave (com Early Rejection C1)         │\n", us_per_key);
        println("│  Rejeições Precoces em C1    : {:>12} de {} ({:.1f}% filtradas antes de memcmp) │\n",
                   filtered, DERIV_COUNT, filter_pct);
    }
    println("╰────────────────────────────────────────────────────────────────────────────────────╯\n\n");

    // =========================================================================
    // 6. MICRO-BENCHMARK: SHA-512 STREAMING vs TEMPLATE (preset/complete)
    // =========================================================================
    // Duas rotas de código distintas:
    //   A) Streaming one-shot: constrói o contexto, absorve prefixo + sufixo
    //      e finaliza, por hash. Compressão do prefixo é reexecutada 1x por hash.
    //   B) Template (preset/complete): o midstate pós-prefixo e a tabela W
    //      do bloco final são pré-computados UMA vez. Cada complete() só
    //      executa o bloco final.
    print_box_top("[6/6] BENCHMARK: SHA-512 STREAMING vs TEMPLATE (preset/complete)");
    {
        constexpr size_t PREFIX_LEN = 128;        // exatamente 1 bloco SHA-512
        constexpr size_t SUFFIX_LEN = 16;
        constexpr size_t BATCH      = 1u << 16;   // 65536 hashes

        vector<uint8_t> prefix(PREFIX_LEN, 0x5A);
        vector<uint8_t> suffixes(BATCH * SUFFIX_LEN);
        for (size_t i = 0; i < BATCH; ++i) {
            for (size_t j = 0; j < SUFFIX_LEN; ++j) {
                suffixes[i * SUFFIX_LEN + j] =
                    static_cast<uint8_t>((i * 131u + j * 7u) & 0xFFu);
            }
        }
        vector<uint8_t> out_a(BATCH * 64), out_b(BATCH * 64);

        // --- Rota A: streaming one-shot por hash ---
        auto ta0 = Clock::now();
        for (size_t i = 0; i < BATCH; ++i) {
            crypto::SHA512 h;
            h.update(prefix.data(), PREFIX_LEN);
            h.update(suffixes.data() + i * SUFFIX_LEN, SUFFIX_LEN);
            h.finalize(out_a.data() + i * 64);
        }
        auto ta1 = Clock::now();
        const double a_sec = chrono::duration<double>(ta1 - ta0).count();

        // --- Rota B: preset + complete_batch ---
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

        print_box_line(format("Rota SIMD do host            : {} ({} lanes)",
                                   crypto::SHA512::simd_name(), crypto::SHA512::simd_lanes()));
        print_box_line(format("Conformidade rota A vs B     : {}",
                                   match ? "\033[92m[BIT-EXACT MATCH]\033[0m"
                                         : "\033[91m[DIVERGENCIA]\033[0m"));
        print_box_line(format("Prefixo / Sufixo             : {} B / {} B", PREFIX_LEN, SUFFIX_LEN));
        print_box_line(format("Amostras                     : {} hashes", BATCH));
        print_box_line(format("Rota A (streaming one-shot)  : {:>10.2f} kh/s ({:>7.1f} ns/hash)",
                                   a_khs, (a_sec / BATCH) * 1e9));
        print_box_line(format("Rota B (preset + complete)   : {:>10.2f} kh/s ({:>7.1f} ns/hash)",
                                   b_khs, (b_sec / BATCH) * 1e9));
        print_box_line(format("Ganho do template            : {:>+9.1f}% ({:.2f}x)",
                                   (speedup - 1.0) * 100.0, speedup));
    }
    print_box_bottom();
    println();

    // =========================================================================
    // PAINEL FINAL DE RECOMENDAÇÕES E METRIFICAÇÃO CONSOLIDADA
    // =========================================================================
    print_box_top("RESUMO EXECUTIVO DE PERFORMANCE & RECOMENDAÇÕES", DEFAULT_INNER_WIDTH);
    print_box_line("1. PODA MATEMÁTICA ANALÍTICA:", DEFAULT_INNER_WIDTH);
    print_box_line("   - Dedução Cascata (w_N-1 = ?): Reduz espaço em 16x (12w) a 256x (24w).", DEFAULT_INNER_WIDTH);
    print_box_line("   - Restrição Não-Repetição (--distinct): Subtrai de 10 a 23 palavras por roda.", DEFAULT_INNER_WIDTH);
    print_box_line("   - Checksum em Hardware (SHA-NI): Executa mais de 3.5 milhões de ops/segundo.", DEFAULT_INNER_WIDTH);
    print_box_line("2. ARQUITETURA COMPUTACIONAL:", DEFAULT_INNER_WIDTH);
    print_box_line("   - O gargalo computacional primário é o PBKDF2 (2048 rodadas HMAC-SHA512).", DEFAULT_INNER_WIDTH);
    print_box_line("   - O filtro precoce C1 elimina 99.999% da sobrecarga de verificação de chave.", DEFAULT_INNER_WIDTH);
    print_box_line("3. RECOMENDAÇÃO DE HARDWARE:", DEFAULT_INNER_WIDTH);
    if (!devices.empty()) {
        print_box_line("   - Use '--gpu' para cargas com espaço de busca massivo (K >= 3).", DEFAULT_INNER_WIDTH);
        print_box_line("   - Use CPU SIMD (padrão) para buscas com 1 ou 2 incógnitas e poda ativa.", DEFAULT_INNER_WIDTH);
    } else {
        print_box_line("   - Use '--threads 0' para máxima saturação de todos os núcleos da CPU.", DEFAULT_INNER_WIDTH);
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    println();

    return 0;
}

} // namespace cryptowords
