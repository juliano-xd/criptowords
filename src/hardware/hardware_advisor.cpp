#include "../../include/hardware/hardware_advisor.hpp"

#include <algorithm>
#include <format>
#include <print>

#include "../../include/cli/ui.hpp"

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

using namespace cryptowords::ui;

namespace cryptowords {
namespace hardware {

namespace {

const char* simd_name(SimdArch a) {
    switch (a) {
        case SimdArch::AVX512: return "AVX-512";
        case SimdArch::AVX2:   return "AVX2";
        case SimdArch::SSE:
        default:               return "SSE4.1";
    }
}

SimdArch choose_simd_arch(const HostProfile& host) {
    if (host.cpu.caps.avx512f) {
#ifdef CRYPTOWORDS_HAVE_AVX512
        return SimdArch::AVX512;
#elif defined(CRYPTOWORDS_HAVE_AVX2)
        return SimdArch::AVX2;
#else
        return SimdArch::SSE;
#endif
    }
    if (host.cpu.caps.avx2) {
#ifdef CRYPTOWORDS_HAVE_AVX2
        return SimdArch::AVX2;
#else
        return SimdArch::SSE;
#endif
    }
    return SimdArch::SSE;
}

uint32_t choose_thread_count(const AppConfig& cfg, const HostProfile& host, SimdArch simd) {
    if (cfg.num_threads > 0) return static_cast<uint32_t>(cfg.num_threads);

    const bool simd_wide = (simd == SimdArch::AVX2) || (simd == SimdArch::AVX512);
    if (host.cpu.topology.smt_enabled && simd_wide) {
        return host.cpu.topology.physical_cores > 0
                   ? host.cpu.topology.physical_cores
                   : 1;
    }
    return host.cpu.topology.logical_threads > 0
               ? host.cpu.topology.logical_threads
               : 1;
}

const HostGpuDevice* choose_gpu(const AppConfig& cfg, const HostProfile& host) {
    if (host.gpus.empty()) return nullptr;

    if (cfg.gpu_platform >= 0 && cfg.gpu_device >= 0) {
        for (const auto& g : host.gpus) {
            if (g.platform_idx == cfg.gpu_platform && g.device_idx == cfg.gpu_device) return &g;
        }
    }
    for (const auto& g : host.gpus) if (g.is_recommended) return &g;
    return &host.gpus.front();
}

size_t choose_gpu_workgroup(const HostGpuDevice& gpu) {
    size_t pref = gpu.preferred_work_group_multiple;
    if (pref == 0) pref = 32;

    size_t wg = 256;
    if (gpu.category == GpuCategory::Integrated || gpu.compute_units <= 4) wg = 64;
    if (wg > gpu.max_work_group) wg = gpu.max_work_group;
    wg = (wg / pref) * pref;
    if (wg == 0) wg = pref;
    return wg;
}

size_t choose_gpu_batch(const HostGpuDevice& gpu, size_t wg, const AppConfig& cfg) {
    if (cfg.gpu_batch > 0) return cfg.gpu_batch;

    size_t batch;
    if (gpu.category == GpuCategory::DiscreteHighEnd) {
        batch = gpu.compute_units * wg * 2;
        batch = std::clamp(batch, size_t(32768), size_t(65536));
    } else if (gpu.category == GpuCategory::DiscreteMidRange) {
        batch = gpu.compute_units * wg * 2;
        batch = std::clamp(batch, size_t(8192), size_t(32768));
    } else {
        batch = 512;
    }

    if (gpu.max_alloc_bytes > 0) {
        const size_t max_k = gpu.max_alloc_bytes / 256;
        if (batch > max_k) batch = max_k;
    }
    batch = ((batch + wg - 1) / wg) * wg;
    return batch;
}

size_t choose_slot_size(const AppConfig& cfg) {
    const size_t words = cfg.mnemonics.size();
    const bool is_cjk = (cfg.language == "ja" || cfg.language == "japanese" ||
                         cfg.language == "ko" || cfg.language == "korean" ||
                         cfg.language.starts_with("zh") ||
                         cfg.language.starts_with("chinese") ||
                         cfg.separator == "\xE3\x80\x80");
    if (is_cjk || words >= 21) return 512;
    if (words > 12)            return 256;
    return 128;
}

std::string describe_cpu_engine(SimdArch simd, bool has_sha_ni) {
    return std::string("CPU Nativo SIMD ") + simd_name(simd) +
           (has_sha_ni ? " + SHA-NI" : "");
}

}  // namespace

TuningStrategy HardwareAdvisor::analyze(const AppConfig& cfg, const HostProfile& host) {
    TuningStrategy strat;

    strat.chosen_simd         = choose_simd_arch(host);
    strat.use_hardware_sha_ni = host.cpu.caps.sha_ni;
    strat.use_hardware_sha512 = host.cpu.caps.intel_sha512;
    strat.recommended_threads = choose_thread_count(cfg, host, strat.chosen_simd);
    strat.enable_core_pinning = cfg.pin_cores;

    const HostGpuDevice* gpu = choose_gpu(cfg, host);
    if (gpu) {
        strat.chosen_gpu_platform   = gpu->platform_idx;
        strat.chosen_gpu_device     = gpu->device_idx;
        strat.chosen_workgroup_size = choose_gpu_workgroup(*gpu);
        strat.chosen_gpu_batch      = choose_gpu_batch(*gpu, strat.chosen_workgroup_size, cfg);
    }

    strat.chosen_slot_size = choose_slot_size(cfg);

    if (cfg.use_hybrid) {
        strat.chosen_engine = ExecutionEngineChoice::HybridParallel;
        strat.engine_desc   = std::string("Híbrido Paralelo (CPU ") + simd_name(strat.chosen_simd) +
                              " + GPU OpenCL)";
        strat.rationale =
            "Modo híbrido ativado: paralelismo heterogêneo entre threads de CPU e lotes assíncronos de GPU.";
    } else if (cfg.use_gpu) {
        const bool weak_igpu = gpu && (gpu->category == GpuCategory::Integrated ||
                                       gpu->compute_units <= 4);
        if (weak_igpu && host.cpu.topology.logical_threads >= 4 && cfg.num_threads != 1) {
            strat.chosen_engine       = ExecutionEngineChoice::HybridParallel;
            strat.recommended_threads = host.cpu.topology.logical_threads;
            strat.engine_desc = std::string("Híbrido Cooperativo Adaptativo (CPU ") +
                                simd_name(strat.chosen_simd) + " + iGPU " + gpu->device_name + ")";
            strat.rationale = "Hardware Assimétrico Detectado: A CPU (" +
                              std::to_string(host.cpu.topology.logical_threads) +
                              " threads) possui maior vazão isolada que a iGPU (" +
                              std::to_string(gpu->compute_units) +
                              " CUs). Ativado automaticamente o Caminho Híbrido Cooperativo para SOMAR "
                              "a CPU com a iGPU em vez de subutilizar o sistema.";
        } else {
            strat.chosen_engine       = ExecutionEngineChoice::GpuOpenCL;
            strat.recommended_threads = 1;
            strat.engine_desc = "GPU OpenCL Dedicada (" +
                                std::string(gpu ? gpu->device_name : "Dispositivo Auto") + ")";
            strat.rationale =
                "Aceleração GPU solicitada: fluxo contínuo de PBKDF2 em lotes de alta ocupação via OpenCL.";
        }
    } else {
        const bool auto_pick_gpu = !cfg.use_cpu && cfg.num_threads <= 1 && cfg.n_unknowns >= 2 &&
                                   gpu && gpu->is_discrete &&
                                   gpu->category == GpuCategory::DiscreteHighEnd;
        if (auto_pick_gpu) {
            strat.chosen_engine       = ExecutionEngineChoice::GpuOpenCL;
            strat.recommended_threads = 1;
            strat.engine_desc = "GPU OpenCL de Alta Performance (" + gpu->device_name + ")";
            strat.rationale = "dGPU de alta vazão detectada (" +
                              std::to_string(gpu->compute_units) +
                              " CUs/SMs) com espaço combinatório suficiente (" +
                              std::to_string(cfg.n_unknowns) + " incógnitas). Recomendado aceleração GPU.";
        } else {
            strat.chosen_engine = ExecutionEngineChoice::CpuSIMD;
            strat.engine_desc   = describe_cpu_engine(strat.chosen_simd, strat.use_hardware_sha_ni);
            strat.rationale = std::string("CPU multithread com instruções vetoriais ") +
                              simd_name(strat.chosen_simd) +
                              (strat.use_hardware_sha_ni
                                   ? " e SHA-NI em silício (~10x no checksum)"
                                   : "") +
                              " oferece a menor latência e maior vazão sustentada para este perfil.";

            const bool simd_wide = (strat.chosen_simd == SimdArch::AVX2) ||
                                   (strat.chosen_simd == SimdArch::AVX512);
            if (host.cpu.topology.smt_enabled && simd_wide) {
                strat.rationale += " [SIMD Vetorial: Alocação 1:1 por núcleo físico (" +
                                   std::to_string(strat.recommended_threads) +
                                   "T) para eliminar disputa de portas FPU/SIMD do SMT e maximizar throughput]";
            }
            if (host.cpu.topology.numa_nodes > 1) {
                strat.rationale += " [Topologia Multi-NUMA (" +
                                   std::to_string(host.cpu.topology.numa_nodes) +
                                   " nós): Core pinning ativado para retenção de afinidade de nó]";
            }
        }
    }

    return strat;
}

void HardwareAdvisor::apply_tuning(AppConfig& cfg, const TuningStrategy& strat) {
    if (strat.chosen_engine == ExecutionEngineChoice::HybridParallel) {
        cfg.use_hybrid = true;
        cfg.use_gpu = true;
    } else if (strat.chosen_engine == ExecutionEngineChoice::GpuOpenCL) {
        cfg.use_gpu = true;
        cfg.use_hybrid = false;
        if (cfg.num_threads == 0) cfg.num_threads = 1;
    }

    if (cfg.num_threads == 0) cfg.num_threads = strat.recommended_threads;
    if (cfg.gpu_batch == 0)   cfg.gpu_batch   = strat.chosen_gpu_batch;
    if (cfg.gpu_platform < 0) cfg.gpu_platform = strat.chosen_gpu_platform;
    if (cfg.gpu_device < 0)   cfg.gpu_device   = strat.chosen_gpu_device;
}

void HardwareAdvisor::print_host_report(const HostProfile& host, const TuningStrategy& strat) {
    print_box_top("DIAGNÓSTICO PROFUNDO DE HARDWARE DO HOSPEDEIRO", DEFAULT_INNER_WIDTH);

    print_box_line(std::format("Ambiente     : {} │ Compilador: {}", host.os_info, host.compiler_info),
                   DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    print_box_line(std::format("Processador  : \033[1;37m{}\033[0m ({})",
                               host.cpu.brand_string, host.cpu.vendor),
                   DEFAULT_INNER_WIDTH);

    print_box_line(std::format(
        "Microarq.    : \033[1;36m{}\033[0m │ Família: 0x{:02x} ({}) │ Modelo: 0x{:02x} ({}) │ Stepping: {}",
        host.cpu.microarch_family, host.cpu.raw_family, host.cpu.raw_family,
        host.cpu.raw_model, host.cpu.raw_model, host.cpu.raw_stepping),
        DEFAULT_INNER_WIDTH);

    print_box_line(std::format("Microcódigo  : {} │ Endereçamento: {} bits físico, {} bits virtual",
                               host.cpu.microcode.empty() ? "N/A" : host.cpu.microcode,
                               host.cpu.physical_addr_bits > 0 ? host.cpu.physical_addr_bits : 48,
                               host.cpu.virtual_addr_bits  > 0 ? host.cpu.virtual_addr_bits  : 48),
                   DEFAULT_INNER_WIDTH);

    print_box_line(std::format(
        "Topologia    : {} Núcleos Físicos │ {} Threads Lógicas (SMT: {}) │ {} Soquete(s) │ {} Nó(s) NUMA",
        host.cpu.topology.physical_cores, host.cpu.topology.logical_threads,
        (host.cpu.topology.smt_enabled ? "\033[1;32mAtivo\033[0m" : "Desativado"),
        host.cpu.topology.sockets, host.cpu.topology.numa_nodes),
        DEFAULT_INNER_WIDTH);

    if (host.cpu.topology.is_hybrid) {
        print_box_line(std::format("Arquitetura  : \033[1;33mHeterogênea Híbrida\033[0m ({} P-Cores, {} E-Cores)",
                                   host.cpu.topology.performance_cores, host.cpu.topology.efficiency_cores),
                       DEFAULT_INNER_WIDTH);
    }
    if (host.cpu.topology.cppc_active) {
        print_box_line(
            "Silício CPPC : \033[1;32mAtivo\033[0m (Collaborative Processor Performance Control - "
            "Priorização de Golden Cores)",
            DEFAULT_INNER_WIDTH);
    }

    print_box_line(std::format(
        "Frequência   : {} MHz Máx │ {} MHz Base │ Mín: {} MHz │ Atual: {} MHz",
        host.cpu.max_clock_mhz, host.cpu.base_clock_mhz, host.cpu.min_clock_mhz,
        (host.cpu.current_clock_mhz > 0 ? host.cpu.current_clock_mhz : host.cpu.max_clock_mhz)),
        DEFAULT_INNER_WIDTH);

    if (!host.cpu.scaling_governor.empty() || !host.cpu.scaling_driver.empty()) {
        print_box_line(std::format(
            "Governador   : {} ({}) │ EPP: {} │ Boost (CPB/Turbo): {}",
            (host.cpu.scaling_governor.empty() ? "padrão" : host.cpu.scaling_governor),
            (host.cpu.scaling_driver.empty()   ? "nativo" : host.cpu.scaling_driver),
            (host.cpu.epp_preference.empty()   ? "N/A"    : host.cpu.epp_preference),
            (host.cpu.caps.cpb_boost ? "\033[1;32mHabilitado\033[0m" : "N/A")),
            DEFAULT_INNER_WIDTH);
    }

    print_box_line(std::format(
        "Hierarquia L1: L1d: {} KB ({} vias, {} sets, x{}) │ L1i: {} KB ({} vias, x{}) │ Linha: {}B",
        host.cpu.cache.l1d_bytes / 1024, host.cpu.cache.l1d_ways, host.cpu.cache.l1d_sets,
        host.cpu.cache.l1d_instances, host.cpu.cache.l1i_bytes / 1024,
        host.cpu.cache.l1i_ways, host.cpu.cache.l1d_instances, host.cpu.cache.cache_line_size),
        DEFAULT_INNER_WIDTH);

    print_box_line(std::format(
        "Hierarquia L2/3: L2: {} KB ({} vias, {} sets, x{}) │ L3: {} MB ({} vias, {} sets)",
        host.cpu.cache.l2_bytes / 1024, host.cpu.cache.l2_ways, host.cpu.cache.l2_sets,
        host.cpu.cache.l2_instances, host.cpu.cache.l3_bytes / (1024 * 1024),
        host.cpu.cache.l3_ways, host.cpu.cache.l3_sets),
        DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    print_box_line("\033[1;37mEXTENSÕES DE INSTRUÇÃO E CAPACIDADES DE SILÍCIO (CPUID):\033[0m",
                   DEFAULT_INNER_WIDTH);

    std::string simds;
    if (host.cpu.caps.avx512f) simds += "\033[1;32mAVX-512(F/BW/VL)\033[0m ";
    if (host.cpu.caps.avx10)   simds += "[AVX10] ";
    if (host.cpu.caps.avx2)    simds += "\033[1;33mAVX2\033[0m ";
    if (host.cpu.caps.avx)     simds += "AVX ";
    if (host.cpu.caps.sse42)   simds += "SSE4.2 ";
    if (host.cpu.caps.sse41)   simds += "SSE4.1 ";
    print_box_line(std::format("  ├─ SIMD / Vetorial: {}", simds.empty() ? "Básico" : simds),
                   DEFAULT_INNER_WIDTH);

    std::string cryptos;
    if (host.cpu.caps.sha_ni)       cryptos += "\033[1;32m[SHA-NI Silício (SHA-256)]\033[0m ";
    if (host.cpu.caps.intel_sha512) cryptos += "\033[1;32m[Intel SHA-512 Silício]\033[0m ";
    if (host.cpu.caps.aes_ni)       cryptos += "AES-NI ";
    print_box_line(std::format("  ├─ Criptografia   : {}",
                               cryptos.empty() ? "Nenhuma extensão dedicada" : cryptos),
                   DEFAULT_INNER_WIDTH);

    std::string bits;
    if (host.cpu.caps.bmi2)   bits += "\033[1;33mBMI2(RORX/PDEP)\033[0m ";
    if (host.cpu.caps.bmi1)   bits += "BMI1 ";
    if (host.cpu.caps.movbe)  bits += "\033[1;32mMOVBE(Byte-Swap)\033[0m ";
    if (host.cpu.caps.popcnt) bits += "POPCNT ";
    if (host.cpu.caps.adx)    bits += "ADX ";
    if (host.cpu.caps.clzero) bits += "\033[1;32mCLZERO(64B/ciclo)\033[0m ";
    print_box_line(std::format("  └─ Aritmética/Bit : {}", bits.empty() ? "Padrão" : bits),
                   DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    print_box_line(std::format("Memória Host : {} MB Total │ {} MB Livre │ Hugepages 1GB: {} │ THP: {}",
                               host.memory.total_ram_bytes / (1024 * 1024),
                               host.memory.available_ram_bytes / (1024 * 1024),
                               (host.cpu.caps.hugepages_1gb
                                    ? "\033[1;32mSuportado (PDPE1GB)\033[0m"
                                    : "Não suportado"),
                               host.cpu.thp_status.empty() ? "N/A" : host.cpu.thp_status),
                   DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    if (host.gpus.empty()) {
        print_box_line("Dispositivos GPU: Nenhum dispositivo OpenCL detectado.", DEFAULT_INNER_WIDTH);
    } else {
        print_box_line(std::format("Dispositivos GPU Detectados ({}) :", host.gpus.size()),
                       DEFAULT_INNER_WIDTH);
        for (size_t i = 0; i < host.gpus.size(); ++i) {
            const auto& g = host.gpus[i];
            std::string badge = g.is_recommended ? " \033[1;32m★ [RECOMENDADO]\033[0m" : "";
            print_box_line(
                std::format("  \033[1;37m[Plat {}, Dev {}]\033[0m \033[1;36m{}\033[0m ({}){}",
                            g.platform_idx, g.device_idx, g.device_name, g.category_str, badge),
                DEFAULT_INNER_WIDTH);
            print_box_line(
                std::format("     ├─ CUs: {:<3} │ Clock: {:<4} MHz │ VRAM: {:<5} MB │ Warp/Wave: {:<2}",
                            g.compute_units, g.clock_freq_mhz, g.global_mem_bytes / (1024 * 1024),
                            g.preferred_work_group_multiple),
                DEFAULT_INNER_WIDTH);
            print_box_line(
                std::format("     └─ Driver: {:<20} │ Max WorkGroup: {:<4} │ Compute Index: {:.1f}",
                            g.driver_version, g.max_work_group, g.compute_index),
                DEFAULT_INNER_WIDTH);
        }
    }
    print_box_separator(DEFAULT_INNER_WIDTH);

    print_box_line("\033[1;32mORQUESTRAÇÃO E AUTO-TUNING RECOMENDADO PARA ESTE HOST:\033[0m",
                   DEFAULT_INNER_WIDTH);
    print_box_line(std::format("  ├─ Motor Ideal   : \033[1;33m{}\033[0m", strat.engine_desc),
                   DEFAULT_INNER_WIDTH);
    print_box_line(std::format("  ├─ Threads CPU   : {} workers com Afinidade Física (Core Pinning: {})",
                               strat.recommended_threads,
                               (strat.enable_core_pinning ? "\033[1;32mSim\033[0m" : "Não")),
                   DEFAULT_INNER_WIDTH);

    if (strat.chosen_gpu_platform >= 0) {
        print_box_line(
            std::format("  ├─ Ajuste GPU    : Batch {} chaves │ WorkGroup {} threads │ Buffer slot {} B",
                        format_num(static_cast<double>(strat.chosen_gpu_batch)),
                        strat.chosen_workgroup_size, strat.chosen_slot_size),
            DEFAULT_INNER_WIDTH);
    }

    print_box_line(std::format("  └─ Diagnóstico   : {}", strat.rationale), DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    print_box_line("\033[1;36mAPROVEITAMENTO DAS CAPACIDADES DA CPU NO CRIPTOWORDS:\033[0m",
                   DEFAULT_INNER_WIDTH);
    print_box_line(
        std::format("  ├─ Checksum BIP-39 : {}",
                    (host.cpu.caps.sha_ni
                         ? "\033[1;32mAcelerado por SHA-NI em silício (~70 ciclos/bloco)\033[0m"
                         : "Emulação vetorial por software")),
        DEFAULT_INNER_WIDTH);
    print_box_line(
        std::format("  ├─ PBKDF2 SHA-512  : {}",
                    (host.cpu.caps.intel_sha512
                         ? "\033[1;32mAcelerado por Intel SHA-512 nativo em silício\033[0m"
                         : (host.cpu.caps.avx512f
                                ? "\033[1;33mVetorização AVX-512 (8 sementes/vetor) em registradores ZMM\033[0m"
                                : (host.cpu.caps.avx2
                                       ? "\033[1;33mVetorização AVX2 (4 sementes/vetor) + FMA3 + RORX (BMI2)\033[0m"
                                       : "Vetorização SSE4.1 (2 sementes/vetor)")))),
        DEFAULT_INNER_WIDTH);
    print_box_line(
        std::format("  ├─ Endereço/Tokens : {}",
                    (host.cpu.caps.movbe
                         ? "\033[1;32mMOVBE Big-Endian Swap em 1 ciclo (Zero Latência)\033[0m"
                         : "Bitshift convencional")),
        DEFAULT_INNER_WIDTH);
    print_box_line(
        std::format("  ├─ Caches e Buffers: {}",
                    (host.cpu.caps.clzero
                         ? "\033[1;32mCLZERO ativado (Sanitização imediata de 64B no L1d)\033[0m"
                         : "Vetor de inicialização em cache L1d")),
        DEFAULT_INNER_WIDTH);
    print_box_line(
        std::format("  ├─ Aritmética BMI  : {}",
                    (host.cpu.caps.bmi2
                         ? "\033[1;32mBMI2 RORX/PDEP (Rotações sem dependência de flags)\033[0m"
                         : "Instruções escalares padrão")),
        DEFAULT_INNER_WIDTH);
    print_box_line(
        std::format("  └─ Topologia/Cores : {}",
                    (strat.enable_core_pinning
                         ? "\033[1;32mCore Pinning Físico Ativo (Previne migração de cache L1/L2)\033[0m"
                         : "Escalonamento dinâmico pelo SO")),
        DEFAULT_INNER_WIDTH);

    print_box_bottom(DEFAULT_INNER_WIDTH);
}

void HardwareAdvisor::print_tuning_summary(const TuningStrategy& strat, bool quiet) {
    if (quiet) return;
    std::string line = std::format(
        " [Auto-Tuning] Motor: \033[1;33m{}\033[0m │ Threads: {} │ Lote GPU: {} chaves",
        strat.engine_desc, strat.recommended_threads,
        (strat.chosen_gpu_platform >= 0
             ? format_num(static_cast<double>(strat.chosen_gpu_batch))
             : "N/A"));
    std::println("{}", line);
}

}  // namespace hardware
}  // namespace cryptowords
