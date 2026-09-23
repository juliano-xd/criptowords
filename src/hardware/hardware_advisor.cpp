#include "../../include/hardware/hardware_advisor.hpp"
#include "../../include/cli/ui.hpp"

#include <print>
#include <format>
#include <algorithm>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

using namespace cryptowords::ui;

namespace cryptowords {
namespace hardware {

TuningStrategy HardwareAdvisor::analyze(const AppConfig& cfg, const HostProfile& host) {
    TuningStrategy strat;

    // 1. Seleção de Arquitetura SIMD
    if (host.cpu.caps.avx512f) {
#ifdef CRYPTOWORDS_HAVE_AVX512
        strat.chosen_simd = SimdArch::AVX512;
#elif defined(CRYPTOWORDS_HAVE_AVX2)
        strat.chosen_simd = SimdArch::AVX2;
#else
        strat.chosen_simd = SimdArch::SSE;
#endif
    } else if (host.cpu.caps.avx2) {
#ifdef CRYPTOWORDS_HAVE_AVX2
        strat.chosen_simd = SimdArch::AVX2;
#else
        strat.chosen_simd = SimdArch::SSE;
#endif
    } else {
        strat.chosen_simd = SimdArch::SSE;
    }

    // 2. Aceleração de Checksum e Criptografia em Silício
    strat.use_hardware_sha_ni = host.cpu.caps.sha_ni;
    strat.use_hardware_sha512 = host.cpu.caps.intel_sha512;

    // 3. Alocação de Threads de CPU
    if (cfg.num_threads > 0) {
        strat.recommended_threads = cfg.num_threads;
    } else {
        // Se a CPU tiver 16 ou mais núcleos físicos e estiver executando com AVX-512,
        // alocar 1 thread por núcleo físico evita a disputa de portas de execução ZMM de 512 bits
        // e previne throttling térmico / clock downclock do SMT.
        if (host.cpu.topology.physical_cores >= 16 && strat.chosen_simd == SimdArch::AVX512) {
            strat.recommended_threads = host.cpu.topology.physical_cores;
        } else {
            // Modo Auto geral: usar todas as threads lógicas com afinidade de silício (core pinning)
            strat.recommended_threads = host.cpu.topology.logical_threads > 0 ? host.cpu.topology.logical_threads : 1;
        }
    }
    strat.enable_core_pinning = cfg.pin_cores;

    // 4. Seleção e Sintonia de GPU
    const HostGpuDevice* best_gpu = nullptr;
    if (!host.gpus.empty()) {
        if (cfg.gpu_platform >= 0 && cfg.gpu_device >= 0) {
            for (const auto& g : host.gpus) {
                if (g.platform_idx == cfg.gpu_platform && g.device_idx == cfg.gpu_device) {
                    best_gpu = &g;
                    break;
                }
            }
        }
        if (!best_gpu) {
            for (const auto& g : host.gpus) {
                if (g.is_recommended) {
                    best_gpu = &g;
                    break;
                }
            }
        }
        if (!best_gpu) best_gpu = &host.gpus.front();
    }

    if (best_gpu) {
        strat.chosen_gpu_platform = best_gpu->platform_idx;
        strat.chosen_gpu_device = best_gpu->device_idx;

        // Workgroup Size: múltiplo preferido de warp/wavefront
        size_t pref = best_gpu->preferred_work_group_multiple;
        if (pref == 0) pref = 32;
        size_t wg = 256;
        if (wg > best_gpu->max_work_group) wg = best_gpu->max_work_group;
        wg = (wg / pref) * pref;
        if (wg == 0) wg = pref;
        strat.chosen_workgroup_size = wg;

        // GPU Batch Size adaptativo:
        if (cfg.gpu_batch > 0) {
            strat.chosen_gpu_batch = cfg.gpu_batch;
        } else {
            // Dimensionamento para streaming double-buffering com sobreposição 100% CPU/GPU
            size_t batch = best_gpu->compute_units * strat.chosen_workgroup_size * 2;
            if (best_gpu->category == GpuCategory::DiscreteHighEnd) {
                batch = std::clamp(batch, size_t(32768), size_t(65536));
            } else if (best_gpu->category == GpuCategory::DiscreteMidRange) {
                batch = std::clamp(batch, size_t(16384), size_t(32768));
            } else { // iGPU ou Entry
                batch = std::clamp(batch, size_t(8192), size_t(16384));
            }
            if (best_gpu->max_alloc_bytes > 0) {
                size_t max_k = best_gpu->max_alloc_bytes / 256;
                if (batch > max_k) batch = max_k;
            }
            // Alinhamento com o Workgroup
            batch = ((batch + strat.chosen_workgroup_size - 1) / strat.chosen_workgroup_size) * strat.chosen_workgroup_size;
            strat.chosen_gpu_batch = batch;
        }
    }

    // Slot size de strings
    size_t words = cfg.mnemonics.size();
    bool is_cjk = (cfg.language == "ja" || cfg.language == "japanese" ||
                   cfg.language == "ko" || cfg.language == "korean" ||
                   cfg.language.starts_with("zh") || cfg.language.starts_with("chinese") ||
                   cfg.separator == "\xE3\x80\x80");
    if (is_cjk || words >= 21) {
        strat.chosen_slot_size = 512;
    } else if (words > 12) {
        strat.chosen_slot_size = 256;
    } else {
        strat.chosen_slot_size = 128;
    }

    // 5. Decisão de Motor de Execução
    if (cfg.use_hybrid) {
        strat.chosen_engine = ExecutionEngineChoice::HybridParallel;

        strat.engine_desc = "Híbrido Paralelo (CPU " + std::string(strat.chosen_simd == SimdArch::AVX512 ? "AVX-512" : (strat.chosen_simd == SimdArch::AVX2 ? "AVX2" : "SSE")) + " + GPU OpenCL)";
        strat.rationale = "Modo híbrido ativado: paralelismo heterogêneo entre threads de CPU e lotes assíncronos de GPU.";
    } else if (cfg.use_gpu) {
        strat.chosen_engine = ExecutionEngineChoice::GpuOpenCL;
        strat.engine_desc = "GPU OpenCL Dedicada (" + (best_gpu ? best_gpu->device_name : "Dispositivo Auto") + ")";
        strat.rationale = "Aceleração GPU solicitada: fluxo contínuo de PBKDF2 em lotes de alta ocupação via OpenCL.";
    } else {
        // Se o usuário não especificou motor, analisamos se a máquina tem dGPU dominante
        if (best_gpu && best_gpu->is_discrete && best_gpu->category == GpuCategory::DiscreteHighEnd) {
            strat.chosen_engine = ExecutionEngineChoice::GpuOpenCL;
            strat.engine_desc = "GPU OpenCL de Alta Performance (" + best_gpu->device_name + ")";
            strat.rationale = "dGPU de alta vazão detectada (" + std::to_string(best_gpu->compute_units) + " CUs/SMs). Recomendado aceleração GPU.";
        } else {
            strat.chosen_engine = ExecutionEngineChoice::CpuSIMD;
            std::string simd_name = (strat.chosen_simd == SimdArch::AVX512 ? "AVX-512" : (strat.chosen_simd == SimdArch::AVX2 ? "AVX2" : "SSE4.1"));
            strat.engine_desc = "CPU Nativo SIMD " + simd_name + (strat.use_hardware_sha_ni ? " + SHA-NI" : "");
            strat.rationale = "CPU multithread com instruções vetoriais " + simd_name +
                              (strat.use_hardware_sha_ni ? " e SHA-NI em silício (~10x no checksum)" : "") +
                              " oferece a menor latência e maior vazão sustentada para este perfil.";
            if (host.cpu.topology.physical_cores >= 16 && strat.chosen_simd == SimdArch::AVX512) {
                strat.rationale += " [High-Core AVX-512: Alocação 1:1 por núcleo físico para evitar contenção de pipeline ZMM e throttling térmico de SMT]";
            }
            if (host.cpu.topology.numa_nodes > 1) {
                strat.rationale += " [Topologia Multi-NUMA (" + std::to_string(host.cpu.topology.numa_nodes) + " nós): Core pinning ativado para retenção de afinidade de nó]";
            }
        }
    }

    return strat;
}

void HardwareAdvisor::apply_tuning(AppConfig& cfg, const TuningStrategy& strat) {
    if (cfg.num_threads == 0) {
        cfg.num_threads = strat.recommended_threads;
    }
    if (cfg.gpu_batch == 0) {
        cfg.gpu_batch = strat.chosen_gpu_batch;
    }
    if (cfg.gpu_platform < 0) {
        cfg.gpu_platform = strat.chosen_gpu_platform;
    }
    if (cfg.gpu_device < 0) {
        cfg.gpu_device = strat.chosen_gpu_device;
    }
}

void HardwareAdvisor::print_host_report(const HostProfile& host, const TuningStrategy& strat) {
    print_box_top("DIAGNÓSTICO PROFUNDO DE HARDWARE DO HOSPEDEIRO", DEFAULT_INNER_WIDTH);

    // Sistema e Compilador
    std::string s_sys = std::format("Ambiente     : {} │ Compilador: {}", host.os_info, host.compiler_info);
    print_box_line(s_sys, DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    // CPU Info
    std::string s_cpu_name = std::format("Processador  : \033[1;37m{}\033[0m ({})", host.cpu.brand_string, host.cpu.vendor);
    print_box_line(s_cpu_name, DEFAULT_INNER_WIDTH);

    std::string s_micro = std::format("Microarq.    : \033[1;36m{}\033[0m │ Família: 0x{:02x} ({}) │ Modelo: 0x{:02x} ({}) │ Stepping: {}",
                                      host.cpu.microarch_family, host.cpu.raw_family, host.cpu.raw_family,
                                      host.cpu.raw_model, host.cpu.raw_model, host.cpu.raw_stepping);
    print_box_line(s_micro, DEFAULT_INNER_WIDTH);

    std::string s_ucode = std::format("Microcódigo  : {} │ Endereçamento: {} bits físico, {} bits virtual",
                                      (host.cpu.microcode.empty() ? "N/A" : host.cpu.microcode),
                                      (host.cpu.physical_addr_bits > 0 ? host.cpu.physical_addr_bits : 48),
                                      (host.cpu.virtual_addr_bits > 0 ? host.cpu.virtual_addr_bits : 48));
    print_box_line(s_ucode, DEFAULT_INNER_WIDTH);

    std::string s_topo = std::format("Topologia    : {} Núcleos Físicos │ {} Threads Lógicas (SMT: {}) │ {} Soquete(s) │ {} Nó(s) NUMA",
                                     host.cpu.topology.physical_cores, host.cpu.topology.logical_threads,
                                     (host.cpu.topology.smt_enabled ? "\033[1;32mAtivo\033[0m" : "Desativado"),
                                     host.cpu.topology.sockets, host.cpu.topology.numa_nodes);
    print_box_line(s_topo, DEFAULT_INNER_WIDTH);

    if (host.cpu.topology.is_hybrid) {
        std::string s_hyb = std::format("Arquitetura  : \033[1;33mHeterogênea Híbrida\033[0m ({} P-Cores, {} E-Cores)",
                                        host.cpu.topology.performance_cores, host.cpu.topology.efficiency_cores);
        print_box_line(s_hyb, DEFAULT_INNER_WIDTH);
    }
    if (host.cpu.topology.cppc_active) {
        std::string s_cppc = std::format("Silício CPPC : \033[1;32mAtivo\033[0m (Collaborative Processor Performance Control - Priorização de Golden Cores)");
        print_box_line(s_cppc, DEFAULT_INNER_WIDTH);
    }

    std::string s_clock = std::format("Frequência   : {} MHz Máx │ {} MHz Base │ Mín: {} MHz │ Atual: {} MHz",
                                      host.cpu.max_clock_mhz, host.cpu.base_clock_mhz, host.cpu.min_clock_mhz,
                                      (host.cpu.current_clock_mhz > 0 ? host.cpu.current_clock_mhz : host.cpu.max_clock_mhz));
    print_box_line(s_clock, DEFAULT_INNER_WIDTH);

    if (!host.cpu.scaling_governor.empty() || !host.cpu.scaling_driver.empty()) {
        std::string s_gov = std::format("Governador   : {} ({}) │ EPP: {} │ Boost (CPB/Turbo): {}",
                                        (host.cpu.scaling_governor.empty() ? "padrão" : host.cpu.scaling_governor),
                                        (host.cpu.scaling_driver.empty() ? "nativo" : host.cpu.scaling_driver),
                                        (host.cpu.epp_preference.empty() ? "N/A" : host.cpu.epp_preference),
                                        (host.cpu.caps.cpb_boost ? "\033[1;32mHabilitado\033[0m" : "N/A"));
        print_box_line(s_gov, DEFAULT_INNER_WIDTH);
    }

    // Caches detalhados
    std::string s_cache1 = std::format("Hierarquia L1: L1d: {} KB ({} vias, {} sets, x{}) │ L1i: {} KB ({} vias, x{}) │ Linha: {}B",
                                       host.cpu.cache.l1d_bytes / 1024, host.cpu.cache.l1d_ways, host.cpu.cache.l1d_sets, host.cpu.cache.l1d_instances,
                                       host.cpu.cache.l1i_bytes / 1024, host.cpu.cache.l1i_ways, host.cpu.cache.l1d_instances,
                                       host.cpu.cache.cache_line_size);
    print_box_line(s_cache1, DEFAULT_INNER_WIDTH);

    std::string s_cache2 = std::format("Hierarquia L2/3: L2: {} KB ({} vias, {} sets, x{}) │ L3: {} MB ({} vias, {} sets)",
                                       host.cpu.cache.l2_bytes / 1024, host.cpu.cache.l2_ways, host.cpu.cache.l2_sets, host.cpu.cache.l2_instances,
                                       host.cpu.cache.l3_bytes / (1024 * 1024), host.cpu.cache.l3_ways, host.cpu.cache.l3_sets);
    print_box_line(s_cache2, DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    // Conjunto Completo de Instruções (ISA)
    print_box_line("\033[1;37mEXTENSÕES DE INSTRUÇÃO E CAPACIDADES DE SILÍCIO (CPUID):\033[0m", DEFAULT_INNER_WIDTH);

    // 1. SIMD Clássico & SSE
    std::string simds = "";
    if (host.cpu.caps.avx2) simds += "\033[1;33mAVX2\033[0m ";
    if (host.cpu.caps.avx)  simds += "AVX ";
    if (host.cpu.caps.f16c) simds += "F16C ";
    if (host.cpu.caps.fma3) simds += "FMA3 ";
    if (host.cpu.caps.fma4) simds += "FMA4 ";
    if (host.cpu.caps.xop)  simds += "XOP ";
    if (host.cpu.caps.tbm)  simds += "TBM ";
    if (host.cpu.caps.sse42) simds += "SSE4.2 ";
    if (host.cpu.caps.sse41) simds += "SSE4.1 ";
    if (host.cpu.caps.sse4a) simds += "SSE4a ";
    if (host.cpu.caps.ssse3) simds += "SSSE3 ";
    if (host.cpu.caps.sse3)  simds += "SSE3 ";
    if (host.cpu.caps.sse2)  simds += "SSE2 ";
    if (host.cpu.caps.mmx)   simds += "MMX ";
    if (host.cpu.caps.misalignsse) simds += "MisalignSSE";
    print_box_line(std::format("  ├─ SIMD Clássico : {}", simds), DEFAULT_INNER_WIDTH);

    // 2. AVX-512 e Novas Gerações
    std::string avx512s = "";
    if (host.cpu.caps.avx512f)  avx512s += "\033[1;32mF\033[0m ";
    if (host.cpu.caps.avx512dq) avx512s += "DQ ";
    if (host.cpu.caps.avx512bw) avx512s += "BW ";
    if (host.cpu.caps.avx512vl) avx512s += "\033[1;33mVL(128/256)\033[0m ";
    if (host.cpu.caps.avx512cd) avx512s += "CD ";
    if (host.cpu.caps.avx512er) avx512s += "ER ";
    if (host.cpu.caps.avx512pf) avx512s += "PF ";
    if (host.cpu.caps.avx512ifma) avx512s += "IFMA ";
    if (host.cpu.caps.avx512vbmi) avx512s += "VBMI ";
    if (host.cpu.caps.avx512vbmi2) avx512s += "VBMI2 ";
    if (host.cpu.caps.avx512vnni) avx512s += "VNNI ";
    if (host.cpu.caps.avx512bitalg) avx512s += "BITALG ";
    if (host.cpu.caps.avx512vpopcntdq) avx512s += "VPOPCNTDQ ";
    if (host.cpu.caps.avx512fp16) avx512s += "FP16 ";
    if (host.cpu.caps.avx512bf16) avx512s += "BF16 ";
    if (host.cpu.caps.avx512_4fmaps) avx512s += "4FMAPS ";
    if (host.cpu.caps.avx512_4vnniw) avx512s += "4VNNIW ";
    if (host.cpu.caps.avx512_vp2intersect) avx512s += "VP2INTERSECT ";
    if (host.cpu.caps.avx10) avx512s += "\033[1;36m[AVX10 Converged]\033[0m ";
    if (host.cpu.caps.apx)   avx512s += "\033[1;32m[Intel APX 32-GPRs]\033[0m ";
    if (host.cpu.caps.amx_tile) avx512s += "[AMX-Tile] ";
    if (host.cpu.caps.amx_int8) avx512s += "AMX-INT8 ";
    if (host.cpu.caps.amx_bf16) avx512s += "AMX-BF16 ";
    if (host.cpu.caps.amx_fp16) avx512s += "AMX-FP16 ";
    if (host.cpu.caps.amx_complex) avx512s += "AMX-Complex ";
    if (host.cpu.caps.avx_vnni) avx512s += "AVX-VNNI ";
    if (host.cpu.caps.avx_ifma) avx512s += "AVX-IFMA ";
    if (host.cpu.caps.avx_ne_convert) avx512s += "AVX-NE-CONVERT ";
    if (host.cpu.caps.avx_vnni_int8) avx512s += "VNNI-INT8 ";
    if (host.cpu.caps.avx_vnni_int16) avx512s += "VNNI-INT16 ";
    if (avx512s.empty()) avx512s = "Não suportado no núcleo deste processador";
    print_box_line(std::format("  ├─ AVX-512 / ISA : {}", avx512s), DEFAULT_INNER_WIDTH);

    // 3. Criptografia e Hashing em Silício
    std::string cryptos = "";
    if (host.cpu.caps.sha_ni)       cryptos += "\033[1;32m[SHA-NI Silício (SHA-256)]\033[0m ";
    if (host.cpu.caps.intel_sha512) cryptos += "\033[1;32m[Intel SHA-512 Silício]\033[0m ";
    if (host.cpu.caps.sm3)          cryptos += "SM3 ";
    if (host.cpu.caps.sm4)          cryptos += "SM4 ";
    if (host.cpu.caps.aes_ni)       cryptos += "AES-NI ";
    if (host.cpu.caps.vaes)         cryptos += "\033[1;33mVAES(256/512)\033[0m ";
    if (host.cpu.caps.pclmulqdq)    cryptos += "PCLMULQDQ ";
    if (host.cpu.caps.vpclmulqdq)   cryptos += "VPCLMULQDQ ";
    if (host.cpu.caps.gfni)         cryptos += "GFNI ";
    if (host.cpu.caps.rdrand)       cryptos += "RDRAND ";
    if (host.cpu.caps.rdseed)       cryptos += "RDSEED ";
    if (host.cpu.caps.key_locker)   cryptos += "KeyLocker ";
    if (cryptos.empty()) cryptos = "Nenhuma extensão criptográfica dedicada encontrada";
    print_box_line(std::format("  ├─ Criptografia  : {}", cryptos), DEFAULT_INNER_WIDTH);

    // 4. Manipulação de Bits, Matemática & Sincronização
    std::string bits = "";
    if (host.cpu.caps.bmi2)      bits += "\033[1;33mBMI2(RORX/PDEP/PEXT)\033[0m ";
    if (host.cpu.caps.bmi1)      bits += "BMI1(ANDN/TZCNT) ";
    if (host.cpu.caps.movbe)     bits += "\033[1;32mMOVBE(Byte-Swap)\033[0m ";
    if (host.cpu.caps.popcnt)    bits += "POPCNT ";
    if (host.cpu.caps.lzcnt_abm) bits += "LZCNT(ABM) ";
    if (host.cpu.caps.adx)       bits += "ADX(ADCX/ADOX) ";
    if (host.cpu.caps.cmpccxadd) bits += "CMPCCXADD ";
    if (host.cpu.caps.rao_int)   bits += "RAO-INT ";
    if (host.cpu.caps.waitpkg)   bits += "WAITPKG(UMWAIT) ";
    if (host.cpu.caps.serialize) bits += "SERIALIZE ";
    if (host.cpu.caps.tsx_rtm)   bits += "TSX(RTM) ";
    if (host.cpu.caps.tsx_hle)   bits += "TSX(HLE) ";
    print_box_line(std::format("  ├─ Aritmética/Bit: {}", bits), DEFAULT_INNER_WIDTH);

    // 5. Caches, Memória e Barramento
    std::string mem_isa = "";
    if (host.cpu.caps.clzero)    mem_isa += "\033[1;32m[CLZERO 64B em 1 ciclo]\033[0m ";
    if (host.cpu.caps.clflushopt) mem_isa += "CLFLUSHOPT ";
    if (host.cpu.caps.clwb)      mem_isa += "CLWB ";
    if (host.cpu.caps.cldemote)  mem_isa += "CLDEMOTE ";
    if (host.cpu.caps.movdiri)   mem_isa += "MOVDIRI ";
    if (host.cpu.caps.movdir64b) mem_isa += "\033[1;32mMOVDIR64B(Direct-Store 64B)\033[0m ";
    if (host.cpu.caps.enqcmd)    mem_isa += "ENQCMD ";
    if (host.cpu.caps.clflush)   mem_isa += "CLFLUSH ";
    if (host.cpu.caps.erms)      mem_isa += "ERMS(Fast-Memcpy) ";
    if (host.cpu.caps.fsrm)      mem_isa += "FSRM(<128B) ";
    if (host.cpu.caps.fsgsbase)  mem_isa += "FSGSBASE ";
    if (host.cpu.caps.rdpru)     mem_isa += "RDPRU ";
    if (host.cpu.caps.rdpid)     mem_isa += "RDPID ";
    if (host.cpu.caps.rdtscp)    mem_isa += "RDTSCP ";
    if (host.cpu.caps.invariant_tsc) mem_isa += "InvariantTSC ";
    if (host.cpu.caps.prefetchw) mem_isa += "PREFETCHW ";
    if (host.cpu.caps.prefetchwt1) mem_isa += "PREFETCHWT1 ";
    if (host.cpu.caps.prefetchi) mem_isa += "PREFETCHI ";
    if (host.cpu.caps.mwaitx)    mem_isa += "MWAITX ";
    print_box_line(std::format("  ├─ Caches/Memória: {}", mem_isa), DEFAULT_INNER_WIDTH);

    // 6. Segurança e Virtualização
    std::string sec_isa = "";
    if (host.cpu.caps.la57)      sec_isa += "LA57(57b-Virtual) ";
    if (host.cpu.caps.cet_ss)    sec_isa += "CET-SS(Shadow-Stack) ";
    if (host.cpu.caps.cet_ibt)   sec_isa += "CET-IBT ";
    if (host.cpu.caps.umip)      sec_isa += "UMIP ";
    if (host.cpu.caps.smep)      sec_isa += "SMEP ";
    if (host.cpu.caps.smap)      sec_isa += "SMAP ";
    if (host.cpu.caps.pku_ospke) sec_isa += "PKU/OSPKE ";
    if (host.cpu.caps.sme)       sec_isa += "\033[1;32mAMD-SME(Mem-Encrypt)\033[0m ";
    if (host.cpu.caps.sev)       sec_isa += "SEV ";
    if (host.cpu.caps.sev_snp)   sec_isa += "SEV-SNP ";
    if (host.cpu.caps.intel_vmx) sec_isa += "Intel-VMX ";
    if (host.cpu.caps.amd_svm)   sec_isa += "AMD-SVM ";
    print_box_line(std::format("  └─ Segurança/SO  : {}", sec_isa), DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    // Memória RAM e Hugepages
    std::string s_mem = std::format("Memória Host : {} MB Total │ {} MB Livre │ Hugepages 1GB: {} │ THP: {}",
                                    host.memory.total_ram_bytes / (1024 * 1024),
                                    host.memory.available_ram_bytes / (1024 * 1024),
                                    (host.cpu.caps.hugepages_1gb ? "\033[1;32mSuportado (PDPE1GB)\033[0m" : "Não suportado"),
                                    (host.cpu.thp_status.empty() ? "N/A" : host.cpu.thp_status));
    print_box_line(s_mem, DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    // Dispositivos GPU
    if (host.gpus.empty()) {
        print_box_line("Dispositivos GPU: Nenhum dispositivo OpenCL detectado.", DEFAULT_INNER_WIDTH);
    } else {
        std::string s_gpu_hdr = std::format("Dispositivos GPU Detectados ({}) :", host.gpus.size());
        print_box_line(s_gpu_hdr, DEFAULT_INNER_WIDTH);

        for (size_t i = 0; i < host.gpus.size(); ++i) {
            const auto& g = host.gpus[i];
            std::string badge = g.is_recommended ? " \033[1;32m★ [RECOMENDADO]\033[0m" : "";
            std::string line1 = std::format("  \033[1;37m[Plat {}, Dev {}]\033[0m \033[1;36m{}\033[0m ({}){}",
                                            g.platform_idx, g.device_idx, g.device_name, g.category_str, badge);
            print_box_line(line1, DEFAULT_INNER_WIDTH);

            std::string line2 = std::format("     ├─ CUs: {:<3} │ Clock: {:<4} MHz │ VRAM: {:<5} MB │ Warp/Wave: {:<2}",
                                            g.compute_units, g.clock_freq_mhz, g.global_mem_bytes / (1024 * 1024), g.preferred_work_group_multiple);
            print_box_line(line2, DEFAULT_INNER_WIDTH);

            std::string line3 = std::format("     └─ Driver: {:<20} │ Max WorkGroup: {:<4} │ Compute Index: {:.1f}",
                                            g.driver_version, g.max_work_group, g.compute_index);
            print_box_line(line3, DEFAULT_INNER_WIDTH);
        }
    }
    print_box_separator(DEFAULT_INNER_WIDTH);


    // Estratégia Recomendada
    print_box_line("\033[1;32mORQUESTRAÇÃO E AUTO-TUNING RECOMENDADO PARA ESTE HOST:\033[0m", DEFAULT_INNER_WIDTH);
    std::string s_eng = std::format("  ├─ Motor Ideal   : \033[1;33m{}\033[0m", strat.engine_desc);
    print_box_line(s_eng, DEFAULT_INNER_WIDTH);

    std::string s_thr = std::format("  ├─ Threads CPU   : {} workers com Afinidade Física (Core Pinning: {})",
                                    strat.recommended_threads, (strat.enable_core_pinning ? "\033[1;32mSim\033[0m" : "Não"));
    print_box_line(s_thr, DEFAULT_INNER_WIDTH);

    if (strat.chosen_gpu_platform >= 0) {
        std::string s_gopt = std::format("  ├─ Ajuste GPU    : Batch {} chaves │ WorkGroup {} threads │ Buffer slot {} B",
                                         format_num(static_cast<double>(strat.chosen_gpu_batch)),
                                         strat.chosen_workgroup_size, strat.chosen_slot_size);
        print_box_line(s_gopt, DEFAULT_INNER_WIDTH);
    }

    std::string s_rat = std::format("  └─ Diagnóstico   : {}", strat.rationale);
    print_box_line(s_rat, DEFAULT_INNER_WIDTH);
    print_box_separator(DEFAULT_INNER_WIDTH);

    // Mapeamento de instruções no CriptoWords
    print_box_line("\033[1;36mAPROVEITAMENTO DAS CAPACIDADES DA CPU NO CRIPTOWORDS:\033[0m", DEFAULT_INNER_WIDTH);
    std::string s_acc1 = std::format("  ├─ Checksum BIP-39 : {}",
        (host.cpu.caps.sha_ni ? "\033[1;32mAcelerado por SHA-NI em silício (~70 ciclos/bloco)\033[0m" : "Emulação vetorial por software"));
    print_box_line(s_acc1, DEFAULT_INNER_WIDTH);

    std::string s_acc2 = std::format("  ├─ PBKDF2 SHA-512  : {}",
        (host.cpu.caps.intel_sha512 ? "\033[1;32mAcelerado por Intel SHA-512 nativo em silício\033[0m" :
         (host.cpu.caps.avx512f ? "\033[1;33mVetorização AVX-512 (8 sementes/vetor) em registradores ZMM\033[0m" :
          (host.cpu.caps.avx2 ? "\033[1;33mVetorização AVX2 (4 sementes/vetor) + FMA3 + RORX (BMI2)\033[0m" : "Vetorização SSE4.1 (2 sementes/vetor)"))));
    print_box_line(s_acc2, DEFAULT_INNER_WIDTH);

    std::string s_acc3 = std::format("  ├─ Endereço/Tokens : {}",
        (host.cpu.caps.movbe ? "\033[1;32mMOVBE Big-Endian Swap em 1 ciclo (Zero Latência)\033[0m" : "Bitshift convencional"));
    print_box_line(s_acc3, DEFAULT_INNER_WIDTH);

    std::string s_acc4 = std::format("  ├─ Caches e Buffers: {}",
        (host.cpu.caps.clzero ? "\033[1;32mCLZERO ativado (Sanitização imediata de 64B no L1d)\033[0m" :
         (host.cpu.caps.movdir64b ? "\033[1;32mMOVDIR64B ativado (Direct Store sem poluição de cache)\033[0m" : "Vetor de inicialização em cache L1d")));
    print_box_line(s_acc4, DEFAULT_INNER_WIDTH);

    std::string s_acc5 = std::format("  ├─ Telemetria/Sync : {}",
        (host.cpu.caps.rdpid ? "\033[1;32mRDPID em Ring 3 (Identificação de Core em 1 ciclo sem syscall)\033[0m" :
         (host.cpu.caps.rdtscp ? "RDTSCP atômico (TSC + Core ID)" : "Telemetria padrão")));
    print_box_line(s_acc5, DEFAULT_INNER_WIDTH);

    std::string s_acc6 = std::format("  └─ Topologia/Cores : {}",
        (strat.enable_core_pinning ? "\033[1;32mCore Pinning Físico Ativo (Previne migração de cache L1/L2)\033[0m" : "Escalonamento dinâmico pelo SO"));
    print_box_line(s_acc6, DEFAULT_INNER_WIDTH);

    print_box_bottom(DEFAULT_INNER_WIDTH);

}

void HardwareAdvisor::print_tuning_summary(const TuningStrategy& strat) {
    std::string line = std::format(" [Auto-Tuning] Motor: \033[1;33m{}\033[0m │ Threads: {} │ Lote GPU: {} chaves",
                                   strat.engine_desc, strat.recommended_threads,
                                   (strat.chosen_gpu_platform >= 0 ? format_num(static_cast<double>(strat.chosen_gpu_batch)) : "N/A"));
    std::println("{}", line);
}

} // namespace hardware
} // namespace cryptowords
