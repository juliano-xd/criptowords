#pragma once

#include "host_probe.hpp"
#include "../config.hpp"
#include "../simd/batch_processor.hpp"

#include <string>
#include <vector>

namespace cryptowords {
namespace hardware {

enum class ExecutionEngineChoice {
    CpuSIMD,
    GpuOpenCL,
    HybridParallel
};

struct TuningStrategy {
    ExecutionEngineChoice chosen_engine = ExecutionEngineChoice::CpuSIMD;
    std::string engine_desc;

    // CPU tuning
    uint32_t recommended_threads = 0;
    bool enable_core_pinning = true;
    SimdArch chosen_simd = SimdArch::SSE;
    bool use_hardware_sha_ni = false;
    bool use_hardware_sha512 = false;

    // GPU tuning
    int chosen_gpu_platform = -1;
    int chosen_gpu_device = -1;
    size_t chosen_workgroup_size = 256;
    size_t chosen_gpu_batch = 16384;
    size_t chosen_slot_size = 128;

    // Racional técnico da escolha
    std::string rationale;
};

class HardwareAdvisor {
public:
    static TuningStrategy analyze(const AppConfig& cfg, const HostProfile& host);
    static void apply_tuning(AppConfig& cfg, const TuningStrategy& strat);
    static void print_host_report(const HostProfile& host, const TuningStrategy& strat);
    static void print_tuning_summary(const TuningStrategy& strat);
};

} // namespace hardware
} // namespace cryptowords
