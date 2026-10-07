#include "../../include/gpu/gpu_backend.hpp"

#include <iostream>
#include <print>
#include <vector>

#include "../../include/config.hpp"

#if defined(CRYPTOWORDS_HAVE_HIP)
  #include "gpu/hip/hip_engine.hpp"
#endif

namespace cryptowords {

namespace {
std::unique_ptr<IGpuEngine> g_active_engine;
}  // namespace

GpuBackendCaps probe_gpu_backends() {
    GpuBackendCaps caps;
#if defined(CRYPTOWORDS_HAVE_HIP)
    if (hip_backend_available()) {
        caps.has_hip = true;
        caps.hip_device_count = 1;
    }
#endif
    // CUDA: quando o engine for implementado, popular caps.has_cuda aqui.
    return caps;
}

// =========================================================================
// Stub de enumerar devices AMD quando o backend HIP não está no binário.
// host_probe.cpp chama essa função incondicionalmente — sem esse stub o
// link quebra em ARM64/Termux (ou em builds x86 sem ROCm).
// =========================================================================
#if !defined(CRYPTOWORDS_HAVE_HIP)
std::vector<HipDeviceSummary> enumerate_hip_devices() {
    return {};
}
#endif

// =========================================================================
// Fábrica CUDA — stub. Retorna nullptr até o backend real existir; o
// pipeline detecta isso e cai no caminho CPU.
// =========================================================================
std::unique_ptr<IGpuEngine> create_cuda_engine() {
    return nullptr;
}

bool init_gpu_engine(const AppConfig& cfg, size_t slot_size, const uint64_t* salt_block64) {
    if (g_active_engine) return true;

    // Ordem de preferência: HIP → CUDA → nenhum.
#if defined(CRYPTOWORDS_HAVE_HIP)
    if (auto eng = create_hip_engine(); eng && eng->init(cfg, slot_size, salt_block64)) {
        g_active_engine = std::move(eng);
        return true;
    }
#endif

    if (auto eng = create_cuda_engine(); eng && eng->init(cfg, slot_size, salt_block64)) {
        g_active_engine = std::move(eng);
        return true;
    }

#if defined(CRYPTOWORDS_HAVE_HIP)
    std::println(std::cerr, "[GPU] Nenhum backend GPU inicializou com sucesso.");
#else
    std::println(std::cerr,
                 "[GPU] Binário compilado sem suporte a GPU. "
                 "Recompile com ROCm (HIP) ou CUDA para acelerar.");
#endif
    return false;
}

IGpuEngine* get_gpu_engine() { return g_active_engine.get(); }

void shutdown_gpu_engine() {
    if (g_active_engine) {
        g_active_engine->cleanup();
        g_active_engine.reset();
    }
}

void print_gpu_device_list() {
#if defined(CRYPTOWORDS_HAVE_HIP)
    auto devs = enumerate_hip_devices();
    if (devs.empty()) {
        std::println("Nenhum device AMD ROCm detectado.");
        return;
    }
    std::println("\n=== Devices AMD (ROCm/HIP) ===\n");
    for (const auto& d : devs) {
        std::string badge = d.is_recommended ? "  ★ [recomendado]" : "";
        std::println("  [Dev {}] {} ({}){}", d.device_idx, d.name, d.gcn_arch, badge);
        std::println("    CUs: {}  │ Clock: {} MHz │ VRAM: {} MB │ warp: {}",
                     d.compute_units, d.clock_mhz, d.vram_bytes / (1024 * 1024),
                     d.warp_size);
        std::println("    Driver: {}", d.driver_version);
    }
    std::println("");
#else
    std::println("[GPU] Binário compilado sem HIP/ROCm. Nenhum device AMD disponível.");
#endif
}

}  // namespace cryptowords
