#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../config.hpp"

namespace cryptowords {

enum class GpuComputeMode : uint32_t {
    PostPbkdf2Only = 0,
    FullPipeline   = 1,   // reservado
};

enum class GpuVendor : uint8_t {
    HIP = 0,    // AMD ROCm
    CUDA = 1,   // NVIDIA
    OpenCL = 2, // reservado
};

// =========================================================================
// Interface de engine GPU. Um engine gerencia os recursos do device e
// processa lotes de seeds já prontas (pós-PBKDF2).
// =========================================================================
class IGpuEngine {
   public:
    virtual ~IGpuEngine() = default;

    virtual bool init(const AppConfig& cfg, size_t slot_size, const uint64_t* salt_block) = 0;
    virtual void cleanup() = 0;

    virtual GpuComputeMode compute_mode() const noexcept = 0;

    // Post-PBKDF2: recebe seeds, devolve índice do primeiro match (0xFFFFFFFF se nenhum).
    virtual bool enqueue_post_pbkdf2(size_t slot,
                                     const std::vector<uint8_t>& seeds,
                                     uint32_t num_seeds,
                                     const uint8_t* target_bytes,
                                     uint64_t target_fast,
                                     uint32_t* result_out) = 0;

    virtual bool enqueue_full_pipeline(size_t, const std::vector<uint16_t>&, uint32_t,
                                       CoinTarget, const uint8_t*, uint64_t, uint32_t*) {
        return false;
    }

    virtual bool wait_batch(size_t slot) = 0;
    virtual bool is_slot_in_flight(size_t slot) const = 0;

    virtual size_t get_optimal_batch_size() const = 0;
    virtual size_t get_slot_size() const = 0;
    virtual size_t get_local_work_size() const = 0;

    virtual std::string get_device_name() const = 0;
    virtual std::string get_backend_name() const = 0;
};

// Detecção de backends presentes no host.
struct GpuBackendCaps {
    bool has_hip = false;
    int  hip_device_count = 0;
    // Placeholder: a implementação CUDA virá num próximo estágio; o campo
    // já existe para não ter quebra de ABI no futuro.
    bool has_cuda = false;
    int  cuda_device_count = 0;
};

GpuBackendCaps probe_gpu_backends();
bool init_gpu_engine(const AppConfig& cfg, size_t slot_size, const uint64_t* salt_block64);
IGpuEngine* get_gpu_engine();
void shutdown_gpu_engine();

// Resumo de device AMD (HIP).
struct HipDeviceSummary {
    int         device_idx = 0;
    std::string name, gcn_arch, driver_version;
    uint32_t    compute_units = 0, clock_mhz = 0, warp_size = 0, max_threads_per_block = 0;
    uint64_t    vram_bytes = 0, shared_mem_per_block = 0;
    bool        is_integrated = false, is_recommended = false;
    GpuComputeMode suggested_mode = GpuComputeMode::PostPbkdf2Only;
};

std::vector<HipDeviceSummary> enumerate_hip_devices();
void print_gpu_device_list();

#if defined(CRYPTOWORDS_HAVE_HIP)
bool hip_backend_available();
std::unique_ptr<IGpuEngine> create_hip_engine();
#endif

// -------------------------------------------------------------------------
// Fábrica do backend CUDA. Retorna nullptr enquanto o engine CUDA não
// existe — o `init_gpu_engine` trata como "backend indisponível".
// -------------------------------------------------------------------------
std::unique_ptr<IGpuEngine> create_cuda_engine();

}  // namespace cryptowords
