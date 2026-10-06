#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <print>
#include <vector>

#include <hip/hip_runtime.h>

#include "config.hpp"
#include "hip_engine.hpp"
#include "pbkdf2_sha512.cuh"
#include "post_pbkdf2.cuh"

#include "../../../include/math/Point.hpp"
#include "../../../include/math/Secp256k1Fp.hpp"

namespace cryptowords {

static constexpr size_t HIP_NUM_SLOTS = 8;

struct HipEngine::Impl {
    struct Slot {
        uint8_t*    d_seeds_in   = nullptr;
        uint8_t*    d_target     = nullptr;
        uint32_t*   d_result_idx = nullptr;
        hipStream_t stream       = nullptr;
        hipEvent_t  ev_read      = nullptr;
        bool        in_flight    = false;
    };

    int             device_id = 0;
    hipDeviceProp_t props{};
    uint64_t*       d_salt_block = nullptr;
    uint32_t*       d_g_table    = nullptr;
    std::array<Slot, HIP_NUM_SLOTS> slots{};
};

HipEngine::HipEngine() : impl_(std::make_unique<Impl>()) {}
HipEngine::~HipEngine() { cleanup(); }

namespace {

// Gera os 256 pontos afins 2^i · G para o kernel HIP.
// Usa Point<Secp256k1Fp> em runtime (não constexpr) para evitar o limite de
// step do clang.
std::vector<uint32_t> build_g_table_host() {
    using Fp = Secp256k1Fp;
    using Fe = Fp::Element;
    using PT = Point<Fp>;

    const Fe gx = {0x59f2815b16f81798ULL, 0x029bfcdb2dce28d9ULL,
                   0x55a06295ce870b07ULL, 0x79be667ef9dcbbacULL};
    const Fe gy = {0x9c47d08ffb10d4b8ULL, 0xfd17b448a6855419ULL,
                   0x5da4fbfc0e1108a8ULL, 0x483ada7726a3c465ULL};

    std::array<PT, 256> jac{};
    PT P = PT::from_affine(gx, gy);
    for (int i = 0; i < 256; ++i) {
        jac[i] = P;
        P.dbl_inplace();
    }

    std::array<Fe, 256> scratch{};
    PT::batch_normalize(jac.data(), 256, scratch.data());

    std::vector<uint32_t> h(256 * 16, 0);
    for (int i = 0; i < 256; ++i) {
        auto aff = jac[i].to_affine();
        const Fe& x = aff.first;
        const Fe& y = aff.second;
        for (int w = 0; w < 4; ++w) {
            h[i * 16 + w * 2 + 0]     = static_cast<uint32_t>(x[w] & 0xFFFFFFFFu);
            h[i * 16 + w * 2 + 1]     = static_cast<uint32_t>(x[w] >> 32);
            h[i * 16 + 8 + w * 2 + 0] = static_cast<uint32_t>(y[w] & 0xFFFFFFFFu);
            h[i * 16 + 8 + w * 2 + 1] = static_cast<uint32_t>(y[w] >> 32);
        }
    }
    return h;
}

}  // namespace

bool HipEngine::init(const AppConfig& cfg, size_t slot_size, const uint64_t* salt_block) {
    if (initialized_) return true;

    int dev_count = 0;
    if (hipGetDeviceCount(&dev_count) != hipSuccess || dev_count <= 0) {
        std::println(std::cerr, "[HIP] Nenhum device AMD.");
        return false;
    }

    int dev = (cfg.gpu_device >= 0 && cfg.gpu_device < dev_count) ? cfg.gpu_device : 0;
    if (hipSetDevice(dev) != hipSuccess) return false;
    impl_->device_id = dev;
    if (hipGetDeviceProperties(&impl_->props, dev) != hipSuccess) return false;
    device_name_ = impl_->props.name;

    slot_size_ = std::max<size_t>(slot_size, 64);
    local_work_size_ = 64;

    const size_t cu = static_cast<size_t>(impl_->props.multiProcessorCount);
    size_t batch = cfg.gpu_batch > 0
                       ? static_cast<size_t>(cfg.gpu_batch)
                       : (cu * local_work_size_ * 16);
    batch = ((batch + 63) / 64) * 64;
    batch = std::clamp(batch, size_t{512}, size_t{524288});
    const size_t max_by_vram = (impl_->props.totalGlobalMem / 4) / slot_size_;
    if (max_by_vram > 0 && batch > max_by_vram) batch = max_by_vram;
    if (batch < 512) batch = 512;
    max_batch_size_ = batch;

    compute_mode_ = GpuComputeMode::PostPbkdf2Only;

    std::println("[HIP] Device: {} | {} CUs | warp={} | batch={} | mode=PostPbkdf2Only",
                 device_name_, cu, impl_->props.warpSize, max_batch_size_);

    // G_TABLE 256 × 16 u32 (16 KB)
    {
        std::vector<uint32_t> h = build_g_table_host();
        if (hipMalloc(reinterpret_cast<void**>(&impl_->d_g_table),
                      256 * 16 * sizeof(uint32_t)) != hipSuccess) {
            cleanup();
            return false;
        }
        if (hipMemcpy(impl_->d_g_table, h.data(),
                      256 * 16 * sizeof(uint32_t),
                      hipMemcpyHostToDevice) != hipSuccess) {
            cleanup();
            return false;
        }
    }

    // Salt block
    if (hipMalloc(reinterpret_cast<void**>(&impl_->d_salt_block),
                  16 * sizeof(uint64_t)) != hipSuccess) { cleanup(); return false; }
    if (hipMemcpy(impl_->d_salt_block, salt_block,
                  16 * sizeof(uint64_t), hipMemcpyHostToDevice) != hipSuccess) { cleanup(); return false; }

    // Slots — cada um é um pipeline independente com stream próprio.
    for (auto& s : impl_->slots) {
        if (hipMalloc(reinterpret_cast<void**>(&s.d_seeds_in), max_batch_size_ * 64) != hipSuccess ||
            hipMalloc(reinterpret_cast<void**>(&s.d_target),    20) != hipSuccess ||
            hipMalloc(reinterpret_cast<void**>(&s.d_result_idx), sizeof(uint32_t)) != hipSuccess ||
            hipStreamCreate(&s.stream) != hipSuccess ||
            hipEventCreateWithFlags(&s.ev_read, hipEventDisableTiming) != hipSuccess) {
            cleanup(); return false;
        }
        s.in_flight = false;
    }

    initialized_ = true;
    return true;
}

void HipEngine::cleanup() {
    if (!impl_) return;
    if (impl_->d_salt_block) { (void)hipFree(impl_->d_salt_block); impl_->d_salt_block = nullptr; }
    if (impl_->d_g_table)    { (void)hipFree(impl_->d_g_table);    impl_->d_g_table = nullptr; }

    for (auto& s : impl_->slots) {
        if (s.stream) { (void)hipStreamSynchronize(s.stream); (void)hipStreamDestroy(s.stream); }
        if (s.ev_read)     (void)hipEventDestroy(s.ev_read);
        if (s.d_seeds_in)  (void)hipFree(s.d_seeds_in);
        if (s.d_target)    (void)hipFree(s.d_target);
        if (s.d_result_idx)(void)hipFree(s.d_result_idx);
        s = {};
    }
    initialized_ = false;
}

bool HipEngine::enqueue_post_pbkdf2(size_t slot,
                                    const std::vector<uint8_t>& seeds,
                                    uint32_t num_seeds,
                                    const uint8_t* target_bytes,
                                    uint64_t target_fast,
                                    uint32_t* result_out) {
    if (!initialized_ || slot >= HIP_NUM_SLOTS || num_seeds == 0) return false;
    if (num_seeds > max_batch_size_) return false;
    if (seeds.size() < num_seeds * 64u) return false;

    auto& s = impl_->slots[slot];

    if (s.in_flight) {
        hipError_t err = s.ev_read ? hipEventSynchronize(s.ev_read)
                                   : hipStreamSynchronize(s.stream);
        if (err != hipSuccess) return false;
        s.in_flight = false;
    }

    const uint32_t miss = 0xFFFFFFFFu;

    if (hipMemcpyAsync(s.d_result_idx, &miss, sizeof(uint32_t),
                       hipMemcpyHostToDevice, s.stream) != hipSuccess) return false;
    if (hipMemcpyAsync(s.d_seeds_in, seeds.data(), num_seeds * 64,
                       hipMemcpyHostToDevice, s.stream) != hipSuccess) return false;
    if (hipMemcpyAsync(s.d_target, target_bytes, 20,
                       hipMemcpyHostToDevice, s.stream) != hipSuccess) return false;

    const uint32_t lws  = static_cast<uint32_t>(local_work_size_);
    const uint32_t grid = (num_seeds + lws - 1) / lws;

    cw_amd::post_pbkdf2_eth_batch<<<grid, lws, 0, s.stream>>>(
        s.d_seeds_in,
        num_seeds,
        s.d_target,
        target_fast,
        impl_->d_g_table,
        s.d_result_idx);

    if (hipGetLastError() != hipSuccess) return false;

    if (result_out) {
        if (hipMemcpyAsync(result_out, s.d_result_idx, sizeof(uint32_t),
                           hipMemcpyDeviceToHost, s.stream) != hipSuccess) return false;
        if (hipEventRecord(s.ev_read, s.stream) != hipSuccess) return false;
    }

    s.in_flight = true;
    return true;
}

bool HipEngine::wait_batch(size_t slot) {
    if (!initialized_ || slot >= HIP_NUM_SLOTS) return false;
    auto& s = impl_->slots[slot];
    if (!s.in_flight) return false;
    hipError_t err = s.ev_read ? hipEventSynchronize(s.ev_read)
                               : hipStreamSynchronize(s.stream);
    s.in_flight = false;
    return err == hipSuccess;
}

bool HipEngine::is_slot_in_flight(size_t slot) const {
    if (!initialized_ || slot >= HIP_NUM_SLOTS) return false;
    return impl_->slots[slot].in_flight;
}

std::unique_ptr<IGpuEngine> create_hip_engine() {
    return std::make_unique<HipEngine>();
}

bool hip_backend_available() {
    int n = 0;
    return hipGetDeviceCount(&n) == hipSuccess && n > 0;
}

namespace {

bool name_looks_integrated(const std::string& n) {
    static const char* k[] = {
        "Radeon Graphics", "Vega 8", "Vega 10", "Vega 11",
        "Radeon 610M", "Radeon 660M", "Radeon 680M",
        "Radeon 710M", "Radeon 740M", "Radeon 760M", "Radeon 780M",
        "Radeon 880M", "Radeon 890M",
        "Renoir", "Cezanne", "Rembrandt", "Phoenix", "Hawk Point", "Strix",
    };
    for (auto* s : k) if (n.find(s) != std::string::npos) return true;
    return false;
}

}  // namespace

std::vector<HipDeviceSummary> enumerate_hip_devices() {
    std::vector<HipDeviceSummary> out;
    int n = 0;
    if (hipGetDeviceCount(&n) != hipSuccess || n <= 0) return out;

    out.reserve(n);
    int best_score = -1;
    size_t best_idx = 0;

    for (int i = 0; i < n; ++i) {
        hipDeviceProp_t p{};
        if (hipGetDeviceProperties(&p, i) != hipSuccess) continue;

        HipDeviceSummary d{};
        d.device_idx            = i;
        d.name                  = p.name;
        d.gcn_arch              = p.gcnArchName;
        d.driver_version        = "ROCm";
        d.compute_units         = static_cast<uint32_t>(p.multiProcessorCount);
        d.clock_mhz             = static_cast<uint32_t>(p.clockRate / 1000);
        d.vram_bytes            = static_cast<uint64_t>(p.totalGlobalMem);
        d.warp_size             = static_cast<uint32_t>(p.warpSize);
        d.max_threads_per_block = static_cast<uint32_t>(p.maxThreadsPerBlock);
        d.shared_mem_per_block  = static_cast<uint64_t>(p.sharedMemPerBlock);
        d.is_integrated         = name_looks_integrated(d.name);
        d.suggested_mode        = (d.compute_units >= 16 && !d.is_integrated)
                                    ? GpuComputeMode::FullPipeline
                                    : GpuComputeMode::PostPbkdf2Only;

        int score = static_cast<int>(d.compute_units) * 1000
                  + static_cast<int>(d.clock_mhz)
                  + static_cast<int>(d.vram_bytes / (1024ULL * 1024ULL * 1024ULL)) * 500;
        if (score > best_score) { best_score = score; best_idx = out.size(); }

        out.push_back(std::move(d));
    }
    if (!out.empty()) out[best_idx].is_recommended = true;
    return out;
}

}  // namespace cryptowords
