#pragma once

#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 300
#endif

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include "gpu_info.hpp"
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <mutex>
#include <optional>

namespace cryptowords {

struct GpuExecutionMetrics {
    uint64_t write_time_ns = 0;
    uint64_t kernel_time_ns = 0;
    uint64_t read_time_ns = 0;
    uint64_t total_time_ns = 0;
    double bandwidth_h2d_gb_s = 0.0;
    double bandwidth_d2h_gb_s = 0.0;
    double kernel_keys_per_sec = 0.0;
    double total_keys_per_sec = 0.0;
};

class GPUEngine {
public:
    static GPUEngine& get_instance() {
        static GPUEngine instance;
        return instance;
    }

    bool init(int platform_id = -1, int device_id = -1, size_t batch_size = 0, const uint64_t* salt_block = nullptr, bool silent = false, size_t slot_size = 256);
    void cleanup();
    size_t get_optimal_batch_size() const { return max_batch_size_; }
    size_t get_slot_size() const { return slot_size_; }
    const gpu::DiscoveredDevice* get_active_device() const {
        return active_device_.has_value() ? &active_device_.value() : nullptr;
    }
    
    static constexpr size_t NUM_SLOTS = 3;

    bool pbkdf2_batch(const std::vector<uint8_t>& passwords, 
                      const std::vector<uint32_t>& pass_lens, 
                      std::vector<uint8_t>& out_seeds,
                      uint32_t num_hashes);

    bool pbkdf2_batch_profiled(const std::vector<uint8_t>& passwords, 
                               const std::vector<uint32_t>& pass_lens, 
                               std::vector<uint8_t>& out_seeds,
                               uint32_t num_hashes,
                               GpuExecutionMetrics& metrics);

    // Métodos do pipeline assíncrono Triple-Buffering
    bool enqueue_batch_async(size_t slot,
                             const std::vector<uint8_t>& passwords,
                             const std::vector<uint32_t>& pass_lens,
                             uint32_t num_hashes,
                             uint8_t* out_seeds_ptr);

    bool wait_batch(size_t slot);
    bool is_slot_in_flight(size_t slot) const {
        if (slot >= NUM_SLOTS) return false;
        std::lock_guard<std::mutex> lock(mu_);
        return slot_in_flight_[slot];
    }
    bool is_unified_memory() const { return is_unified_memory_; }
    size_t get_local_work_size() const { return local_work_size_; }

private:
    GPUEngine() = default;
    ~GPUEngine();

    GPUEngine(const GPUEngine&) = delete;
    GPUEngine& operator=(const GPUEngine&) = delete;

    std::string load_kernel(const std::string& filename);
    void cleanup_locked();

    bool initialized_ = false;
    mutable std::mutex mu_;
    std::optional<gpu::DiscoveredDevice> active_device_;

    cl_context context_ = nullptr;
    cl_program pbkdf2_prog_ = nullptr;
    std::array<cl_command_queue, NUM_SLOTS> queue_ = {nullptr, nullptr, nullptr};
    std::array<cl_kernel, NUM_SLOTS> pbkdf2_kernel_ = {nullptr, nullptr, nullptr};

    std::array<cl_mem, NUM_SLOTS> d_passwords_ = {nullptr, nullptr, nullptr};
    std::array<cl_mem, NUM_SLOTS> d_pass_lens_ = {nullptr, nullptr, nullptr};
    std::array<cl_mem, NUM_SLOTS> d_out_seeds_ = {nullptr, nullptr, nullptr};
    cl_mem d_salt_block_ = nullptr;
    std::array<cl_event, NUM_SLOTS> ev_kernel_ = {nullptr, nullptr, nullptr};
    std::array<cl_event, NUM_SLOTS> ev_read_ = {nullptr, nullptr, nullptr};
    std::array<bool, NUM_SLOTS> slot_in_flight_ = {false, false, false};
    std::array<uint32_t, NUM_SLOTS> slot_hashes_ = {0, 0, 0};

    bool is_unified_memory_ = false;
    size_t local_work_size_ = 32;
    size_t max_batch_size_ = 65536;
    size_t slot_size_ = 256;
};

} // namespace cryptowords
