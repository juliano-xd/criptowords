#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../../../include/gpu/gpu_backend.hpp"

namespace cryptowords {

class HipEngine final : public IGpuEngine {
   public:
    HipEngine();
    ~HipEngine() override;

    bool init(const AppConfig& cfg, size_t slot_size, const uint64_t* salt_block) override;
    void cleanup() override;

    GpuComputeMode compute_mode() const noexcept override { return compute_mode_; }

    bool enqueue_post_pbkdf2(size_t slot,
                             const std::vector<uint8_t>& seeds,
                             uint32_t num_seeds,
                             const uint8_t* target_bytes,
                             uint64_t target_fast,
                             uint32_t* result_out) override;

    bool wait_batch(size_t slot) override;
    bool is_slot_in_flight(size_t slot) const override;

    size_t get_optimal_batch_size() const override { return max_batch_size_; }
    size_t get_slot_size() const override { return slot_size_; }
    size_t get_local_work_size() const override { return local_work_size_; }

    std::string get_device_name() const override { return device_name_; }
    std::string get_backend_name() const override { return "HIP (AMD ROCm)"; }

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    bool initialized_ = false;
    std::string device_name_;
    size_t max_batch_size_ = 65536;
    size_t slot_size_ = 256;
    size_t local_work_size_ = 64;
    GpuComputeMode compute_mode_ = GpuComputeMode::PostPbkdf2Only;
};

}  // namespace cryptowords
