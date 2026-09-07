#pragma once
#include "pbkdf2_hmac512.hpp"
#include <CL/cl.h>
#include <cstdint>
#include <cstring>
#include <flat_map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace gpu {

class Engine {
  public:
    Engine();
    ~Engine();

    bool init(const std::string& kernel_file = "");
    bool is_initialized() const {
        return initialized_;
    }
    bool is_gpu() const {
        return is_gpu_;
    }
    const std::string& device_name() const {
        return device_name_;
    }

    bool pbkdf2_batch(const std::vector<std::string>& mnemonics, int iterations,
                      std::vector<std::vector<uint8_t>>& seeds);

    bool pbkdf2_batch_from_ids(const std::vector<std::vector<uint16_t>>& mnemonic_ids,
                               const std::vector<std::string>& wordlist, int iterations,
                               std::vector<std::vector<uint8_t>>& seeds);

  private:
    bool build_kernel(const std::string& kernel_file);
    void cleanup();

    cl_context ctx_ = nullptr;
    cl_command_queue cmdq_ = nullptr;
    cl_program program_ = nullptr;
    cl_kernel kernel_ = nullptr;
    bool initialized_ = false;
    bool is_gpu_ = false;
    std::string device_name_;
};

} // namespace gpu
