#pragma once

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <vector>
#include <string>
#include <cstdint>
#include <mutex>

namespace cryptowords {

class GPUEngine {
public:
    static GPUEngine& get_instance() {
        static GPUEngine instance;
        return instance;
    }

    bool init();
    
    // Processa 65536 senhas (ou o batch disponivel) 
    // Retorna as 65536 sementes (64 bytes cada).
    bool pbkdf2_batch(const std::vector<uint8_t>& passwords, 
                      const std::vector<uint32_t>& pass_lens, 
                      std::vector<uint8_t>& out_seeds,
                      uint32_t num_hashes);

private:
    GPUEngine() = default;
    ~GPUEngine();

    GPUEngine(const GPUEngine&) = delete;
    GPUEngine& operator=(const GPUEngine&) = delete;

    std::string load_kernel(const std::string& filename);

    bool initialized_ = false;
    std::mutex mu_;

    cl_context context_ = nullptr;
    cl_command_queue queue_ = nullptr;
    cl_program pbkdf2_prog_ = nullptr;
    cl_kernel pbkdf2_kernel_ = nullptr;

    cl_mem d_passwords_ = nullptr;
    cl_mem d_pass_lens_ = nullptr;
    cl_mem d_out_seeds_ = nullptr;
    
    size_t max_batch_size_ = 65536;
};

} // namespace cryptowords
