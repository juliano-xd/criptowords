#include "../include/gpu_engine.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <print>

namespace cryptowords {

GPUEngine::~GPUEngine() {
    if (d_passwords_) clReleaseMemObject(d_passwords_);
    if (d_pass_lens_) clReleaseMemObject(d_pass_lens_);
    if (d_out_seeds_) clReleaseMemObject(d_out_seeds_);
    if (pbkdf2_kernel_) clReleaseKernel(pbkdf2_kernel_);
    if (pbkdf2_prog_) clReleaseProgram(pbkdf2_prog_);
    if (queue_) clReleaseCommandQueue(queue_);
    if (context_) clReleaseContext(context_);
}

std::string GPUEngine::load_kernel(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool GPUEngine::init() {
    std::lock_guard<std::mutex> lock(mu_);
    if (initialized_) return true;

    cl_int err;
    cl_platform_id platform;
    err = clGetPlatformIDs(1, &platform, nullptr);
    if (err != CL_SUCCESS) return false;

    cl_device_id device;
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, nullptr);
    if (err != CL_SUCCESS) return false;

    context_ = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) return false;

    queue_ = clCreateCommandQueue(context_, device, 0, &err);
    if (err != CL_SUCCESS) return false;

    std::string pbkdf2_src = load_kernel("src/opencl/pbkdf2_gpu.cl");
    if (pbkdf2_src.empty()) {
        std::println(stderr, "Erro: Arquivo src/opencl/pbkdf2_gpu.cl nao encontrado!");
        return false;
    }

    const char* src_ptr = pbkdf2_src.c_str();
    pbkdf2_prog_ = clCreateProgramWithSource(context_, 1, &src_ptr, nullptr, &err);
    
    // Flags de otimizacao extremas para a Radeon
    const char* options = "-cl-mad-enable -cl-strict-aliasing";
    err = clBuildProgram(pbkdf2_prog_, 1, &device, options, nullptr, nullptr);
    
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(pbkdf2_prog_, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string log(log_size, '\0');
        clGetProgramBuildInfo(pbkdf2_prog_, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        std::println(stderr, "Erro ao compilar pbkdf2_gpu.cl:\n{}", log);
        return false;
    }

    pbkdf2_kernel_ = clCreateKernel(pbkdf2_prog_, "pbkdf2_batch", &err);
    if (err != CL_SUCCESS) return false;

    // Alocar os buffers globais massivos
    d_passwords_ = clCreateBuffer(context_, CL_MEM_READ_ONLY, max_batch_size_ * 128, nullptr, &err);
    d_pass_lens_ = clCreateBuffer(context_, CL_MEM_READ_ONLY, max_batch_size_ * 4, nullptr, &err);
    d_out_seeds_ = clCreateBuffer(context_, CL_MEM_WRITE_ONLY, max_batch_size_ * 64, nullptr, &err);

    initialized_ = true;
    return true;
}

bool GPUEngine::pbkdf2_batch(const std::vector<uint8_t>& passwords, 
                             const std::vector<uint32_t>& pass_lens, 
                             std::vector<uint8_t>& out_seeds,
                             uint32_t num_hashes) 
{
    if (!initialized_) return false;
    if (num_hashes == 0) return true;

    cl_int err;
    err = clEnqueueWriteBuffer(queue_, d_passwords_, CL_FALSE, 0, num_hashes * 128, passwords.data(), 0, nullptr, nullptr);
    err |= clEnqueueWriteBuffer(queue_, d_pass_lens_, CL_FALSE, 0, num_hashes * 4, pass_lens.data(), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) return false;

    err = clSetKernelArg(pbkdf2_kernel_, 0, sizeof(cl_mem), &d_passwords_);
    err |= clSetKernelArg(pbkdf2_kernel_, 1, sizeof(cl_mem), &d_pass_lens_);
    err |= clSetKernelArg(pbkdf2_kernel_, 2, sizeof(uint32_t), &num_hashes);
    err |= clSetKernelArg(pbkdf2_kernel_, 3, sizeof(cl_mem), &d_out_seeds_);
    if (err != CL_SUCCESS) return false;

    size_t global_work_size = num_hashes;
    size_t local_work_size = 256; 
    
    // Se o batch for menor que 256, ajuste o local
    if (global_work_size < local_work_size) {
        // Pad to nearest multiple of 256 for optimal hardware dispatch, but since our kernel is strictly reqd_work_group_size(256), 
        // we MUST pass global as a multiple of 256. 
        global_work_size = ((num_hashes + 255) / 256) * 256; 
    } else {
        global_work_size = ((num_hashes + 255) / 256) * 256;
    }

    err = clEnqueueNDRangeKernel(queue_, pbkdf2_kernel_, 1, nullptr, &global_work_size, &local_work_size, 0, nullptr, nullptr);
    if (err != CL_SUCCESS) return false;

    err = clEnqueueReadBuffer(queue_, d_out_seeds_, CL_TRUE, 0, num_hashes * 64, out_seeds.data(), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) return false;

    return true;
}

} // namespace cryptowords
