#include "../../include/gpu/gpu_engine.hpp"
#include "../../include/gpu/kernels_embedded.hpp"
#include <fstream>
#include <sstream>
#include <print>
#include <cstdlib>
#include <cstring>

namespace cryptowords {

void GPUEngine::cleanup_locked() {
    for (size_t s = 0; s < NUM_SLOTS; ++s) {
        if (ev_read_[s])     { clReleaseEvent(ev_read_[s]); ev_read_[s] = nullptr; }
        if (ev_kernel_[s])   { clReleaseEvent(ev_kernel_[s]); ev_kernel_[s] = nullptr; }
        if (d_passwords_[s]) { clReleaseMemObject(d_passwords_[s]); d_passwords_[s] = nullptr; }
        if (d_pass_lens_[s]) { clReleaseMemObject(d_pass_lens_[s]); d_pass_lens_[s] = nullptr; }
        if (d_out_seeds_[s]) { clReleaseMemObject(d_out_seeds_[s]); d_out_seeds_[s] = nullptr; }
        slot_in_flight_[s] = false;
        slot_hashes_[s] = 0;
    }
    if (d_salt_block_) { clReleaseMemObject(d_salt_block_); d_salt_block_ = nullptr; }
    if (pbkdf2_kernel_) { clReleaseKernel(pbkdf2_kernel_);  pbkdf2_kernel_ = nullptr; }
    if (pbkdf2_prog_)   { clReleaseProgram(pbkdf2_prog_);   pbkdf2_prog_ = nullptr; }
    if (queue_)         { clReleaseCommandQueue(queue_);    queue_ = nullptr; }
    if (context_)       { clReleaseContext(context_);       context_ = nullptr; }
    initialized_ = false;
    active_device_ = std::nullopt;
}

void GPUEngine::cleanup() {
    std::lock_guard<std::mutex> lock(mu_);
    cleanup_locked();
}

GPUEngine::~GPUEngine() {
    cleanup();
}

std::string GPUEngine::load_kernel(const std::string& filename) {
    // 1. Tenta carregar do disco (se o usuário estiver desenvolvendo kernels ou tiver apontado diretório)
    std::vector<std::string> candidates = {
        filename,
        "../" + filename,
        "../../" + filename,
        "/usr/local/share/criptowords/" + filename,
        "/usr/share/criptowords/" + filename
    };

    const char* env_dir = std::getenv("CRYPTOWORDS_KERNEL_DIR");
    if (env_dir) {
        candidates.insert(candidates.begin(), std::string(env_dir) + "/" + filename);
    }

    std::ifstream file;
    for (const auto& path : candidates) {
        file.open(path);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            return buffer.str();
        }
    }

    // 2. Fallback Autônomo e Portátil: usa o kernel embutido no próprio binário!
    return std::string(gpu::PBKDF2_GPU_KERNEL_SRC);
}

bool GPUEngine::init(int platform_id, int device_id, size_t batch_size, const uint64_t* salt_block, bool silent, size_t slot_size) {
    std::lock_guard<std::mutex> lock(mu_);
    if (initialized_) return true;

    slot_size_ = (slot_size > 0) ? slot_size : 256;

    auto chosen = gpu::select_device(platform_id, device_id);
    if (!chosen) {
        std::println(stderr, "\n[✗] ERRO NA SELEÇÃO DE GPU:");
        if (platform_id >= 0 || device_id >= 0) {
            std::println(stderr, "    Dispositivo solicitado [Plat {}, Dev {}] não foi encontrado.", platform_id, device_id);
        } else {
            std::println(stderr, "    Nenhum dispositivo OpenCL compatível encontrado no sistema.");
        }
        std::println(stderr, "    Execute './criptowords --list-gpus' para listar as placas disponíveis.\n");
        return false;
    }

    active_device_ = chosen;
    const auto& dev = *chosen;

    if (!silent) {
        gpu::print_device_capabilities(dev);
    }

    // Ajuste dinâmico do tamanho do lote
    if (batch_size > 0) {
        max_batch_size_ = ((batch_size + 255) / 256) * 256;
    } else {
        size_t local_sz = (dev.max_work_group >= 256) ? 256 : dev.max_work_group;
        size_t calc_batch = dev.compute_units * local_sz * 32;
        if (calc_batch < 8192) calc_batch = 8192;
        if (calc_batch > 65536) calc_batch = 65536;
        max_batch_size_ = ((calc_batch + 255) / 256) * 256;
    }

    cl_int err = CL_SUCCESS;
    cl_device_id d_id = dev.device_id;

    context_ = clCreateContext(nullptr, 1, &d_id, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) {
        std::println(stderr, "Erro ao criar contexto OpenCL: {}", err);
        cleanup_locked();
        return false;
    }

    cl_queue_properties q_props[] = { CL_QUEUE_PROPERTIES, CL_QUEUE_PROFILING_ENABLE, 0 };
    queue_ = clCreateCommandQueueWithProperties(context_, d_id, q_props, &err);
    if (err != CL_SUCCESS) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        queue_ = clCreateCommandQueue(context_, d_id, CL_QUEUE_PROFILING_ENABLE, &err);
#pragma GCC diagnostic pop
        if (err != CL_SUCCESS) {
            std::println(stderr, "Erro ao criar fila de comandos OpenCL com profiling: {}", err);
            cleanup_locked();
            return false;
        }
    }

    std::string pbkdf2_src = load_kernel("src/gpu/kernels/pbkdf2_gpu.cl");
    if (pbkdf2_src.empty()) {
        std::println(stderr, "Erro: Fonte do kernel OpenCL vazio!");
        cleanup_locked();
        return false;
    }

    const char* src_ptr = pbkdf2_src.c_str();
    pbkdf2_prog_ = clCreateProgramWithSource(context_, 1, &src_ptr, nullptr, &err);
    if (err != CL_SUCCESS) {
        std::println(stderr, "Erro ao criar programa OpenCL: {}", err);
        cleanup_locked();
        return false;
    }

    const char* options = "-cl-mad-enable";
    err = clBuildProgram(pbkdf2_prog_, 1, &d_id, options, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        clGetProgramBuildInfo(pbkdf2_prog_, d_id, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string log(log_size, '\0');
        clGetProgramBuildInfo(pbkdf2_prog_, d_id, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        std::println(stderr, "Erro ao compilar kernel OpenCL PBKDF2:\n{}", log);
        cleanup_locked();
        return false;
    }

    pbkdf2_kernel_ = clCreateKernel(pbkdf2_prog_, "pbkdf2_batch", &err);
    if (err != CL_SUCCESS) {
        std::println(stderr, "Erro ao criar kernel pbkdf2_batch: {}", err);
        cleanup_locked();
        return false;
    }

    // Detecção de memória unificada para otimização Zero-Copy em APUs
    cl_bool unified = CL_FALSE;
    clGetDeviceInfo(d_id, CL_DEVICE_HOST_UNIFIED_MEMORY, sizeof(unified), &unified, nullptr);
    is_unified_memory_ = (unified == CL_TRUE);

    // Ajuste dinâmico de workgroup size para máxima ocupação de wavefronts (Wave32/Wave64)
    size_t pref_mul = 0;
    clGetKernelWorkGroupInfo(pbkdf2_kernel_, d_id, CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof(pref_mul), &pref_mul, nullptr);
    if (pref_mul > 0 && pref_mul <= dev.max_work_group) {
        local_work_size_ = pref_mul;
    } else {
        local_work_size_ = (dev.max_work_group >= 64) ? 64 : dev.max_work_group;
    }

    // Alocar os buffers globais com suporte a double-buffering e memória unificada
    cl_mem_flags flags_in = CL_MEM_READ_ONLY;
    cl_mem_flags flags_out = CL_MEM_WRITE_ONLY;
    if (is_unified_memory_) {
        flags_in |= CL_MEM_ALLOC_HOST_PTR;
        flags_out |= CL_MEM_ALLOC_HOST_PTR;
    }

    for (size_t s = 0; s < NUM_SLOTS; ++s) {
        d_passwords_[s] = clCreateBuffer(context_, flags_in, max_batch_size_ * slot_size_, nullptr, &err);
        d_pass_lens_[s] = clCreateBuffer(context_, flags_in, max_batch_size_ * sizeof(uint32_t), nullptr, &err);
        d_out_seeds_[s] = clCreateBuffer(context_, flags_out, max_batch_size_ * 64, nullptr, &err);
        ev_kernel_[s] = nullptr;
        ev_read_[s] = nullptr;
        slot_in_flight_[s] = false;
        slot_hashes_[s] = 0;
        if (err != CL_SUCCESS || !d_passwords_[s] || !d_pass_lens_[s] || !d_out_seeds_[s]) {
            std::println(stderr, "Erro ao alocar buffers na VRAM da GPU para slot {}: {}", s, err);
            cleanup_locked();
            return false;
        }
    }

    uint64_t default_salt[16] = {
        0x6d6e656d6f6e6963ULL, // "mnemonic"
        0x0000000180000000ULL, // INT(1) + 0x80 pad
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1120ULL                // (128 + 8 + 4) * 8
    };
    const void* salt_ptr = salt_block ? salt_block : default_salt;
    d_salt_block_ = clCreateBuffer(context_, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 16 * sizeof(uint64_t), const_cast<void*>(salt_ptr), &err);

    if (err != CL_SUCCESS || !d_salt_block_) {
        std::println(stderr, "Erro ao alocar buffer de salt na VRAM da GPU: {}", err);
        cleanup_locked();
        return false;
    }

    uint32_t slot_sz_u32 = static_cast<uint32_t>(slot_size_);
    err  = clSetKernelArg(pbkdf2_kernel_, 4, sizeof(cl_mem), &d_salt_block_);
    err |= clSetKernelArg(pbkdf2_kernel_, 5, sizeof(uint32_t), &slot_sz_u32);

    if (err != CL_SUCCESS) {
        std::println(stderr, "Erro ao fixar argumentos estáticos do kernel: {}", err);
        cleanup_locked();
        return false;
    }

    initialized_ = true;
    return true;
}

bool GPUEngine::enqueue_batch_async(size_t slot,
                                    const std::vector<uint8_t>& passwords,
                                    const std::vector<uint32_t>& pass_lens,
                                    uint32_t num_hashes,
                                    uint8_t* out_seeds_ptr)
{
    if (!initialized_ || slot >= NUM_SLOTS || num_hashes == 0) return false;
    std::lock_guard<std::mutex> lock(mu_);

    if (slot_in_flight_[slot]) {
        if (ev_read_[slot]) {
            clWaitForEvents(1, &ev_read_[slot]);
            clReleaseEvent(ev_read_[slot]);
            ev_read_[slot] = nullptr;
        } else if (ev_kernel_[slot]) {
            clWaitForEvents(1, &ev_kernel_[slot]);
            clReleaseEvent(ev_kernel_[slot]);
            ev_kernel_[slot] = nullptr;
        }
        slot_in_flight_[slot] = false;
    }

    cl_int err = CL_SUCCESS;
    err |= clEnqueueWriteBuffer(queue_, d_passwords_[slot], CL_FALSE, 0, num_hashes * slot_size_, passwords.data(), 0, nullptr, nullptr);
    err |= clEnqueueWriteBuffer(queue_, d_pass_lens_[slot], CL_FALSE, 0, num_hashes * sizeof(uint32_t), pass_lens.data(), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) return false;

    uint32_t slot_sz_u32 = static_cast<uint32_t>(slot_size_);
    err  = clSetKernelArg(pbkdf2_kernel_, 0, sizeof(cl_mem), &d_passwords_[slot]);
    err |= clSetKernelArg(pbkdf2_kernel_, 1, sizeof(cl_mem), &d_pass_lens_[slot]);
    err |= clSetKernelArg(pbkdf2_kernel_, 2, sizeof(uint32_t), &num_hashes);
    err |= clSetKernelArg(pbkdf2_kernel_, 3, sizeof(cl_mem), &d_out_seeds_[slot]);
    err |= clSetKernelArg(pbkdf2_kernel_, 4, sizeof(cl_mem), &d_salt_block_);
    err |= clSetKernelArg(pbkdf2_kernel_, 5, sizeof(uint32_t), &slot_sz_u32);
    if (err != CL_SUCCESS) return false;

    size_t local_sz = local_work_size_;
    size_t global_sz = ((num_hashes + local_sz - 1) / local_sz) * local_sz;

    err = clEnqueueNDRangeKernel(queue_, pbkdf2_kernel_, 1, nullptr, &global_sz, &local_sz, 0, nullptr, &ev_kernel_[slot]);
    if (err != CL_SUCCESS) return false;

    if (out_seeds_ptr) {
        err = clEnqueueReadBuffer(queue_, d_out_seeds_[slot], CL_FALSE, 0, num_hashes * 64, out_seeds_ptr, 0, nullptr, &ev_read_[slot]);
        if (err != CL_SUCCESS) return false;
    }

    slot_in_flight_[slot] = true;
    slot_hashes_[slot] = num_hashes;
    clFlush(queue_);
    return true;
}

bool GPUEngine::wait_batch(size_t slot) {
    if (slot >= NUM_SLOTS) return false;
    std::lock_guard<std::mutex> lock(mu_);
    if (!initialized_ || !slot_in_flight_[slot]) return false;

    cl_int err = CL_SUCCESS;
    if (ev_read_[slot]) {
        err = clWaitForEvents(1, &ev_read_[slot]);
        clReleaseEvent(ev_read_[slot]);
        ev_read_[slot] = nullptr;
    } else if (ev_kernel_[slot]) {
        err = clWaitForEvents(1, &ev_kernel_[slot]);
        clReleaseEvent(ev_kernel_[slot]);
        ev_kernel_[slot] = nullptr;
    }

    if (ev_kernel_[slot]) {
        clReleaseEvent(ev_kernel_[slot]);
        ev_kernel_[slot] = nullptr;
    }

    slot_in_flight_[slot] = false;
    return (err == CL_SUCCESS);
}

bool GPUEngine::pbkdf2_batch(const std::vector<uint8_t>& passwords,
                             const std::vector<uint32_t>& pass_lens,
                             std::vector<uint8_t>& out_seeds,
                             uint32_t num_hashes)
{
    if (out_seeds.size() < num_hashes * 64) {
        out_seeds.resize(num_hashes * 64);
    }
    if (!enqueue_batch_async(0, passwords, pass_lens, num_hashes, out_seeds.data())) return false;
    return wait_batch(0);
}

bool GPUEngine::pbkdf2_batch_profiled(const std::vector<uint8_t>& passwords,
                                      const std::vector<uint32_t>& pass_lens,
                                      std::vector<uint8_t>& out_seeds,
                                      uint32_t num_hashes,
                                      GpuExecutionMetrics& metrics)
{
    if (!initialized_) return false;
    std::lock_guard<std::mutex> lock(mu_);
    if (num_hashes == 0) return true;

    cl_int err = CL_SUCCESS;
    cl_event ev_write_pw = nullptr;
    cl_event ev_write_len = nullptr;
    cl_event ev_kernel = nullptr;
    cl_event ev_read = nullptr;

    err |= clEnqueueWriteBuffer(queue_, d_passwords_[0], CL_FALSE, 0, num_hashes * slot_size_, passwords.data(), 0, nullptr, &ev_write_pw);
    err |= clEnqueueWriteBuffer(queue_, d_pass_lens_[0], CL_FALSE, 0, num_hashes * sizeof(uint32_t), pass_lens.data(), 0, nullptr, &ev_write_len);
    if (err != CL_SUCCESS) return false;

    uint32_t slot_sz_u32 = static_cast<uint32_t>(slot_size_);
    err  = clSetKernelArg(pbkdf2_kernel_, 0, sizeof(cl_mem), &d_passwords_[0]);
    err |= clSetKernelArg(pbkdf2_kernel_, 1, sizeof(cl_mem), &d_pass_lens_[0]);
    err |= clSetKernelArg(pbkdf2_kernel_, 2, sizeof(uint32_t), &num_hashes);
    err |= clSetKernelArg(pbkdf2_kernel_, 3, sizeof(cl_mem), &d_out_seeds_[0]);
    err |= clSetKernelArg(pbkdf2_kernel_, 4, sizeof(cl_mem), &d_salt_block_);
    err |= clSetKernelArg(pbkdf2_kernel_, 5, sizeof(uint32_t), &slot_sz_u32);
    if (err != CL_SUCCESS) return false;

    size_t local_work_size = local_work_size_;
    size_t global_work_size = ((num_hashes + local_work_size - 1) / local_work_size) * local_work_size;

    err = clEnqueueNDRangeKernel(queue_, pbkdf2_kernel_, 1, nullptr, &global_work_size, &local_work_size, 0, nullptr, &ev_kernel);
    if (err != CL_SUCCESS) return false;

    err = clEnqueueReadBuffer(queue_, d_out_seeds_[0], CL_TRUE, 0, num_hashes * 64, out_seeds.data(), 0, nullptr, &ev_read);
    if (err != CL_SUCCESS) return false;

    cl_ulong pw_start = 0, pw_end = 0, len_start = 0, len_end = 0;
    cl_ulong k_start = 0, k_end = 0, r_start = 0, r_end = 0;

    clGetEventProfilingInfo(ev_write_pw, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &pw_start, nullptr);
    clGetEventProfilingInfo(ev_write_pw, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &pw_end, nullptr);
    clGetEventProfilingInfo(ev_write_len, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &len_start, nullptr);
    clGetEventProfilingInfo(ev_write_len, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &len_end, nullptr);

    clGetEventProfilingInfo(ev_kernel, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &k_start, nullptr);
    clGetEventProfilingInfo(ev_kernel, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &k_end, nullptr);

    clGetEventProfilingInfo(ev_read, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &r_start, nullptr);
    clGetEventProfilingInfo(ev_read, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &r_end, nullptr);

    clReleaseEvent(ev_write_pw);
    clReleaseEvent(ev_write_len);
    clReleaseEvent(ev_kernel);
    clReleaseEvent(ev_read);

    uint64_t w_time = (pw_end > pw_start ? pw_end - pw_start : 0) + (len_end > len_start ? len_end - len_start : 0);
    uint64_t k_time = (k_end > k_start ? k_end - k_start : 1);
    uint64_t r_time = (r_end > r_start ? r_end - r_start : 0);
    uint64_t total_time = (r_end > pw_start ? r_end - pw_start : (w_time + k_time + r_time));

    metrics.write_time_ns = w_time;
    metrics.kernel_time_ns = k_time;
    metrics.read_time_ns = r_time;
    metrics.total_time_ns = total_time;

    double h2d_bytes = static_cast<double>(num_hashes) * (slot_size_ + sizeof(uint32_t));
    double d2h_bytes = static_cast<double>(num_hashes) * 64;

    metrics.bandwidth_h2d_gb_s = (w_time > 0) ? (h2d_bytes / static_cast<double>(w_time)) : 0.0;
    metrics.bandwidth_d2h_gb_s = (r_time > 0) ? (d2h_bytes / static_cast<double>(r_time)) : 0.0;

    double k_sec = static_cast<double>(k_time) / 1e9;
    double tot_sec = static_cast<double>(total_time) / 1e9;

    metrics.kernel_keys_per_sec = (k_sec > 0) ? (num_hashes / k_sec) : 0.0;
    metrics.total_keys_per_sec = (tot_sec > 0) ? (num_hashes / tot_sec) : 0.0;

    return true;
}

} // namespace cryptowords
