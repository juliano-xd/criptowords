#include <CL/cl.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <chrono>

std::string load_kernel(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return "";
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string to_hex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    for(size_t i = 0; i < length; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

void check_cl(cl_int err, const std::string& msg) {
    if (err != CL_SUCCESS) {
        std::cerr << "Erro OpenCL [" << err << "]: " << msg << std::endl;
        exit(1);
    }
}

int main() {
    std::cout << "[PBKDF2 GPU] Iniciando motor massivo...\n";

    cl_int err;
    cl_platform_id platform;
    clGetPlatformIDs(1, &platform, nullptr);
    cl_device_id device;
    clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, nullptr);

    cl_context context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
    cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);

    std::string src = load_kernel("src/opencl/pbkdf2_gpu.cl");
    const char* src_ptr = src.c_str();
    cl_program prog = clCreateProgramWithSource(context, 1, &src_ptr, nullptr, &err);
    err = clBuildProgram(prog, 1, &device, nullptr, nullptr, nullptr);
    
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::vector<char> log(log_size);
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        std::cout << "  [FAIL] Falha ao compilar PBKDF2. Log:\n" << log.data() << "\n";
        return 1;
    }

    cl_kernel k = clCreateKernel(prog, "pbkdf2_batch", &err);
    check_cl(err, "Falha ao criar kernel");

    // Preparar batch de 16.384 hashes simultâneos
    size_t batch_size = 16384;
    std::vector<uint8_t> passwords(batch_size * 128, 0);
    std::vector<uint32_t> pass_lens(batch_size, 0);
    
    // A string de teste oficial do vetor BIP39:
    std::string base_pass = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    for (size_t i = 0; i < batch_size; ++i) {
        // Preenche com a mnemônica
        std::memcpy(&passwords[i * 128], base_pass.c_str(), base_pass.size());
        pass_lens[i] = base_pass.size();
    }

    std::vector<uint8_t> outputs(batch_size * 64, 0);

    cl_mem d_pass = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, passwords.size(), passwords.data(), &err);
    cl_mem d_lens = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, pass_lens.size() * 4, pass_lens.data(), &err);
    cl_mem d_outs = clCreateBuffer(context, CL_MEM_WRITE_ONLY, outputs.size(), nullptr, &err);
    
    uint32_t num_hashes = batch_size;
    clSetKernelArg(k, 0, sizeof(cl_mem), &d_pass);
    clSetKernelArg(k, 1, sizeof(cl_mem), &d_lens);
    clSetKernelArg(k, 2, sizeof(uint32_t), &num_hashes);
    clSetKernelArg(k, 3, sizeof(cl_mem), &d_outs);

    std::cout << "  [+] Engatilhando " << batch_size << " hashes PBKDF2 (2048 rounds cada) na GPU...\n";
    
    auto t1 = std::chrono::high_resolution_clock::now();
    
    size_t global_work_size = batch_size;
    // Tenta usar work group size fixo de 256, se possivel
    size_t local_work_size = 256; 
    err = clEnqueueNDRangeKernel(queue, k, 1, nullptr, &global_work_size, &local_work_size, 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // Fallback pra auto-sizing se a placa nao aguentar 256
        err = clEnqueueNDRangeKernel(queue, k, 1, nullptr, &global_work_size, nullptr, 0, nullptr, nullptr);
    }
    check_cl(err, "Falha ao rodar kernel PBKDF2");

    clEnqueueReadBuffer(queue, d_outs, CL_TRUE, 0, outputs.size(), outputs.data(), 0, nullptr, nullptr);
    
    auto t2 = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double>(t2 - t1).count();

    std::string expected = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    std::string got = to_hex(&outputs[0], 64);

    std::cout << "\n[✓] Tempo de execucao (" << batch_size << " senhas): " << std::fixed << std::setprecision(4) << duration << " segundos\n";
    std::cout << "[✓] Hashes por segundo (H/s): " << std::fixed << std::setprecision(2) << (batch_size / duration) << " H/s\n\n";

    if (got == expected) {
        std::cout << "  [PASS] A Semente Mestra Gerada pela GPU esta CORRETA e validada pelo BIP39!\n";
    } else {
        std::cout << "  [FAIL] Falha no PBKDF2\n";
        std::cout << "         Esperado : " << expected << "\n";
        std::cout << "         Recebido : " << got << "\n";
    }

    return 0;
}
