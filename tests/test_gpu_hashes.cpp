#include <CL/cl.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

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

void check_cl_error(cl_int err, const std::string& msg) {
    if (err != CL_SUCCESS) {
        std::cerr << "Erro OpenCL [" << err << "]: " << msg << std::endl;
        exit(1);
    }
}

int main() {
    std::cout << "[TDD] Iniciando testes de corretude SHA-256 e SHA-512 na GPU...\n";

    cl_int err;
    cl_uint num_platforms;
    err = clGetPlatformIDs(1, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        std::cout << "[!] Nenhuma plataforma OpenCL encontrada para teste.\n";
        return 0;
    }
    cl_platform_id platform;
    clGetPlatformIDs(1, &platform, nullptr);
    
    cl_device_id device;
    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, nullptr);
    check_cl_error(err, "Falha ao obter dispositivo");

    cl_context context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
    cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);

    // ==========================================
    // TESTE SHA-256
    // ==========================================
    std::cout << "\n[1] Testando SHA-256...\n";
    std::string sha256_src = load_kernel("src/opencl/sha256_gpu.cl");
    if (sha256_src.empty()) {
        std::cout << "  [FAIL] Arquivo src/opencl/sha256_gpu.cl nao encontrado!\n";
    } else {
        const char* src_ptr = sha256_src.c_str();
        cl_program prog256 = clCreateProgramWithSource(context, 1, &src_ptr, nullptr, &err);
        err = clBuildProgram(prog256, 1, &device, nullptr, nullptr, nullptr);
        if (err != CL_SUCCESS) {
            size_t log_size;
            clGetProgramBuildInfo(prog256, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
            std::vector<char> log(log_size);
            clGetProgramBuildInfo(prog256, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
            std::cout << "  [FAIL] Falha ao compilar SHA-256. Log:\n" << log.data() << "\n";
        } else {
            cl_kernel k256 = clCreateKernel(prog256, "test_sha256", &err);
            check_cl_error(err, "Falha ao criar kernel SHA-256");

            const char* input_str = "abc";
            size_t input_len = 3;
            cl_mem in_buf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, input_len, (void*)input_str, &err);
            cl_mem out_buf = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32, nullptr, &err);

            clSetKernelArg(k256, 0, sizeof(cl_mem), &in_buf);
            clSetKernelArg(k256, 1, sizeof(unsigned int), &input_len);
            clSetKernelArg(k256, 2, sizeof(cl_mem), &out_buf);

            size_t global_work_size = 1;
            err = clEnqueueNDRangeKernel(queue, k256, 1, nullptr, &global_work_size, nullptr, 0, nullptr, nullptr);
            check_cl_error(err, "Falha ao rodar kernel SHA-256");

            uint8_t out_hash[32] = {0};
            clEnqueueReadBuffer(queue, out_buf, CL_TRUE, 0, 32, out_hash, 0, nullptr, nullptr);

            std::string expected_sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            std::string got_sha256 = to_hex(out_hash, 32);

            if (got_sha256 == expected_sha256) {
                std::cout << "  [PASS] SHA-256 (abc) == " << got_sha256 << "\n";
            } else {
                std::cout << "  [FAIL] SHA-256 (abc) Incorreto!\n";
                std::cout << "         Esperado : " << expected_sha256 << "\n";
                std::cout << "         Recebido : " << got_sha256 << "\n";
            }
        }
    }

    // ==========================================
    // TESTE SHA-512
    // ==========================================
    std::cout << "\n[2] Testando SHA-512...\n";
    std::string sha512_src = load_kernel("src/opencl/sha512_gpu.cl");
    if (sha512_src.empty()) {
        std::cout << "  [FAIL] Arquivo src/opencl/sha512_gpu.cl nao encontrado!\n";
    } else {
        const char* src_ptr = sha512_src.c_str();
        cl_program prog512 = clCreateProgramWithSource(context, 1, &src_ptr, nullptr, &err);
        err = clBuildProgram(prog512, 1, &device, nullptr, nullptr, nullptr);
        if (err != CL_SUCCESS) {
            size_t log_size;
            clGetProgramBuildInfo(prog512, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
            std::vector<char> log(log_size);
            clGetProgramBuildInfo(prog512, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
            std::cout << "  [FAIL] Falha ao compilar SHA-512. Log:\n" << log.data() << "\n";
        } else {
            cl_kernel k512 = clCreateKernel(prog512, "test_sha512", &err);
            check_cl_error(err, "Falha ao criar kernel SHA-512");

            const char* input_str = "abc";
            size_t input_len = 3;
            cl_mem in_buf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, input_len, (void*)input_str, &err);
            cl_mem out_buf = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 64, nullptr, &err);

            clSetKernelArg(k512, 0, sizeof(cl_mem), &in_buf);
            clSetKernelArg(k512, 1, sizeof(unsigned int), &input_len);
            clSetKernelArg(k512, 2, sizeof(cl_mem), &out_buf);

            size_t global_work_size = 1;
            err = clEnqueueNDRangeKernel(queue, k512, 1, nullptr, &global_work_size, nullptr, 0, nullptr, nullptr);
            check_cl_error(err, "Falha ao rodar kernel SHA-512");

            uint8_t out_hash[64] = {0};
            clEnqueueReadBuffer(queue, out_buf, CL_TRUE, 0, 64, out_hash, 0, nullptr, nullptr);

            std::string expected_sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
            std::string got_sha512 = to_hex(out_hash, 64);

            if (got_sha512 == expected_sha512) {
                std::cout << "  [PASS] SHA-512 (abc) == " << got_sha512 << "\n";
            } else {
                std::cout << "  [FAIL] SHA-512 (abc) Incorreto!\n";
                std::cout << "         Esperado : " << expected_sha512 << "\n";
                std::cout << "         Recebido : " << got_sha512 << "\n";
            }
        }
    }

    std::cout << "\n[TDD] Testes finalizados.\n";
    return 0;
}
