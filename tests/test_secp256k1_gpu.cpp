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

std::string to_hex_le(const uint32_t* data, size_t length) {
    std::stringstream ss;
    for(int i = length - 1; i >= 0; --i)
        ss << std::hex << std::setw(8) << std::setfill('0') << data[i];
    return ss.str();
}

int main() {
    std::cout << "[Secp256k1 GPU] Iniciando motor de Curva Eliptica...\n";

    cl_int err;
    cl_platform_id platform;
    clGetPlatformIDs(1, &platform, nullptr);
    cl_device_id device;
    clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, nullptr);

    cl_context context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
    cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);

    std::string src = load_kernel("src/opencl/secp256k1_gpu.cl");
    const char* src_ptr = src.c_str();
    cl_program prog = clCreateProgramWithSource(context, 1, &src_ptr, nullptr, &err);
    err = clBuildProgram(prog, 1, &device, nullptr, nullptr, nullptr);
    
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::vector<char> log(log_size);
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, log_size, log.data(), nullptr);
        std::cout << "  [FAIL] Falha ao compilar SECP256K1. Log:\n" << log.data() << "\n";
        return 1;
    }

    cl_kernel k = clCreateKernel(prog, "test_secp256k1", &err);

    // Test Vector: Private Key = 1 (Expected Public Key = Generator Point G)
    uint32_t priv_key[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint32_t pub_x[8] = {0};
    uint32_t pub_y[8] = {0};

    cl_mem d_priv = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 32, priv_key, &err);
    cl_mem d_pub_x = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32, nullptr, &err);
    cl_mem d_pub_y = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32, nullptr, &err);
    
    clSetKernelArg(k, 0, sizeof(cl_mem), &d_priv);
    clSetKernelArg(k, 1, sizeof(cl_mem), &d_pub_x);
    clSetKernelArg(k, 2, sizeof(cl_mem), &d_pub_y);

    size_t global_work_size = 1;
    clEnqueueNDRangeKernel(queue, k, 1, nullptr, &global_work_size, nullptr, 0, nullptr, nullptr);
    clEnqueueReadBuffer(queue, d_pub_x, CL_TRUE, 0, 32, pub_x, 0, nullptr, nullptr);
    clEnqueueReadBuffer(queue, d_pub_y, CL_TRUE, 0, 32, pub_y, 0, nullptr, nullptr);

    std::string expected_x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    std::string got_x = to_hex_le(pub_x, 8);

    if (got_x == expected_x) {
        std::cout << "  [PASS] Secp256k1 validada! (GPU Point Multiplication)\n";
    } else {
        std::cout << "  [FAIL] Erro matematico na GPU\n         Esperado: " << expected_x << "\n         Recebido: " << got_x << "\n";
    }
    return 0;
}
