#include "../include/gpu_info.hpp"
#include <CL/cl.h>
#include <iostream>
#include <vector>
#include <string>
#include <print>

namespace cryptowords {
namespace gpu {

std::string get_string_info(cl_device_id device, cl_device_info param) {
    size_t size;
    clGetDeviceInfo(device, param, 0, nullptr, &size);
    if (size == 0) return "";
    std::string result(size, '\0');
    clGetDeviceInfo(device, param, size, result.data(), nullptr);
    if(!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

template<typename T>
T get_num_info(cl_device_id device, cl_device_info param) {
    T value = 0;
    clGetDeviceInfo(device, param, sizeof(T), &value, nullptr);
    return value;
}

void detect_and_print_capabilities() {
    std::println("\n[=] Iniciando Sondagem Profunda de Hardware (OpenCL)...");
    
    cl_uint num_platforms = 0;
    clGetPlatformIDs(0, nullptr, &num_platforms);
    if (num_platforms == 0) {
        std::println("    [!] Nenhuma plataforma OpenCL encontrada no sistema.");
        return;
    }

    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);

    for (cl_uint i = 0; i < num_platforms; ++i) {
        cl_uint num_devices = 0;
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL, 0, nullptr, &num_devices);
        if (num_devices == 0) continue;

        std::vector<cl_device_id> devices(num_devices);
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL, num_devices, devices.data(), nullptr);

        for (cl_uint j = 0; j < num_devices; ++j) {
            cl_device_id d = devices[j];
            
            cl_device_type type = get_num_info<cl_device_type>(d, CL_DEVICE_TYPE);
            std::string type_str = (type & CL_DEVICE_TYPE_GPU) ? "GPU Dedicada/Integrada" :
                                   (type & CL_DEVICE_TYPE_CPU) ? "Processador (CPU)" : "Acelerador";

            std::string name = get_string_info(d, CL_DEVICE_NAME);
            std::string vendor = get_string_info(d, CL_DEVICE_VENDOR);
            std::string version = get_string_info(d, CL_DEVICE_VERSION);
            
            cl_uint compute_units = get_num_info<cl_uint>(d, CL_DEVICE_MAX_COMPUTE_UNITS);
            size_t max_work_group = get_num_info<size_t>(d, CL_DEVICE_MAX_WORK_GROUP_SIZE);
            cl_ulong global_mem = get_num_info<cl_ulong>(d, CL_DEVICE_GLOBAL_MEM_SIZE);
            cl_ulong local_mem = get_num_info<cl_ulong>(d, CL_DEVICE_LOCAL_MEM_SIZE);
            cl_ulong max_alloc = get_num_info<cl_ulong>(d, CL_DEVICE_MAX_MEM_ALLOC_SIZE);
            cl_uint clock_freq = get_num_info<cl_uint>(d, CL_DEVICE_MAX_CLOCK_FREQUENCY);
            
            std::println("\n    🖥️  Dispositivo Encontrado: {}", name);
            std::println("    ├─ Tipo: {}", type_str);
            std::println("    ├─ Fabricante: {}", vendor);
            std::println("    ├─ Motor OpenCL: {}", version);
            std::println("    ├─ Compute Units (CUs/SMs): {} núcleos multiprocessadores", compute_units);
            std::println("    ├─ Clock Máximo: {} MHz", clock_freq);
            std::println("    ├─ Tamanho Máximo do WorkGroup: {} threads por bloco", max_work_group);
            std::println("    ├─ VRAM Global: {} MB", global_mem / (1024 * 1024));
            std::println("    ├─ VRAM Alocação Máxima: {} MB", max_alloc / (1024 * 1024));
            std::println("    └─ Memória Compartilhada (L1/Local): {} KB por bloco", local_mem / 1024);
            
            std::string extensions = get_string_info(d, CL_DEVICE_EXTENSIONS);
            std::println("    [+] Capacidades Técnicas Extraídas:");
            if (extensions.find("cl_khr_int64_base_atomics") != std::string::npos)
                std::println("        - Suporte a Operações Atômicas de 64-bits (Essencial para PBKDF2/SHA512)");
            if (extensions.find("cl_khr_fp64") != std::string::npos)
                std::println("        - Precisão Dupla Nativa (FP64)");
            if (extensions.find("cl_nv_pragma_unroll") != std::string::npos || extensions.find("cl_amd_unroll") != std::string::npos)
                std::println("        - Loop Unrolling via Hardware Pragma");
            if (extensions.find("cl_khr_byte_addressable_store") != std::string::npos)
                std::println("        - Acesso a Memória por Byte (Otimização de Array)");

            // ==============================================================
            // CÁLCULO DE PLANEJAMENTO HEURÍSTICO PARA A PLACA ENCONTRADA
            // ==============================================================
            std::println("\n    [⚙️] Motor Dinâmico: Planejando Distribuição Ideal para esta Placa...");
            
            // 1. Determinar o Local Work Size (Tamanho do Bloco)
            // Em algoritmos pesados de Hash (SHA512 tem muitos registradores), 
            // usar o MAX absoluto (ex: 1024) pode causar "Register Spilling" (vazamento pra VRAM lenta).
            // A heurística ideal de criptografia estabiliza em blocos de 256.
            size_t optimal_local_size = (max_work_group >= 256) ? 256 : max_work_group;
            
            // 2. Determinar a Volumetria de Ocupação (Global Work Size)
            // GPUs escondem latência de memória agendando milhares de threads.
            // Para saturar a placa, queremos pelo menos 32 "Waves" por Compute Unit.
            size_t waves_per_cu = 32;
            size_t optimal_global_size = compute_units * optimal_local_size * waves_per_cu;

            // 3. Cálculo de Memória VRAM Exigida (O Custo do PBKDF2)
            // Cada thread precisará salvar o estado intermediário e o hash final (aprox 200 bytes por thread)
            size_t bytes_per_thread = 200; 
            cl_ulong required_vram = optimal_global_size * bytes_per_thread;

            // 4. Adaptação Dinâmica de Memória (Safety Check)
            if (required_vram > max_alloc) {
                std::println("        [!] Atenção: VRAM exigida supera o limite máximo de alocação de um único buffer.");
                std::println("        [!] Redimensionando frotas de threads para caber na memória...");
                // Recalcula o global size para o máximo que a memória suporta
                optimal_global_size = (max_alloc / bytes_per_thread) / optimal_local_size * optimal_local_size;
                required_vram = optimal_global_size * bytes_per_thread;
            }

            double req_vram_mb = required_vram / (1024.0 * 1024.0);

            // 5. Estratégia de Cache (Local Memory)
            // O vetor de salt (a palavra/frase do alvo) e as tabelas mágicas (se houver) 
            // vão pra memória L1 para que todos os workers leiam com latência ZERO.
            size_t local_mem_required = 1024; // 1 KB de uso constante por bloco
            std::string l1_status = (local_mem_required <= local_mem) ? "Seguro (Latência Zero)" : "Gargalo (Spill to Global)";

            std::println("        ├─ Estratégia de Blocos (Local Size): {} workers por bloco", optimal_local_size);
            std::println("        ├─ Saturação de Núcleos (Global Size): {} workers simultâneos em voo", optimal_global_size);
            std::println("        ├─ Consumo VRAM Calculado: {:.2f} MB", req_vram_mb);
            std::println("        ├─ Alocação Dinâmica L1: {} Bytes usados de {} KB disponíveis [{}]", local_mem_required, local_mem/1024, l1_status);
            std::println("        └─ Orquestração: A placa processará lotes de {} chaves por pulso.", optimal_global_size);
        }
    }
}

} // namespace gpu
} // namespace cryptowords
