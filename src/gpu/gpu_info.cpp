#include "../../include/gpu/gpu_info.hpp"
#include "../../include/cli/ui.hpp"

#include <vector>
#include <string>
#include <print>
#include <algorithm>
#include <format>

using namespace cryptowords::ui;

namespace cryptowords {
namespace gpu {

static std::string get_string_param(cl_device_id device, cl_device_info param) {
    size_t size = 0;
    clGetDeviceInfo(device, param, 0, nullptr, &size);
    if (size == 0) return "";
    std::string result(size, '\0');
    clGetDeviceInfo(device, param, size, result.data(), nullptr);
    while (!result.empty() && (result.back() == '\0' || result.back() == ' ' || result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

static std::string get_platform_string(cl_platform_id platform, cl_platform_info param) {
    size_t size = 0;
    clGetPlatformInfo(platform, param, 0, nullptr, &size);
    if (size == 0) return "";
    std::string result(size, '\0');
    clGetPlatformInfo(platform, param, size, result.data(), nullptr);
    while (!result.empty() && (result.back() == '\0' || result.back() == ' ' || result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

template<typename T>
static T get_num_param(cl_device_id device, cl_device_info param) {
    T value = 0;
    clGetDeviceInfo(device, param, sizeof(T), &value, nullptr);
    return value;
}

std::vector<DiscoveredDevice> enumerate_devices() {
    std::vector<DiscoveredDevice> result;

    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        return result;
    }

    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);

    int best_score = -1;
    size_t best_idx = 0;

    for (cl_uint p = 0; p < num_platforms; ++p) {
        std::string p_name = get_platform_string(platforms[p], CL_PLATFORM_NAME);

        cl_uint num_devices = 0;
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, 0, nullptr, &num_devices);
        if (err != CL_SUCCESS || num_devices == 0) continue;

        std::vector<cl_device_id> devices(num_devices);
        clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, num_devices, devices.data(), nullptr);

        for (cl_uint d = 0; d < num_devices; ++d) {
            cl_device_id dev_id = devices[d];
            DiscoveredDevice dev;
            dev.platform_idx = static_cast<int>(p);
            dev.device_idx = static_cast<int>(d);
            dev.platform_id = platforms[p];
            dev.device_id = dev_id;
            dev.platform_name = p_name;

            dev.device_name = get_string_param(dev_id, CL_DEVICE_NAME);
            dev.vendor = get_string_param(dev_id, CL_DEVICE_VENDOR);
            dev.version = get_string_param(dev_id, CL_DEVICE_VERSION);
            dev.extensions = get_string_param(dev_id, CL_DEVICE_EXTENSIONS);

            dev.device_type = get_num_param<cl_device_type>(dev_id, CL_DEVICE_TYPE);
            dev.compute_units = get_num_param<cl_uint>(dev_id, CL_DEVICE_MAX_COMPUTE_UNITS);
            dev.max_work_group = get_num_param<size_t>(dev_id, CL_DEVICE_MAX_WORK_GROUP_SIZE);
            dev.global_mem = get_num_param<cl_ulong>(dev_id, CL_DEVICE_GLOBAL_MEM_SIZE);
            dev.max_alloc = get_num_param<cl_ulong>(dev_id, CL_DEVICE_MAX_MEM_ALLOC_SIZE);
            dev.local_mem = get_num_param<cl_ulong>(dev_id, CL_DEVICE_LOCAL_MEM_SIZE);
            dev.clock_freq = get_num_param<cl_uint>(dev_id, CL_DEVICE_MAX_CLOCK_FREQUENCY);

            if (dev.device_type & CL_DEVICE_TYPE_GPU) {
                dev.type_str = "GPU (Dedicada/Integrada)";
                dev.score = 10000;
            } else if (dev.device_type & CL_DEVICE_TYPE_ACCELERATOR) {
                dev.type_str = "Acelerador";
                dev.score = 5000;
            } else if (dev.device_type & CL_DEVICE_TYPE_CPU) {
                dev.type_str = "CPU OpenCL";
                dev.score = 500;
            } else {
                dev.type_str = "Outro Dispositivo";
                dev.score = 100;
            }

            // Bonificações heurísticas
            dev.score += static_cast<int>(dev.compute_units) * 150;
            dev.score += static_cast<int>(dev.global_mem / (1024 * 1024 * 512)) * 50; // +50 por 512MB
            dev.score += static_cast<int>(dev.clock_freq / 20);

            // Se for GPU discreta conhecida (NVIDIA, AMD Radeon, etc.)
            std::string d_upper = dev.device_name;
            for (char& c : d_upper) c = static_cast<char>(std::toupper(c));
            if (d_upper.find("RTX") != std::string::npos ||
                d_upper.find("GTX") != std::string::npos ||
                d_upper.find("TESLA") != std::string::npos ||
                d_upper.find("A100") != std::string::npos ||
                d_upper.find("H100") != std::string::npos ||
                d_upper.find("RADEON") != std::string::npos ||
                d_upper.find("RX") != std::string::npos ||
                d_upper.find("ARC") != std::string::npos) {
                dev.score += 2000;
            }

            if (dev.score > best_score) {
                best_score = dev.score;
                best_idx = result.size();
            }

            result.push_back(std::move(dev));
        }
    }

    if (!result.empty()) {
        result[best_idx].is_recommended = true;
    }

    return result;
}

std::optional<DiscoveredDevice> select_device(int req_platform, int req_device) {
    auto devices = enumerate_devices();
    if (devices.empty()) return std::nullopt;

    if (req_platform >= 0 && req_device >= 0) {
        for (const auto& d : devices) {
            if (d.platform_idx == req_platform && d.device_idx == req_device) {
                return d;
            }
        }
        return std::nullopt;
    }

    if (req_platform >= 0) {
        const DiscoveredDevice* best_on_plat = nullptr;
        for (const auto& d : devices) {
            if (d.platform_idx == req_platform) {
                if (!best_on_plat || d.score > best_on_plat->score) {
                    best_on_plat = &d;
                }
            }
        }
        if (best_on_plat) return *best_on_plat;
        return std::nullopt;
    }

    // Auto: retorna o recomendado
    for (const auto& d : devices) {
        if (d.is_recommended) return d;
    }
    return devices.front();
}

void print_device_list() {
    auto devices = enumerate_devices();

    print_box_top("DISPOSITIVOS OPENCL DETECTADOS NO SISTEMA", DEFAULT_INNER_WIDTH);
    if (devices.empty()) {
        print_box_line("  [!] Nenhuma plataforma ou dispositivo OpenCL encontrado no sistema.", DEFAULT_INNER_WIDTH);
        print_box_line("  Certifique-se de ter drivers de GPU (NVIDIA/AMD/Mesa/Intel) instalados.", DEFAULT_INNER_WIDTH);
        print_box_bottom(DEFAULT_INNER_WIDTH);
        return;
    }

    for (size_t i = 0; i < devices.size(); ++i) {
        const auto& d = devices[i];
        std::string badge = d.is_recommended ? " \033[1;32m★ [RECOMENDADO / AUTO]\033[0m" : "";
        std::string header = std::format("\033[1;37m[Plat {}, Dev {}]\033[0m {} - \033[1;36m{}\033[0m{}",
                                         d.platform_idx, d.device_idx, d.platform_name, d.device_name, badge);
        print_box_line(header, DEFAULT_INNER_WIDTH);

        std::string info1 = std::format("   ├─ Tipo: {:<20} │ CUs/SMs: {:<3} │ Clock: {:<4} MHz",
                                        d.type_str, d.compute_units, d.clock_freq);
        print_box_line(info1, DEFAULT_INNER_WIDTH);

        std::string info2 = std::format("   └─ VRAM: {:<5} MB (Max Alloc: {:<4} MB) │ WorkGroup: {:<4} threads",
                                        d.global_mem / (1024 * 1024), d.max_alloc / (1024 * 1024), d.max_work_group);
        print_box_line(info2, DEFAULT_INNER_WIDTH);

        if (i + 1 < devices.size()) {
            print_box_separator(DEFAULT_INNER_WIDTH);
        }
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);
    std::println("\nUse '--gpu-platform <id> --gpu-device <id>' para selecionar manualmente um dispositivo.");
}

void print_device_capabilities(const DiscoveredDevice& d) {
    print_box_top("ACELERAÇÃO POR HARDWARE: PLACA SELECIONADA", DEFAULT_INNER_WIDTH);
    std::string l1 = std::format("Dispositivo  : \033[1;32m{}\033[0m ({})", d.device_name, d.type_str);
    print_box_line(l1, DEFAULT_INNER_WIDTH);

    std::string l2 = std::format("Plataforma   : {} (Versão: {})", d.platform_name, d.version);
    print_box_line(l2, DEFAULT_INNER_WIDTH);

    std::string l3 = std::format("Paralelismo  : {} Compute Units (CUs) │ Max WorkGroup: {} threads",
                                 d.compute_units, d.max_work_group);
    print_box_line(l3, DEFAULT_INNER_WIDTH);

    std::string l4 = std::format("Memória VRAM : {} MB Global │ {} MB Alocação Máxima",
                                 d.global_mem / (1024 * 1024), d.max_alloc / (1024 * 1024));
    print_box_line(l4, DEFAULT_INNER_WIDTH);

    size_t local_sz = (d.max_work_group >= 64) ? 64 : d.max_work_group;
    size_t batch = d.compute_units * local_sz * 16;
    if (d.compute_units <= 4) {
        batch = std::clamp(batch, size_t(512), size_t(1024));
    } else {
        batch = std::clamp(batch, size_t(8192), size_t(131072));
    }
    batch = ((batch + 63) / 64) * 64;

    std::string l5 = std::format("Orquestração : Lotes dinâmicos de \033[1;33m{} chaves simultâneas\033[0m por pulso OpenCL",
                                 format_num(static_cast<double>(batch)));
    print_box_line(l5, DEFAULT_INNER_WIDTH);
    print_box_bottom(DEFAULT_INNER_WIDTH);
}

} // namespace gpu
} // namespace cryptowords
