#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <optional>

namespace cryptowords {
namespace hardware {

// Informações de topologia e caches da CPU
struct CpuCacheInfo {
    size_t l1d_bytes = 0;
    size_t l1i_bytes = 0;
    size_t l2_bytes = 0;
    size_t l3_bytes = 0;
    uint32_t l1d_instances = 0;
    uint32_t l2_instances = 0;
    uint32_t l3_instances = 0;
    uint32_t cache_line_size = 64;   // Linha de cache padrão em bytes (64 bytes x86_64)
    uint32_t l1d_ways = 0;           // Associatividade L1d (vias)
    uint32_t l1i_ways = 0;           // Associatividade L1i (vias)
    uint32_t l2_ways = 0;            // Associatividade L2 (vias)
    uint32_t l3_ways = 0;            // Associatividade L3 (vias)
    uint32_t l1d_sets = 0;           // Número de conjuntos L1d
    uint32_t l2_sets = 0;            // Número de conjuntos L2
    uint32_t l3_sets = 0;            // Número de conjuntos L3
};

struct CpuTopology {
    uint32_t logical_threads = 0;
    uint32_t physical_cores = 0;
    uint32_t sockets = 1;
    uint32_t numa_nodes = 1;
    bool smt_enabled = false;
    std::vector<int> physical_core_ids;

    // Topologia Híbrida Heterogênea (P-Cores vs E-Cores)
    bool is_hybrid = false;
    uint32_t performance_cores = 0;
    uint32_t efficiency_cores = 0;
    std::vector<int> p_core_ids;
    std::vector<int> e_core_ids;

    // Classificação de Silício & CPPC (Collaborative Processor Performance Control)
    bool cppc_active = false;
    std::vector<uint32_t> core_highest_perf;    // Pontuação de silício por CPU lógica
    std::vector<int> golden_cores_ranking;      // IDs ordenados por maior desempenho
};

// Extensões essenciais de instruções detectadas via CPUID
struct CpuCapabilities {
    // Vetoriais & SIMD
    bool sse41 = false;
    bool sse42 = false;
    bool avx = false;
    bool avx2 = false;
    bool avx512f = false;
    bool avx512bw = false;
    bool avx512vl = false;
    bool avx10 = false;

    // Criptografia em Silício
    bool sha_ni = false;        // SHA-256 em silício (Intel SHA / AMD Zen)
    bool intel_sha512 = false;  // SHA-512 em silício (Intel Arrow Lake / AMD Zen 5)
    bool aes_ni = false;

    // Manipulação de Bits & Silício
    bool bmi1 = false;
    bool bmi2 = false;
    bool popcnt = false;
    bool movbe = false;
    bool adx = false;
    bool clzero = false;
    bool cpb_boost = false;
    bool hugepages_1gb = false;
};

struct CpuInfo {
    std::string vendor;
    std::string brand_string;
    std::string microarch_family;
    uint32_t raw_family = 0;
    uint32_t raw_model = 0;
    uint32_t raw_stepping = 0;
    std::string microcode;
    uint32_t physical_addr_bits = 0;
    uint32_t virtual_addr_bits = 0;

    CpuTopology topology;
    CpuCacheInfo cache;
    CpuCapabilities caps;

    double bogo_mips = 0.0;
    uint32_t base_clock_mhz = 0;
    uint32_t max_clock_mhz = 0;
    uint32_t min_clock_mhz = 0;
    uint32_t current_clock_mhz = 0;
    std::string scaling_governor;
    std::string scaling_driver;
    std::string epp_preference;
    std::string thp_status;
};


struct MemoryInfo {
    uint64_t total_ram_bytes = 0;
    uint64_t available_ram_bytes = 0;
    uint64_t hugepage_size_bytes = 0;
    bool hugepages_available = false;
};

enum class GpuCategory {
    DiscreteHighEnd,
    DiscreteMidRange,
    DiscreteEntry,
    Integrated,
    UnknownAccelerator
};

struct HostGpuDevice {
    int platform_idx = 0;
    int device_idx = 0;
    std::string platform_name;
    std::string device_name;
    std::string vendor;
    std::string driver_version;
    GpuCategory category = GpuCategory::Integrated;
    std::string category_str;
    uint32_t compute_units = 0;
    size_t max_work_group = 0;
    size_t preferred_work_group_multiple = 32;
    uint64_t global_mem_bytes = 0;
    uint64_t max_alloc_bytes = 0;
    uint64_t local_mem_bytes = 0;
    uint32_t clock_freq_mhz = 0;
    double compute_index = 0.0;
    bool is_discrete = false;
    bool is_recommended = false;
};

struct HostProfile {
    CpuInfo cpu;
    MemoryInfo memory;
    std::vector<HostGpuDevice> gpus;
    std::string os_info;
    std::string compiler_info;
};

class HostProbe {
public:
    static CpuInfo probe_cpu();
    static MemoryInfo probe_memory();
    static std::vector<HostGpuDevice> probe_gpus();
    static HostProfile probe_all(bool do_probe_gpus = true);
    static std::vector<int> get_physical_cpu_ids();
};

} // namespace hardware
} // namespace cryptowords
