#include "../../include/hardware/host_probe.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

#if defined(__x86_64__) || defined(_M_X64)
#include "../../include/hardware/cw_cpuid.hpp"
#endif

#if defined(__linux__)
#include <dirent.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#endif

#include "../../include/gpu/gpu_backend.hpp"

namespace cryptowords {
namespace hardware {

namespace {

std::string trim(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                          s.front() == '\n' || s.front() == '\r')) {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                          s.back() == '\n' || s.back() == '\r' || s.back() == '\0')) {
        s.pop_back();
    }
    return s;
}

size_t parse_size_str(const std::string& str) {
    size_t val = 0;
    char unit = '\0';
    std::stringstream ss(str);
    ss >> val >> unit;
    if (unit == 'K' || unit == 'k')      val *= 1024;
    else if (unit == 'M' || unit == 'm') val *= 1024 * 1024;
    else if (unit == 'G' || unit == 'g') val *= 1024 * 1024 * 1024;
    return val;
}

// -----------------------------------------------------------------------------
// CPUID — captura capacidades e brand string.
// -----------------------------------------------------------------------------

#if defined(__x86_64__) || defined(_M_X64)
void probe_cpuid_basico(CpuInfo& info) {
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;

    // Leaf 0: vendor + max leaf.
    cw_cpuid(0, eax, ebx, ecx, edx);
    char vendor_str[13] = {};
    std::memcpy(vendor_str + 0, &ebx, 4);
    std::memcpy(vendor_str + 4, &edx, 4);
    std::memcpy(vendor_str + 8, &ecx, 4);
    info.vendor = vendor_str;
    unsigned max_leaf = eax;

    // Leaf 1: family/model/stepping + features básicas.
    if (max_leaf >= 1) {
        cw_cpuid(1, eax, ebx, ecx, edx);
        const uint32_t stepping    = eax & 0x0F;
        const uint32_t base_model  = (eax >> 4) & 0x0F;
        const uint32_t base_family = (eax >> 8) & 0x0F;
        const uint32_t ext_model   = (eax >> 16) & 0x0F;
        const uint32_t ext_family  = (eax >> 20) & 0xFF;

        info.raw_stepping = stepping;
        info.raw_family = (base_family == 0x0F) ? (base_family + ext_family) : base_family;
        info.raw_model  = (base_family == 0x06 || base_family == 0x0F)
                              ? ((ext_model << 4) | base_model) : base_model;

        info.caps.sse41  = (ecx & (1u << 19)) != 0;
        info.caps.sse42  = (ecx & (1u << 20)) != 0;
        info.caps.movbe  = (ecx & (1u << 22)) != 0;
        info.caps.popcnt = (ecx & (1u << 23)) != 0;
        info.caps.aes_ni = (ecx & (1u << 25)) != 0;
        info.caps.avx    = (ecx & (1u << 28)) != 0;
    }

    // Leaf 7, subleaf 0: AVX2, AVX-512, SHA-NI, BMI.
    if (max_leaf >= 7) {
        cw_cpuid_count(7, 0, eax, ebx, ecx, edx);
        info.caps.bmi1      = (ebx & (1u <<  3)) != 0;
        info.caps.avx2      = (ebx & (1u <<  5)) != 0;
        info.caps.bmi2      = (ebx & (1u <<  8)) != 0;
        info.caps.avx512f   = (ebx & (1u << 16)) != 0;
        info.caps.adx       = (ebx & (1u << 19)) != 0;
        info.caps.sha_ni    = (ebx & (1u << 29)) != 0;
        info.caps.avx512bw  = (ebx & (1u << 30)) != 0;
        info.caps.avx512vl  = (ebx & (1u << 31)) != 0;

        if ((edx & (1u << 15)) != 0) info.topology.is_hybrid = true;

        // Leaf 7, subleaf 1: Intel SHA-512 (AVX-512 + SHA512 ISA).
        cw_cpuid_count(7, 1, eax, ebx, ecx, edx);
        info.caps.intel_sha512 = (eax & (1u << 0)) != 0;
    }

    if (max_leaf >= 0x1A) {
        cw_cpuid(0x1A, eax, ebx, ecx, edx);
        if (((eax >> 24) & 0xFF) != 0) info.topology.is_hybrid = true;
    }

    if (max_leaf >= 0x24) {
        cw_cpuid_count(0x24, 0, eax, ebx, ecx, edx);
        if ((ebx & 0xFF) > 0) info.caps.avx10 = true;
    }

    // Extended leaves.
    cw_cpuid(0x80000000, eax, ebx, ecx, edx);
    unsigned max_ext_leaf = eax;

    if (max_ext_leaf >= 0x80000001) {
        cw_cpuid(0x80000001, eax, ebx, ecx, edx);
        info.caps.hugepages_1gb = (edx & (1u << 26)) != 0;
    }

    if (max_ext_leaf >= 0x80000004) {
        char brand[49] = {};
        unsigned* p = reinterpret_cast<unsigned*>(brand);
        cw_cpuid(0x80000002, p[0],  p[1],  p[2],  p[3]);
        cw_cpuid(0x80000003, p[4],  p[5],  p[6],  p[7]);
        cw_cpuid(0x80000004, p[8],  p[9],  p[10], p[11]);
        info.brand_string = trim(brand);
    }

    if (max_ext_leaf >= 0x80000007) {
        cw_cpuid(0x80000007, eax, ebx, ecx, edx);
        info.caps.cpb_boost = (edx & (1u << 9)) != 0;
    }

    if (max_ext_leaf >= 0x80000008) {
        cw_cpuid(0x80000008, eax, ebx, ecx, edx);
        info.physical_addr_bits = eax & 0xFF;
        info.virtual_addr_bits  = (eax >> 8) & 0xFF;
        info.caps.clzero        = (ebx & (1u << 0)) != 0;
    }
}
#endif

// Classificação de microarquitetura por brand string. Ordem importa:
// os padrões mais específicos vêm primeiro.
void classify_microarch(CpuInfo& info) {
    if (info.brand_string.empty()) {
        info.brand_string = info.vendor.empty()
                                ? "Generic x86_64 Processor"
                                : info.vendor + " Processor";
    }

    std::string b = info.brand_string;
    for (char& c : b) c = static_cast<char>(std::toupper(c));

    if (b.find("7520U") != std::string::npos || b.find("7320U") != std::string::npos ||
        b.find("MENDOCINO") != std::string::npos) {
        info.microarch_family = "AMD Zen 2 (Mendocino APU, 6nm)";
    } else if (b.find("9950X") != std::string::npos || b.find("9900X") != std::string::npos ||
               (b.find("ZEN 5") != std::string::npos && b.find("RYZEN 5") == std::string::npos)) {
        info.microarch_family = "AMD Zen 5 (AVX-512 Nativo Dual-Issue, 4nm)";
    } else if (b.find("7950X") != std::string::npos || b.find("7900X") != std::string::npos ||
               b.find("7800X3D") != std::string::npos ||
               (b.find("ZEN 4") != std::string::npos && b.find("RYZEN") == std::string::npos)) {
        info.microarch_family = "AMD Zen 4 (AVX-512 Fused, 5nm)";
    } else if (b.find("5950X") != std::string::npos || b.find("5900X") != std::string::npos ||
               b.find("5800X") != std::string::npos || b.find("5600X") != std::string::npos ||
               (b.find("ZEN 3") != std::string::npos && b.find("RYZEN") == std::string::npos)) {
        info.microarch_family = "AMD Zen 3 (Monolithic 8-Core CCX, 7nm)";
    } else if (b.find("3950X") != std::string::npos || b.find("3900X") != std::string::npos ||
               b.find("3800X") != std::string::npos || b.find("3700X") != std::string::npos ||
               b.find("3600") != std::string::npos ||
               (b.find("ZEN 2") != std::string::npos && b.find("RYZEN") == std::string::npos)) {
        info.microarch_family = "AMD Zen 2 (Matisse / Renoir, 7nm)";
    } else if (b.find("THREADRIPPER") != std::string::npos) {
        info.microarch_family = "AMD Ryzen Threadripper High-Core Workstation";
    } else if (b.find("EPYC") != std::string::npos) {
        info.microarch_family = "AMD EPYC Server Enterprise Cluster";
    } else if (b.find("RAPTOR LAKE") != std::string::npos || b.find("14900") != std::string::npos ||
               b.find("13900") != std::string::npos) {
        info.microarch_family = "Intel Raptor Lake (Hybrid P/E Cores, Intel 7)";
    } else if (b.find("ALDER LAKE") != std::string::npos || b.find("12900") != std::string::npos) {
        info.microarch_family = "Intel Alder Lake (Golden Cove, Intel 7)";
    } else if (b.find("ARROW LAKE") != std::string::npos || b.find("LUNAR LAKE") != std::string::npos) {
        info.microarch_family = "Intel Arrow Lake (Native SHA-512 Silicon, TSMC N3B)";
    } else if (b.find("XEON") != std::string::npos) {
        info.microarch_family = "Intel Xeon Enterprise Scalable";
    } else if (info.vendor == "AuthenticAMD") {
        info.microarch_family = "AMD x86_64";
    } else if (info.vendor == "GenuineIntel") {
        info.microarch_family = "Intel x86_64";
    } else {
        info.microarch_family = "Arquitetura x86_64";
    }
}

#if defined(__linux__)

// Topologia: physical_cores, sockets, SMT, lista de IDs físicos.
void probe_topology_sysfs(CpuInfo& info) {
    std::set<int> unique_cores;
    std::set<int> unique_sockets;
    uint32_t logical_count = 0;

    for (int cpu_idx = 0; cpu_idx < 1024; ++cpu_idx) {
        std::string core_path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu_idx) + "/topology/core_id";
        std::ifstream f_core(core_path);
        if (!f_core.is_open()) break;

        int core_id = -1;
        f_core >> core_id;
        unique_cores.insert(core_id);
        info.topology.physical_core_ids.push_back(core_id);
        logical_count++;

        std::string pkg_path =
            "/sys/devices/system/cpu/cpu" + std::to_string(cpu_idx) + "/topology/physical_package_id";
        std::ifstream f_pkg(pkg_path);
        if (f_pkg.is_open()) {
            int pkg_id = -1;
            f_pkg >> pkg_id;
            unique_sockets.insert(pkg_id);
        }
    }

    if (logical_count > 0) {
        info.topology.logical_threads = logical_count;
        info.topology.physical_cores  = static_cast<uint32_t>(unique_cores.size());
        info.topology.sockets         = std::max(1u, static_cast<uint32_t>(unique_sockets.size()));
        info.topology.smt_enabled     = (info.topology.logical_threads > info.topology.physical_cores);
    } else {
        info.topology.logical_threads = std::thread::hardware_concurrency();
        info.topology.physical_cores  = std::max(1u, info.topology.logical_threads / 2);
        info.topology.smt_enabled     = (info.topology.logical_threads > info.topology.physical_cores);
    }
}

// Caches L1d/L1i/L2/L3 do cpu0 (assume homogêneos).
void probe_caches_sysfs(CpuInfo& info) {
    for (int idx = 0; idx < 10; ++idx) {
        std::string base = "/sys/devices/system/cpu/cpu0/cache/index" + std::to_string(idx) + "/";
        std::ifstream f_level(base + "level");
        if (!f_level.is_open()) break;

        int level = 0;
        f_level >> level;
        std::ifstream f_type(base + "type");
        std::string type;
        f_type >> type;
        std::ifstream f_size(base + "size");
        std::string sz_str;
        f_size >> sz_str;
        const size_t sz = parse_size_str(sz_str);

        std::ifstream f_linesz(base + "coherency_line_size");
        if (f_linesz.is_open()) {
            uint32_t lsz = 64;
            f_linesz >> lsz;
            if (lsz > 0) info.cache.cache_line_size = lsz;
        }
        uint32_t ways = 0;
        std::ifstream f_ways(base + "ways_of_associativity");
        if (f_ways.is_open()) f_ways >> ways;
        uint32_t sets = 0;
        std::ifstream f_sets(base + "number_of_sets");
        if (f_sets.is_open()) f_sets >> sets;

        if (level == 1) {
            if (type == "Data") {
                info.cache.l1d_bytes     = sz;
                info.cache.l1d_instances = info.topology.physical_cores;
                info.cache.l1d_ways      = ways;
                info.cache.l1d_sets      = sets;
            } else if (type == "Instruction") {
                info.cache.l1i_bytes = sz;
                info.cache.l1i_ways  = ways;
            }
        } else if (level == 2) {
            info.cache.l2_bytes     = sz;
            info.cache.l2_instances = info.topology.physical_cores;
            info.cache.l2_ways      = ways;
            info.cache.l2_sets      = sets;
        } else if (level == 3) {
            info.cache.l3_bytes     = sz;
            info.cache.l3_instances = 1;
            info.cache.l3_ways      = ways;
            info.cache.l3_sets      = sets;
        }
    }
}

void probe_numa_sysfs(CpuInfo& info) {
    int count = 0;
    for (int n = 0; n < 256; ++n) {
        std::string path = "/sys/devices/system/node/node" + std::to_string(n);
        if (access(path.c_str(), F_OK) == 0) ++count;
        else break;
    }
    info.topology.numa_nodes = std::max(1, count);
}

// Frequências em kHz no sysfs, reportadas em MHz.
void probe_freq_sysfs(CpuInfo& info) {
    auto read_khz = [](const char* path, uint32_t& out_mhz) {
        std::ifstream f(path);
        if (!f.is_open()) return;
        uint64_t khz = 0;
        f >> khz;
        out_mhz = static_cast<uint32_t>(khz / 1000);
    };

    read_khz("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", info.max_clock_mhz);
    read_khz("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq", info.min_clock_mhz);
    read_khz("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency",   info.base_clock_mhz);

    if (info.base_clock_mhz == 0) {
        std::ifstream f("/sys/devices/system/cpu/cpu0/acpi_cppc/nominal_freq");
        if (f.is_open()) f >> info.base_clock_mhz;
    }
    if (info.base_clock_mhz == 0) {
        std::ifstream f("/sys/devices/system/cpu/cpu0/cpufreq/amd_pstate_lowest_nonlinear_freq");
        if (f.is_open()) {
            uint64_t khz = 0;
            f >> khz;
            info.base_clock_mhz = static_cast<uint32_t>(khz / 1000);
        }
    }
    if (info.base_clock_mhz == 0 && info.min_clock_mhz > 0) info.base_clock_mhz = info.min_clock_mhz;

    read_khz("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", info.current_clock_mhz);
}

// CPPC: ranking de silício (golden cores) por CPU lógica.
void probe_cppc_sysfs(CpuInfo& info) {
    std::vector<std::pair<uint32_t, int>> ranking;
    for (uint32_t cpu = 0; cpu < info.topology.logical_threads; ++cpu) {
        std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/acpi_cppc/highest_perf";
        std::ifstream f(path);
        if (f.is_open()) {
            uint32_t hperf = 0;
            f >> hperf;
            info.topology.core_highest_perf.push_back(hperf);
            ranking.push_back({hperf, static_cast<int>(cpu)});
            info.topology.cppc_active = true;
        }
    }
    if (!ranking.empty()) {
        std::stable_sort(ranking.begin(), ranking.end(),
                         [](const auto& a, const auto& b) { return a.first > b.first; });
        for (const auto& p : ranking) info.topology.golden_cores_ranking.push_back(p.second);
    }
}

// Microcódigo, governor, EPP, THP, bogo.
void probe_misc_sysfs(CpuInfo& info) {
    std::ifstream f_ucode("/sys/devices/system/cpu/cpu0/microcode/version");
    if (f_ucode.is_open()) f_ucode >> info.microcode;
    std::ifstream f_gov("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
    if (f_gov.is_open()) f_gov >> info.scaling_governor;
    std::ifstream f_drv("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver");
    if (f_drv.is_open()) f_drv >> info.scaling_driver;
    std::ifstream f_epp("/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference");
    if (f_epp.is_open()) f_epp >> info.epp_preference;

    std::ifstream f_thp("/sys/kernel/mm/transparent_hugepage/enabled");
    if (f_thp.is_open()) {
        std::string line;
        std::getline(f_thp, line);
        info.thp_status = trim(line);
    }

    std::ifstream f_proc("/proc/cpuinfo");
    std::string line;
    while (std::getline(f_proc, line)) {
        if (line.starts_with("bogomips")) {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::stringstream ss(line.substr(colon + 1));
                ss >> info.bogo_mips;
                break;
            }
        }
    }
}

// Classificação P-core / E-core por disparidade de frequência máxima.
void probe_hybrid(CpuInfo& info) {
    std::vector<uint32_t> max_freqs;
    uint32_t highest = 0;
    for (uint32_t cpu = 0; cpu < info.topology.logical_threads; ++cpu) {
        std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpufreq/cpuinfo_max_freq";
        std::ifstream f(path);
        uint32_t mf = 0;
        if (f.is_open()) {
            uint64_t khz = 0;
            f >> khz;
            mf = static_cast<uint32_t>(khz / 1000);
        }
        max_freqs.push_back(mf);
        if (mf > highest) highest = mf;
    }

    bool freq_disparity = false;
    if (highest > 0) {
        for (uint32_t mf : max_freqs) {
            if (mf > 0 && mf + 400 < highest) { freq_disparity = true; break; }
        }
    }

    if (info.topology.is_hybrid || freq_disparity) {
        info.topology.is_hybrid = true;
        for (size_t i = 0; i < max_freqs.size(); ++i) {
            if (max_freqs[i] >= highest - 200) info.topology.p_core_ids.push_back(static_cast<int>(i));
            else                                info.topology.e_core_ids.push_back(static_cast<int>(i));
        }
        info.topology.performance_cores = static_cast<uint32_t>(info.topology.p_core_ids.size());
        info.topology.efficiency_cores  = static_cast<uint32_t>(info.topology.e_core_ids.size());
    } else {
        for (uint32_t i = 0; i < info.topology.logical_threads; ++i)
            info.topology.p_core_ids.push_back(static_cast<int>(i));
        info.topology.performance_cores = info.topology.logical_threads;
        info.topology.efficiency_cores  = 0;
    }
}

#endif  // __linux__

}  // namespace

CpuInfo HostProbe::probe_cpu() {
    CpuInfo info;

#if defined(__x86_64__) || defined(_M_X64)
    probe_cpuid_basico(info);
#endif

    classify_microarch(info);

#if defined(__linux__)
    probe_topology_sysfs(info);
    probe_caches_sysfs(info);
    probe_numa_sysfs(info);
    probe_freq_sysfs(info);
    probe_cppc_sysfs(info);
    probe_misc_sysfs(info);
    probe_hybrid(info);
#else
    info.topology.logical_threads = std::thread::hardware_concurrency();
    info.topology.physical_cores  = info.topology.logical_threads;
#endif

    return info;
}

MemoryInfo HostProbe::probe_memory() {
    MemoryInfo mem;
#if defined(__linux__)
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        mem.total_ram_bytes     = static_cast<uint64_t>(si.totalram) * si.mem_unit;
        mem.available_ram_bytes = static_cast<uint64_t>(si.freeram)  * si.mem_unit;
    }

    std::ifstream f_meminfo("/proc/meminfo");
    std::string line;
    while (std::getline(f_meminfo, line)) {
        if (line.starts_with("MemAvailable:")) {
            std::stringstream ss(line.substr(13));
            uint64_t kb = 0;
            ss >> kb;
            mem.available_ram_bytes = kb * 1024;
        } else if (line.starts_with("Hugepagesize:")) {
            std::stringstream ss(line.substr(13));
            uint64_t kb = 0;
            ss >> kb;
            mem.hugepage_size_bytes = kb * 1024;
        } else if (line.starts_with("HugePages_Total:")) {
            std::stringstream ss(line.substr(16));
            uint64_t total = 0;
            ss >> total;
            if (total > 0) mem.hugepages_available = true;
        }
    }
#endif
    return mem;
}

std::vector<HostGpuDevice> HostProbe::probe_gpus() {
    std::vector<HostGpuDevice> devices;

    auto hip_devs = cryptowords::enumerate_hip_devices();
    devices.reserve(hip_devs.size());

    for (const auto& h : hip_devs) {
        HostGpuDevice dev{};
        dev.platform_idx    = 0;  // HIP não tem "platform"
        dev.device_idx      = h.device_idx;
        dev.platform_name   = "ROCm/HIP";
        dev.device_name     = h.name;
        dev.vendor          = "AMD";
        dev.driver_version  = h.driver_version;

        dev.compute_units            = h.compute_units;
        dev.clock_freq_mhz           = h.clock_mhz;
        dev.global_mem_bytes         = h.vram_bytes;
        dev.max_alloc_bytes          = h.vram_bytes / 2;
        dev.local_mem_bytes          = h.shared_mem_per_block;
        dev.max_work_group           = h.max_threads_per_block;
        dev.preferred_work_group_multiple = h.warp_size;

        const bool is_high_end =
            (h.compute_units >= 60 && h.vram_bytes >= 12ULL * 1024 * 1024 * 1024);

        if (h.is_integrated) {
            dev.category     = GpuCategory::Integrated;
            dev.category_str = "iGPU Integrada (APU)";
            dev.is_discrete  = false;
        } else if (is_high_end) {
            dev.category     = GpuCategory::DiscreteHighEnd;
            dev.category_str = "dGPU High-End";
            dev.is_discrete  = true;
        } else if (h.compute_units >= 16) {
            dev.category     = GpuCategory::DiscreteMidRange;
            dev.category_str = "dGPU Mid-Range";
            dev.is_discrete  = true;
        } else {
            dev.category     = GpuCategory::DiscreteEntry;
            dev.category_str = "dGPU Entry-Level";
            dev.is_discrete  = true;
        }

        dev.compute_index =
            static_cast<double>(dev.compute_units) * (dev.clock_freq_mhz / 1000.0) *
            (dev.is_discrete ? 10.0 : 1.0);

        devices.push_back(std::move(dev));
    }

    return devices;
}

HostProfile HostProbe::probe_all(bool do_probe_gpus) {
    HostProfile profile;
    profile.cpu = probe_cpu();
    profile.memory = probe_memory();
    if (do_probe_gpus) profile.gpus = probe_gpus();

    // OS + arquitetura.
#if defined(__linux__)
    #if defined(__aarch64__)
        profile.os_info = "Linux ARM64";
    #elif defined(__x86_64__)
        profile.os_info = "Linux x86_64";
    #else
        profile.os_info = "Linux (unknown arch)";
    #endif
#elif defined(_WIN32)
    #if defined(_M_ARM64)
        profile.os_info = "Windows ARM64";
    #else
        profile.os_info = "Windows x86_64";
    #endif
#elif defined(__APPLE__)
    #if defined(__aarch64__)
        profile.os_info = "macOS ARM64 (Apple Silicon)";
    #else
        profile.os_info = "macOS x86_64";
    #endif
#else
    profile.os_info = "Unix-like";
#endif

#if defined(__clang__)
    profile.compiler_info = "Clang " + std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__);
#elif defined(__GNUC__)
    profile.compiler_info = "GCC " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
#elif defined(_MSC_VER)
    profile.compiler_info = "MSVC " + std::to_string(_MSC_VER);
#else
    profile.compiler_info = "Unknown C++23 Compiler";
#endif

    return profile;
}

std::vector<int> HostProbe::get_physical_cpu_ids() {
    std::vector<int> primary;
    std::vector<int> secondary;
#if defined(__linux__)
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    bool has_affinity = (sched_getaffinity(0, sizeof(cpu_set_t), &allowed) == 0);

    std::unordered_set<uint64_t> seen_physical_cores;
    for (int cpu = 0; cpu < 4096; ++cpu) {
        std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/core_id";
        std::ifstream f(path);
        if (!f) break;
        if (has_affinity && !CPU_ISSET(cpu, &allowed)) continue;

        int core_id = -1;
        int pkg_id  = 0;
        if (f >> core_id) {
            std::string pkg_path =
                "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/physical_package_id";
            std::ifstream f_pkg(pkg_path);
            if (f_pkg >> pkg_id) {}
            uint64_t key = (static_cast<uint64_t>(pkg_id) << 32) | static_cast<uint32_t>(core_id);
            if (seen_physical_cores.insert(key).second) primary.push_back(cpu);
            else                                        secondary.push_back(cpu);
        }
    }
    for (int s : secondary) primary.push_back(s);
#endif
    if (primary.empty()) {
        const unsigned int total = std::thread::hardware_concurrency();
        for (unsigned int i = 0; i < total; ++i) primary.push_back(static_cast<int>(i));
    }
    return primary;
}

}  // namespace hardware
}  // namespace cryptowords
