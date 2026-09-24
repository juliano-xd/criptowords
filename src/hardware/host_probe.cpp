#include "../../include/hardware/host_probe.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <set>
#include <thread>
#include <cstring>
#include <cctype>

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

#if defined(__linux__)
#include <unistd.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#endif

#ifdef CRYPTOWORDS_HAVE_GPU
#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 300
#endif
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
#endif

namespace cryptowords {
namespace hardware {

static std::string trim(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' || s.front() == '\r')) {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r' || s.back() == '\0')) {
        s.pop_back();
    }
    return s;
}

static size_t parse_size_str(const std::string& str) {
    size_t val = 0;
    char unit = '\0';
    std::stringstream ss(str);
    ss >> val >> unit;
    if (unit == 'K' || unit == 'k') val *= 1024;
    else if (unit == 'M' || unit == 'm') val *= 1024 * 1024;
    else if (unit == 'G' || unit == 'g') val *= 1024 * 1024 * 1024;
    return val;
}

CpuInfo HostProbe::probe_cpu() {
    CpuInfo info;

#if defined(__x86_64__) || defined(_M_X64)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;

    // Leaf 0: Vendor String & max leaf
    __cpuid(0, eax, ebx, ecx, edx);
    char vendor_str[13] = {};
    std::memcpy(vendor_str + 0, &ebx, 4);
    std::memcpy(vendor_str + 4, &edx, 4);
    std::memcpy(vendor_str + 8, &ecx, 4);
    info.vendor = vendor_str;
    unsigned max_leaf = eax;

    // Leaf 1: Family, Model, Stepping, Features
    if (max_leaf >= 1) {
        __cpuid(1, eax, ebx, ecx, edx);
        uint32_t stepping = eax & 0x0F;
        uint32_t base_model = (eax >> 4) & 0x0F;
        uint32_t base_family = (eax >> 8) & 0x0F;
        uint32_t ext_model = (eax >> 16) & 0x0F;
        uint32_t ext_family = (eax >> 20) & 0xFF;

        info.raw_stepping = stepping;
        info.raw_family = (base_family == 0x0F) ? (base_family + ext_family) : base_family;
        info.raw_model = (base_family == 0x06 || base_family == 0x0F) ? ((ext_model << 4) | base_model) : base_model;

        // ECX flags
        info.caps.sse3      = (ecx & (1u << 0)) != 0;
        info.caps.pclmulqdq = (ecx & (1u << 1)) != 0;
        info.caps.intel_vmx = (ecx & (1u << 5)) != 0;
        info.caps.ssse3     = (ecx & (1u << 9)) != 0;
        info.caps.fma3      = (ecx & (1u << 12)) != 0;
        info.caps.sse41     = (ecx & (1u << 19)) != 0;
        info.caps.sse42     = (ecx & (1u << 20)) != 0;
        info.caps.movbe     = (ecx & (1u << 22)) != 0;
        info.caps.popcnt    = (ecx & (1u << 23)) != 0;
        info.caps.aes_ni    = (ecx & (1u << 25)) != 0;
        info.caps.avx       = (ecx & (1u << 28)) != 0;
        info.caps.f16c      = (ecx & (1u << 29)) != 0;
        info.caps.rdrand    = (ecx & (1u << 30)) != 0;

        // EDX flags
        info.caps.clflush   = (edx & (1u << 19)) != 0;
        info.caps.mmx       = (edx & (1u << 23)) != 0;
        info.caps.sse       = (edx & (1u << 25)) != 0;
        info.caps.sse2      = (edx & (1u << 26)) != 0;
    }

    // Leaf 7, Subleaf 0: Extensões AVX2, AVX-512, SHA-NI, BMI, AMX, Memória & Proteção
    if (max_leaf >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        // EBX
        info.caps.fsgsbase  = (ebx & (1u << 0)) != 0;
        info.caps.bmi1      = (ebx & (1u << 3)) != 0;
        info.caps.tsx_hle   = (ebx & (1u << 4)) != 0;
        info.caps.avx2      = (ebx & (1u << 5)) != 0;
        info.caps.smep      = (ebx & (1u << 7)) != 0;
        info.caps.bmi2      = (ebx & (1u << 8)) != 0;
        info.caps.erms      = (ebx & (1u << 9)) != 0;
        info.caps.tsx_rtm   = (ebx & (1u << 11)) != 0;
        info.caps.avx512f   = (ebx & (1u << 16)) != 0;
        info.caps.avx512dq  = (ebx & (1u << 17)) != 0;
        info.caps.rdseed    = (ebx & (1u << 18)) != 0;
        info.caps.adx       = (ebx & (1u << 19)) != 0;
        info.caps.smap      = (ebx & (1u << 20)) != 0;
        info.caps.avx512ifma= (ebx & (1u << 21)) != 0;
        info.caps.clflushopt= (ebx & (1u << 23)) != 0;
        info.caps.clwb      = (ebx & (1u << 24)) != 0;
        info.caps.avx512pf  = (ebx & (1u << 26)) != 0;
        info.caps.avx512er  = (ebx & (1u << 27)) != 0;
        info.caps.avx512cd  = (ebx & (1u << 28)) != 0;
        info.caps.sha_ni    = (ebx & (1u << 29)) != 0;
        info.caps.avx512bw  = (ebx & (1u << 30)) != 0;
        info.caps.avx512vl  = (ebx & (1u << 31)) != 0;

        // ECX
        info.caps.prefetchwt1  = (ecx & (1u << 0)) != 0;
        info.caps.avx512vbmi   = (ecx & (1u << 1)) != 0;
        info.caps.umip         = (ecx & (1u << 2)) != 0;
        info.caps.pku_ospke    = (ecx & (1u << 3)) != 0;
        info.caps.waitpkg      = (ecx & (1u << 5)) != 0;
        info.caps.avx512vbmi2  = (ecx & (1u << 6)) != 0;
        info.caps.cet_ss       = (ecx & (1u << 7)) != 0;
        info.caps.gfni         = (ecx & (1u << 8)) != 0;
        info.caps.vaes         = (ecx & (1u << 9)) != 0;
        info.caps.vpclmulqdq   = (ecx & (1u << 10)) != 0;
        info.caps.avx512vnni   = (ecx & (1u << 11)) != 0;
        info.caps.avx512bitalg = (ecx & (1u << 12)) != 0;
        info.caps.avx512vpopcntdq = (ecx & (1u << 14)) != 0;
        info.caps.la57         = (ecx & (1u << 16)) != 0;
        info.caps.rdpid        = (ecx & (1u << 22)) != 0;
        info.caps.key_locker   = (ecx & (1u << 23)) != 0;
        info.caps.cldemote     = (ecx & (1u << 25)) != 0;
        info.caps.movdiri      = (ecx & (1u << 27)) != 0;
        info.caps.movdir64b    = (ecx & (1u << 28)) != 0;
        info.caps.enqcmd       = (ecx & (1u << 29)) != 0;

        // EDX
        info.caps.avx512_4fmaps= (edx & (1u << 2)) != 0;
        info.caps.avx512_4vnniw= (edx & (1u << 3)) != 0;
        info.caps.fsrm         = (edx & (1u << 4)) != 0;
        info.caps.avx512_vp2intersect = (edx & (1u << 8)) != 0;
        info.caps.serialize    = (edx & (1u << 14)) != 0;
        if ((edx & (1u << 15)) != 0) info.topology.is_hybrid = true;
        info.caps.cet_ibt      = (edx & (1u << 20)) != 0;
        info.caps.amx_bf16     = (edx & (1u << 22)) != 0;
        info.caps.avx512fp16   = (edx & (1u << 23)) != 0;
        info.caps.amx_tile     = (edx & (1u << 24)) != 0;
        info.caps.amx_int8     = (edx & (1u << 25)) != 0;

        // Leaf 7, Subleaf 1 (CPUID.(07H,01H)): Intel SHA-512, SM3/SM4, AMX, APX.
        // EAX: SHA512[0] SM3[1] SM4[2] RAOINT[3] AVXVNNI[4] AVX512BF16[5]
        //      CMPCCXADD[7] AMX_COMPLEX[8] AMX_FP16[21] AVXIFMA[23]
        // EDX: AVXVNNIINT8[4] AVXNECONVERT[5] AVXVNNIINT16[10] PREFETCHI[14] APX_F[21]
        __cpuid_count(7, 1, eax, ebx, ecx, edx);
        info.caps.intel_sha512 = (eax & (1u << 0)) != 0;
        info.caps.sm3          = (eax & (1u << 1)) != 0;
        info.caps.sm4          = (eax & (1u << 2)) != 0;
        info.caps.rao_int      = (eax & (1u << 3)) != 0;
        info.caps.avx_vnni     = (eax & (1u << 4)) != 0;
        info.caps.avx512bf16   = (eax & (1u << 5)) != 0;
        info.caps.cmpccxadd    = (eax & (1u << 7)) != 0;
        info.caps.amx_complex  = (eax & (1u << 8)) != 0;
        info.caps.amx_fp16     = (eax & (1u << 21)) != 0;
        info.caps.avx_ifma     = (eax & (1u << 23)) != 0;

        info.caps.avx_vnni_int8  = (edx & (1u << 4)) != 0;
        info.caps.avx_ne_convert = (edx & (1u << 5)) != 0;
        info.caps.avx_vnni_int16 = (edx & (1u << 10)) != 0;
        info.caps.prefetchi      = (edx & (1u << 14)) != 0;
        info.caps.apx            = (edx & (1u << 21)) != 0;
    }

    // Leaf 0x1A: Hybrid Information (P-cores vs E-cores)
    if (max_leaf >= 0x1A) {
        __cpuid(0x1A, eax, ebx, ecx, edx);
        uint32_t core_type = (eax >> 24) & 0xFF;
        if (core_type != 0) {
            info.topology.is_hybrid = true;
        }
    }

    // Leaf 0x24: AVX10
    if (max_leaf >= 0x24) {
        __cpuid_count(0x24, 0, eax, ebx, ecx, edx);
        if ((ebx & 0xFF) > 0) info.caps.avx10 = true;
    }

    // Extended Leaves 0x80000000+
    __cpuid(0x80000000, eax, ebx, ecx, edx);
    unsigned max_ext_leaf = eax;

    if (max_ext_leaf >= 0x80000001) {
        __cpuid(0x80000001, eax, ebx, ecx, edx);
        info.caps.amd_svm      = (ecx & (1u << 2)) != 0;
        info.caps.lzcnt_abm    = (ecx & (1u << 5)) != 0;
        info.caps.sse4a        = (ecx & (1u << 6)) != 0;
        info.caps.misalignsse  = (ecx & (1u << 7)) != 0;
        info.caps.prefetchw    = (ecx & (1u << 8)) != 0;
        info.caps.xop          = (ecx & (1u << 11)) != 0;
        info.caps.fma4         = (ecx & (1u << 16)) != 0;
        info.caps.tbm          = (ecx & (1u << 21)) != 0;
        info.caps.mwaitx       = (ecx & (1u << 29)) != 0;

        info.caps.hugepages_1gb = (edx & (1u << 26)) != 0;
        info.caps.rdtscp        = (edx & (1u << 27)) != 0;
    }

    if (max_ext_leaf >= 0x80000004) {
        char brand[49] = {};
        unsigned* p = reinterpret_cast<unsigned*>(brand);
        __cpuid(0x80000002, p[0], p[1], p[2], p[3]);
        __cpuid(0x80000003, p[4], p[5], p[6], p[7]);
        __cpuid(0x80000004, p[8], p[9], p[10], p[11]);
        info.brand_string = trim(brand);
    }

    if (max_ext_leaf >= 0x80000007) {
        __cpuid(0x80000007, eax, ebx, ecx, edx);
        info.caps.invariant_tsc = (edx & (1u << 8)) != 0;
        info.caps.cpb_boost     = (edx & (1u << 9)) != 0;
    }

    if (max_ext_leaf >= 0x80000008) {
        __cpuid(0x80000008, eax, ebx, ecx, edx);
        info.physical_addr_bits = eax & 0xFF;
        info.virtual_addr_bits  = (eax >> 8) & 0xFF;
        info.caps.clzero        = (ebx & (1u << 0)) != 0;
        info.caps.rdpru         = (ebx & (1u << 4)) != 0;
    }

    if (max_ext_leaf >= 0x8000001F) {
        __cpuid(0x8000001F, eax, ebx, ecx, edx);
        info.caps.sme     = (eax & (1u << 0)) != 0;
        info.caps.sev     = (eax & (1u << 1)) != 0;
        info.caps.sev_snp = (eax & (1u << 4)) != 0;
    }
#endif

    if (info.brand_string.empty()) {
        info.brand_string = info.vendor.empty() ? "Generic x86_64 Processor" : info.vendor + " Processor";
    }

    // Identificação de família / microarquitetura
    std::string b_upper = info.brand_string;
    for (char& c : b_upper) c = static_cast<char>(std::toupper(c));

    if (b_upper.find("7520U") != std::string::npos || b_upper.find("7320U") != std::string::npos || b_upper.find("MENDOCINO") != std::string::npos) {
        info.microarch_family = "AMD Zen 2 (Mendocino APU, 6nm)";
    } else if (b_upper.find("9950X") != std::string::npos || b_upper.find("9900X") != std::string::npos || (b_upper.find("ZEN 5") != std::string::npos && b_upper.find("RYZEN 5") == std::string::npos)) {
        info.microarch_family = "AMD Zen 5 (AVX-512 Nativo Dual-Issue, 4nm)";
    } else if (b_upper.find("7950X") != std::string::npos || b_upper.find("7900X") != std::string::npos || b_upper.find("7800X3D") != std::string::npos || (b_upper.find("ZEN 4") != std::string::npos && b_upper.find("RYZEN") == std::string::npos)) {
        info.microarch_family = "AMD Zen 4 (AVX-512 Fused, 5nm)";
    } else if (b_upper.find("5950X") != std::string::npos || b_upper.find("5900X") != std::string::npos || b_upper.find("5800X") != std::string::npos || b_upper.find("5600X") != std::string::npos || (b_upper.find("ZEN 3") != std::string::npos && b_upper.find("RYZEN") == std::string::npos)) {
        info.microarch_family = "AMD Zen 3 (Monolithic 8-Core CCX, 7nm)";
    } else if (b_upper.find("3950X") != std::string::npos || b_upper.find("3900X") != std::string::npos || b_upper.find("3800X") != std::string::npos || b_upper.find("3700X") != std::string::npos || b_upper.find("3600") != std::string::npos || (b_upper.find("ZEN 2") != std::string::npos && b_upper.find("RYZEN") == std::string::npos)) {
        info.microarch_family = "AMD Zen 2 (Matisse / Renoir, 7nm)";
    } else if (b_upper.find("THREADRIPPER") != std::string::npos) {
        info.microarch_family = "AMD Ryzen Threadripper High-Core Workstation";
    } else if (b_upper.find("EPYC") != std::string::npos) {
        info.microarch_family = "AMD EPYC Server Enterprise Cluster";
    } else if (b_upper.find("RAPTOR LAKE") != std::string::npos || b_upper.find("14900") != std::string::npos || b_upper.find("13900") != std::string::npos) {
        info.microarch_family = "Intel Raptor Lake (Hybrid P/E Cores, Intel 7)";
    } else if (b_upper.find("ALDER LAKE") != std::string::npos || b_upper.find("12900") != std::string::npos) {
        info.microarch_family = "Intel Alder Lake (Golden Cove, Intel 7)";
    } else if (b_upper.find("ARROW LAKE") != std::string::npos || b_upper.find("LUNAR LAKE") != std::string::npos) {
        info.microarch_family = "Intel Arrow Lake (Native SHA-512 Silicon, TSMC N3B)";
    } else if (b_upper.find("XEON") != std::string::npos) {
        info.microarch_family = "Intel Xeon Enterprise Scalable";
    } else if (info.vendor == "AuthenticAMD") {
        info.microarch_family = "AMD x86_64";
    } else if (info.vendor == "GenuineIntel") {
        info.microarch_family = "Intel x86_64";
    } else {
        info.microarch_family = "Arquitetura x86_64";
    }

    // Topologia de núcleos e Caches via Linux sysfs
#if defined(__linux__)
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

        std::string pkg_path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu_idx) + "/topology/physical_package_id";
        std::ifstream f_pkg(pkg_path);
        if (f_pkg.is_open()) {
            int pkg_id = -1;
            f_pkg >> pkg_id;
            unique_sockets.insert(pkg_id);
        }
    }

    if (logical_count > 0) {
        info.topology.logical_threads = logical_count;
        info.topology.physical_cores = static_cast<uint32_t>(unique_cores.size());
        info.topology.sockets = std::max(1u, static_cast<uint32_t>(unique_sockets.size()));
        info.topology.smt_enabled = (info.topology.logical_threads > info.topology.physical_cores);
    } else {
        info.topology.logical_threads = std::thread::hardware_concurrency();
        info.topology.physical_cores = std::max(1u, info.topology.logical_threads / 2);
        info.topology.smt_enabled = (info.topology.logical_threads > info.topology.physical_cores);
    }

    // Leitura dos caches em /sys/devices/system/cpu/cpu0/cache/
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
        size_t sz = parse_size_str(sz_str);

        // Coherency line size
        std::ifstream f_linesz(base + "coherency_line_size");
        if (f_linesz.is_open()) {
            uint32_t lsz = 64;
            f_linesz >> lsz;
            if (lsz > 0) info.cache.cache_line_size = lsz;
        }
        // Ways of associativity
        uint32_t ways = 0;
        std::ifstream f_ways(base + "ways_of_associativity");
        if (f_ways.is_open()) f_ways >> ways;

        // Number of sets
        uint32_t sets = 0;
        std::ifstream f_sets(base + "number_of_sets");
        if (f_sets.is_open()) f_sets >> sets;

        if (level == 1) {
            if (type == "Data") {
                info.cache.l1d_bytes = sz;
                info.cache.l1d_instances = info.topology.physical_cores;
                info.cache.l1d_ways = ways;
                info.cache.l1d_sets = sets;
            } else if (type == "Instruction") {
                info.cache.l1i_bytes = sz;
                info.cache.l1i_ways = ways;
            }
        } else if (level == 2) {
            info.cache.l2_bytes = sz;
            info.cache.l2_instances = info.topology.physical_cores;
            info.cache.l2_ways = ways;
            info.cache.l2_sets = sets;
        } else if (level == 3) {
            info.cache.l3_bytes = sz;
            info.cache.l3_instances = 1;
            info.cache.l3_ways = ways;
            info.cache.l3_sets = sets;
        }
    }

    // NUMA nodes
    int numa_count = 0;
    for (int n = 0; n < 256; ++n) {
        std::string n_path = "/sys/devices/system/node/node" + std::to_string(n);
        std::ifstream f_n(n_path);
        if (access(n_path.c_str(), F_OK) == 0) numa_count++;
        else break;
    }
    info.topology.numa_nodes = std::max(1, numa_count);

    // Frequências do CPU (MHz)
    std::ifstream f_max_freq("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
    if (f_max_freq.is_open()) {
        uint64_t khz = 0;
        f_max_freq >> khz;
        info.max_clock_mhz = static_cast<uint32_t>(khz / 1000);
    }
    std::ifstream f_min_freq("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
    if (f_min_freq.is_open()) {
        uint64_t khz = 0;
        f_min_freq >> khz;
        info.min_clock_mhz = static_cast<uint32_t>(khz / 1000);
    }
    std::ifstream f_base_freq("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency");
    if (f_base_freq.is_open()) {
        uint64_t khz = 0;
        f_base_freq >> khz;
        info.base_clock_mhz = static_cast<uint32_t>(khz / 1000);
    }
    // Fallback para frequência base caso ausente no sysfs padrão (comum em chips AMD)
    if (info.base_clock_mhz == 0) {
        std::ifstream f_cppc_nom("/sys/devices/system/cpu/cpu0/acpi_cppc/nominal_freq");
        if (f_cppc_nom.is_open()) {
            f_cppc_nom >> info.base_clock_mhz;
        }
    }
    if (info.base_clock_mhz == 0) {
        std::ifstream f_amd_nom("/sys/devices/system/cpu/cpu0/cpufreq/amd_pstate_lowest_nonlinear_freq");
        if (f_amd_nom.is_open()) {
            uint64_t khz = 0;
            f_amd_nom >> khz;
            info.base_clock_mhz = static_cast<uint32_t>(khz / 1000);
        }
    }
    if (info.base_clock_mhz == 0 && info.min_clock_mhz > 0) {
        info.base_clock_mhz = info.min_clock_mhz;
    }

    std::ifstream f_cur_freq("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq");
    if (f_cur_freq.is_open()) {
        uint64_t khz = 0;
        f_cur_freq >> khz;
        info.current_clock_mhz = static_cast<uint32_t>(khz / 1000);
    }

    // ACPI CPPC & Ranking de Silício (Golden Cores)
    std::vector<std::pair<uint32_t, int>> perf_ranking;
    for (uint32_t cpu_idx = 0; cpu_idx < info.topology.logical_threads; ++cpu_idx) {
        std::string cppc_path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu_idx) + "/acpi_cppc/highest_perf";
        std::ifstream f_cppc(cppc_path);
        if (f_cppc.is_open()) {
            uint32_t hperf = 0;
            f_cppc >> hperf;
            info.topology.core_highest_perf.push_back(hperf);
            perf_ranking.push_back({hperf, static_cast<int>(cpu_idx)});
            info.topology.cppc_active = true;
        }
    }
    if (!perf_ranking.empty()) {
        std::stable_sort(perf_ranking.begin(), perf_ranking.end(), [](const auto& a, const auto& b) {
            return a.first > b.first;
        });
        for (const auto& p : perf_ranking) {
            info.topology.golden_cores_ranking.push_back(p.second);
        }
    }

    // Transparent Huge Pages (THP)
    std::ifstream f_thp("/sys/kernel/mm/transparent_hugepage/enabled");
    if (f_thp.is_open()) {
        std::string thp_line;
        std::getline(f_thp, thp_line);
        info.thp_status = trim(thp_line);
    }

    // Classificação de Núcleos Híbridos (P-Cores vs E-Cores)
    std::vector<uint32_t> max_freqs;
    uint32_t highest_max = 0;
    for (uint32_t cpu_idx = 0; cpu_idx < info.topology.logical_threads; ++cpu_idx) {
        std::string freq_p = "/sys/devices/system/cpu/cpu" + std::to_string(cpu_idx) + "/cpufreq/cpuinfo_max_freq";
        std::ifstream f_mf(freq_p);
        uint32_t mf = 0;
        if (f_mf.is_open()) {
            uint64_t khz = 0;
            f_mf >> khz;
            mf = static_cast<uint32_t>(khz / 1000);
        }
        max_freqs.push_back(mf);
        if (mf > highest_max) highest_max = mf;
    }
    bool freq_disparity = false;
    if (highest_max > 0) {
        for (uint32_t mf : max_freqs) {
            if (mf > 0 && mf + 400 < highest_max) {
                freq_disparity = true;
                break;
            }
        }
    }
    if (info.topology.is_hybrid || freq_disparity) {
        info.topology.is_hybrid = true;
        for (size_t i = 0; i < max_freqs.size(); ++i) {
            if (max_freqs[i] >= highest_max - 200) {
                info.topology.p_core_ids.push_back(static_cast<int>(i));
            } else {
                info.topology.e_core_ids.push_back(static_cast<int>(i));
            }
        }
        info.topology.performance_cores = static_cast<uint32_t>(info.topology.p_core_ids.size());
        info.topology.efficiency_cores = static_cast<uint32_t>(info.topology.e_core_ids.size());
    } else {
        for (uint32_t i = 0; i < info.topology.logical_threads; ++i) {
            info.topology.p_core_ids.push_back(static_cast<int>(i));
        }
        info.topology.performance_cores = info.topology.logical_threads;
        info.topology.efficiency_cores = 0;
    }

    // Microcódigo, Governor, Driver, EPP
    std::ifstream f_ucode("/sys/devices/system/cpu/cpu0/microcode/version");
    if (f_ucode.is_open()) {
        f_ucode >> info.microcode;
    }
    std::ifstream f_gov("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
    if (f_gov.is_open()) {
        f_gov >> info.scaling_governor;
    }
    std::ifstream f_driver("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver");
    if (f_driver.is_open()) {
        f_driver >> info.scaling_driver;
    }
    std::ifstream f_epp("/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference");
    if (f_epp.is_open()) {
        f_epp >> info.epp_preference;
    }

    // BogoMIPS de /proc/cpuinfo
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
#else
    info.topology.logical_threads = std::thread::hardware_concurrency();
    info.topology.physical_cores = info.topology.logical_threads;
#endif

    return info;
}

MemoryInfo HostProbe::probe_memory() {

    MemoryInfo mem;
#if defined(__linux__)
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        mem.total_ram_bytes = static_cast<uint64_t>(si.totalram) * si.mem_unit;
        mem.available_ram_bytes = static_cast<uint64_t>(si.freeram) * si.mem_unit;
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

#ifdef CRYPTOWORDS_HAVE_GPU
    cl_uint num_platforms = 0;
    cl_int err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) return devices;

    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);

    int best_score = -1;
    size_t best_idx = 0;

    for (cl_uint p = 0; p < num_platforms; ++p) {
        size_t p_size = 0;
        clGetPlatformInfo(platforms[p], CL_PLATFORM_NAME, 0, nullptr, &p_size);
        std::string p_name(p_size, '\0');
        clGetPlatformInfo(platforms[p], CL_PLATFORM_NAME, p_size, p_name.data(), nullptr);
        p_name = trim(p_name);

        cl_uint num_devices = 0;
        err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, 0, nullptr, &num_devices);
        if (err != CL_SUCCESS || num_devices == 0) continue;

        std::vector<cl_device_id> dev_ids(num_devices);
        clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, num_devices, dev_ids.data(), nullptr);

        for (cl_uint d = 0; d < num_devices; ++d) {
            cl_device_id dev_id = dev_ids[d];
            HostGpuDevice dev;
            dev.platform_idx = static_cast<int>(p);
            dev.device_idx = static_cast<int>(d);
            dev.platform_name = p_name;

            // Leitura de strings
            auto read_str = [&](cl_device_info param) {
                size_t sz = 0;
                clGetDeviceInfo(dev_id, param, 0, nullptr, &sz);
                if (sz == 0) return std::string();
                std::string s(sz, '\0');
                clGetDeviceInfo(dev_id, param, sz, s.data(), nullptr);
                return trim(s);
            };

            dev.device_name = read_str(CL_DEVICE_NAME);
            dev.vendor = read_str(CL_DEVICE_VENDOR);
            dev.driver_version = read_str(CL_DRIVER_VERSION);

            cl_device_type dev_type = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_TYPE, sizeof(dev_type), &dev_type, nullptr);

            cl_uint cus = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, nullptr);
            dev.compute_units = cus;

            size_t mwg = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(mwg), &mwg, nullptr);
            dev.max_work_group = mwg;

            cl_ulong gmem = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gmem), &gmem, nullptr);
            dev.global_mem_bytes = gmem;

            cl_ulong max_alloc = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(max_alloc), &max_alloc, nullptr);
            dev.max_alloc_bytes = max_alloc;

            cl_ulong lmem = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_LOCAL_MEM_SIZE, sizeof(lmem), &lmem, nullptr);
            dev.local_mem_bytes = lmem;

            cl_uint clock = 0;
            clGetDeviceInfo(dev_id, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(clock), &clock, nullptr);
            dev.clock_freq_mhz = clock;

            // Classificação inteligente da GPU
            std::string name_upper = dev.device_name;
            for (char& c : name_upper) c = static_cast<char>(std::toupper(c));

            std::string p_name_upper = p_name;
            for (char& c : p_name_upper) c = static_cast<char>(std::toupper(c));

            bool is_cpu_emulator = (dev_type & CL_DEVICE_TYPE_CPU) != 0 ||
                                   name_upper.find("POCL") != std::string::npos ||
                                   name_upper.find("CPU") != std::string::npos ||
                                   p_name_upper.find("PORTABLE COMPUTING") != std::string::npos ||
                                   p_name_upper.find("POCL") != std::string::npos;

            bool name_is_integrated = (name_upper.find("610M") != std::string::npos ||
                                       name_upper.find("680M") != std::string::npos ||
                                       name_upper.find("780M") != std::string::npos ||
                                       name_upper.find("VEGA") != std::string::npos ||
                                       name_upper.find("UHD") != std::string::npos ||
                                       name_upper.find("IRIS") != std::string::npos ||
                                       name_upper.find("INTEGRATED") != std::string::npos);

            bool name_is_high_end = (name_upper.find("RTX 4090") != std::string::npos ||
                                     name_upper.find("RTX 4080") != std::string::npos ||
                                     name_upper.find("RTX 3090") != std::string::npos ||
                                     name_upper.find("7900 XTX") != std::string::npos ||
                                     name_upper.find("7900 XT") != std::string::npos ||
                                     name_upper.find("A100") != std::string::npos ||
                                     name_upper.find("H100") != std::string::npos ||
                                     name_upper.find("MI300") != std::string::npos);

            bool name_is_discrete = (name_is_high_end ||
                                     name_upper.find("RTX") != std::string::npos ||
                                     name_upper.find("GTX") != std::string::npos ||
                                     name_upper.find("RADEON RX") != std::string::npos ||
                                     name_upper.find("ARC A") != std::string::npos);

            double ipc_multiplier = 1.0;
            if (is_cpu_emulator) {
                dev.category = GpuCategory::Integrated;
                dev.category_str = "CPU OpenCL Emulador (PoCL)";
                dev.is_discrete = false;
                ipc_multiplier = 0.01;
            } else if (name_is_high_end) {
                dev.category = GpuCategory::DiscreteHighEnd;
                dev.category_str = "dGPU High-End Enthusiast";
                dev.is_discrete = true;
                ipc_multiplier = 25.0;
            } else if (name_is_discrete && !name_is_integrated) {
                dev.category = GpuCategory::DiscreteMidRange;
                dev.category_str = "dGPU Dedicada Performance";
                dev.is_discrete = true;
                ipc_multiplier = 10.0;
            } else if (name_is_integrated || (dev.compute_units <= 4 && dev.global_mem_bytes < 8ULL * 1024 * 1024 * 1024)) {
                dev.category = GpuCategory::Integrated;
                dev.category_str = "iGPU Integrada (SoC/APU)";
                dev.is_discrete = false;
                ipc_multiplier = 1.0;
            } else {
                dev.category = GpuCategory::DiscreteEntry;
                dev.category_str = "GPU Aceleradora Genérica";
                dev.is_discrete = true;
                ipc_multiplier = 4.0;
            }

            // Warp / Wavefront Size preferido
            if (dev.vendor.find("NVIDIA") != std::string::npos) {
                dev.preferred_work_group_multiple = 32; // Warp NVIDIA
            } else if (dev.vendor.find("Advanced Micro Devices") != std::string::npos || dev.vendor.find("AMD") != std::string::npos) {
                if (name_upper.find("GFX10") != std::string::npos || name_upper.find("GFX11") != std::string::npos || name_upper.find("RDNA") != std::string::npos || name_upper.find("610M") != std::string::npos) {
                    dev.preferred_work_group_multiple = 32; // RDNA Wave32 padrão
                } else {
                    dev.preferred_work_group_multiple = 64; // GCN/CDNA Wave64
                }
            } else {
                dev.preferred_work_group_multiple = 32;
            }

            double driver_priority = 1.0;
            if (p_name_upper.find("RUSTICL") != std::string::npos || p_name_upper.find("POCL") != std::string::npos) {
                driver_priority = 0.6; // Menor prioridade para rusticl/emuladores se driver nativo estiver disponível
            }
            if (name_upper.find("GFX10") != std::string::npos || name_upper.find("GFX11") != std::string::npos) {
                // Em RDNA2/RDNA3 (gfx10xx/gfx11xx), 1 WGP reportado equivale a 2 Compute Units físicas
                if (dev.compute_units == 1) {
                    dev.compute_units = 2;
                }
            }

            // Cálculo do Compute Index (Score)
            dev.compute_index = static_cast<double>(dev.compute_units) * (dev.clock_freq_mhz / 1000.0) * ipc_multiplier * driver_priority;

            int score = static_cast<int>(dev.compute_index * 1000.0);
            if (score > best_score) {
                best_score = score;
                best_idx = devices.size();
            }

            devices.push_back(std::move(dev));
        }
    }

    if (!devices.empty()) {
        devices[best_idx].is_recommended = true;
    }
#endif

    return devices;
}

HostProfile HostProbe::probe_all() {
    HostProfile profile;
    profile.cpu = probe_cpu();
    profile.memory = probe_memory();
    profile.gpus = probe_gpus();

#if defined(__linux__)
    profile.os_info = "Linux x86_64";
#elif defined(_WIN32)
    profile.os_info = "Windows x86_64";
#elif defined(__APPLE__)
    profile.os_info = "macOS";
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

} // namespace hardware
} // namespace cryptowords
