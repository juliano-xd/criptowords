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

// Extensões completas de instruções detectadas em tempo de execução via CPUID
struct CpuCapabilities {
    // 1. Vetoriais Básicas & Legadas (128-bit)
    bool mmx = false;
    bool sse = false;
    bool sse2 = false;
    bool sse3 = false;
    bool ssse3 = false;
    bool sse41 = false;
    bool sse42 = false;
    bool sse4a = false;         // AMD SSE4a
    bool misalignsse = false;   // AMD Misaligned SSE mode

    // 2. Vetorização Intermediária & FMA (128/256-bit)
    bool avx = false;
    bool avx2 = false;
    bool f16c = false;
    bool fma3 = false;
    bool fma4 = false;          // AMD FMA4 legada
    bool xop = false;           // AMD XOP legada
    bool tbm = false;           // AMD Trailing Bit Manipulation
    bool avx_vnni = false;      // AVX2 VNNI (8-bit int)
    bool avx_ifma = false;      // AVX-IFMA (52-bit int)
    bool avx_ne_convert = false;// AVX Neural Network FP16/BF16 Convert
    bool avx_vnni_int8 = false; // AVX VNNI INT8
    bool avx_vnni_int16 = false;// AVX VNNI INT16

    // 3. Vetorização Avançada AVX-512 (512-bit & VL)
    bool avx512f = false;       // Foundation
    bool avx512dq = false;      // Doubleword & Quadword
    bool avx512bw = false;      // Byte & Word
    bool avx512vl = false;      // Vector Length (128/256b op sobre ZMM)
    bool avx512cd = false;      // Conflict Detection
    bool avx512er = false;      // Exponential & Reciprocal
    bool avx512pf = false;      // Prefetch
    bool avx512ifma = false;    // Integer FMA 52-bit
    bool avx512vbmi = false;    // Vector Byte Manipulation
    bool avx512vbmi2 = false;   // Vector Byte Manipulation 2
    bool avx512vnni = false;    // Vector Neural Network Instructions
    bool avx512bitalg = false;  // Bit Algorithms
    bool avx512vpopcntdq = false;// Vector Population Count
    bool avx512fp16 = false;    // Half-Precision Float
    bool avx512bf16 = false;    // Bfloat16
    bool avx512_4fmaps = false; // Multi-precision FMA
    bool avx512_4vnniw = false; // Neural Network Words
    bool avx512_vp2intersect = false;

    // 4. Novas Arquiteturas Vetoriais, IA & APX
    bool avx10 = false;         // Intel AVX10 Converged Vector ISA
    bool amx_tile = false;      // Intel AMX Tile architecture
    bool amx_int8 = false;      // Intel AMX INT8
    bool amx_bf16 = false;      // Intel AMX BF16
    bool amx_fp16 = false;      // Intel AMX FP16
    bool amx_complex = false;   // Intel AMX Complex numbers
    bool apx = false;           // Intel APX (32 General Purpose Registers)

    // 5. Instruções Criptográficas e Segurança em Silício
    bool sha_ni = false;        // Hardware SHA-256 (Intel SHA extensions / AMD Zen)
    bool intel_sha512 = false;  // Hardware SHA-512 (Intel Arrow Lake / AMD Zen 5)
    bool sm3 = false;           // Chinese SM3 Hash
    bool sm4 = false;           // Chinese SM4 Cipher
    bool aes_ni = false;        // AES-NI
    bool vaes = false;          // Vector AES (256/512-bit)
    bool pclmulqdq = false;     // Carry-less Multiplication
    bool vpclmulqdq = false;    // Vector PCLMULQDQ (256/512-bit)
    bool gfni = false;          // Galois Field New Instructions (GF(2^8) SIMD)
    bool rdrand = false;        // Hardware RNG (NIST SP 800-90A)
    bool rdseed = false;        // Hardware Entropy Source (NIST SP 800-90B/C)
    bool key_locker = false;    // Intel Key Locker

    // 6. Manipulação de Bits, Matemática Acelerada & Sincronização
    bool bmi1 = false;          // ANDN, BEXTR, BLSI, BLSMSK, BLSR, TZCNT
    bool bmi2 = false;          // BZHI, MULX, PDEP, PEXT, RORX, SARX, SHLX, SHRX
    bool lzcnt_abm = false;     // Leading Zero Count (ABM)
    bool popcnt = false;        // Population Count (Hamming weight)
    bool movbe = false;         // Move Big-Endian (Hardware Byte-Swap em 1 ciclo)
    bool adx = false;           // Multi-Precision Add-Carry (ADCX / ADOX)
    bool cmpccxadd = false;     // Compare and Add conditional
    bool rao_int = false;       // Remote Atomic Operations
    bool waitpkg = false;       // UMWAIT, TPAUSE (Micro-pausa sem custo de kernel)
    bool serialize = false;     // SERIALIZE (Barreira de instrução não-destrutiva)
    bool tsx_rtm = false;       // Transactional Synchronization Extensions (RTM)
    bool tsx_hle = false;       // Hardware Lock Elision (HLE)

    // 7. Aceleração de Memória, Caches & Barramento
    bool clzero = false;        // AMD Zen Clear Cache Line (Zera 64 bytes em 1 ciclo)
    bool clflush = false;       // Cache line flush
    bool clflushopt = false;    // Optimized cache line flush
    bool clwb = false;          // Cache line write back
    bool cldemote = false;      // Cache line demote (L1/L2 -> L3)
    bool movdiri = false;       // Direct Store 32/64-bit sem poluição de cache
    bool movdir64b = false;     // Direct Store atômico de 64 bytes
    bool enqcmd = false;        // Enqueue Command Work Submission
    bool erms = false;          // Enhanced REP MOVSB/STOSB (Fast Memcpy)
    bool fsrm = false;          // Fast Short REP MOVSB (<128B)
    bool fsgsbase = false;      // Fast Userspace Segment Base
    bool rdpru = false;         // Read Processor User Register (AMD Zen 2+)
    bool rdpid = false;         // Read Processor ID em ring 3 em 1 ciclo
    bool invariant_tsc = false; // Constant & Invariant Time Stamp Counter
    bool rdtscp = false;        // RDTSCP (Leitura atômica de TSC + Processor ID)
    bool cpb_boost = false;     // Core Performance Boost (AMD) / Turbo Boost (Intel)
    bool prefetchw = false;     // Prefetch com intenção de escrita
    bool prefetchwt1 = false;   // Prefetch com intenção de escrita para T1
    bool prefetchi = false;     // Instruction Cache Prefetch
    bool mwaitx = false;        // AMD MWAITX/MONITORX com timeout
    bool hugepages_1gb = false; // Suporte a páginas gigantes de 1GB (PDPE1GB)

    // 8. Segurança, Virtualização & SO
    bool la57 = false;          // 5-Level Paging (57-bit virtual addressing)
    bool cet_ss = false;        // Control-flow Enforcement Shadow Stack
    bool cet_ibt = false;       // Control-flow Enforcement Indirect Branch Tracking
    bool umip = false;          // User-Mode Instruction Prevention
    bool smep = false;          // Supervisor Mode Execution Prevention
    bool smap = false;          // Supervisor Mode Access Prevention
    bool pku_ospke = false;     // Memory Protection Keys
    bool sme = false;           // AMD Secure Memory Encryption
    bool sev = false;           // AMD Secure Encrypted Virtualization
    bool sev_snp = false;       // AMD SEV Secure Nested Paging
    bool intel_vmx = false;     // Intel VMX (VT-x)
    bool amd_svm = false;       // AMD SVM (AMD-V)
};

struct CpuInfo {
    std::string vendor;          // ex: "AuthenticAMD", "GenuineIntel"
    std::string brand_string;    // ex: "AMD Ryzen 5 7520U with Radeon Graphics"
    std::string microarch_family;// ex: "AMD Zen 2 (Mendocino APU, 6nm)"
    uint32_t raw_family = 0;     // ex: 23 (0x17)
    uint32_t raw_model = 0;      // ex: 160 (0xA0)
    uint32_t raw_stepping = 0;   // ex: 0
    std::string microcode;       // ex: "0x8a0000a"
    uint32_t physical_addr_bits = 0; // ex: 48
    uint32_t virtual_addr_bits = 0;  // ex: 48

    CpuTopology topology;
    CpuCacheInfo cache;
    CpuCapabilities caps;

    double bogo_mips = 0.0;
    uint32_t base_clock_mhz = 0;
    uint32_t max_clock_mhz = 0;
    uint32_t min_clock_mhz = 0;
    uint32_t current_clock_mhz = 0;
    std::string scaling_governor; // ex: "powersave", "performance", "schedutil"
    std::string scaling_driver;   // ex: "amd-pstate-epp", "intel_pstate"
    std::string epp_preference;   // ex: "balance_performance", "performance"
    std::string thp_status;       // ex: "[always] madvise never"
};


struct MemoryInfo {
    uint64_t total_ram_bytes = 0;
    uint64_t available_ram_bytes = 0;
    uint64_t hugepage_size_bytes = 0;
    bool hugepages_available = false;
};

enum class GpuCategory {
    DiscreteHighEnd,   // RTX 4090, 4080, 3090, RX 7900 XTX, MI300, H100
    DiscreteMidRange,  // RTX 3060, 4060, RX 6600, RX 7600
    DiscreteEntry,     // GTX 1050, 1650, RX 550
    Integrated,        // Radeon 610M/680M/780M, Intel Iris Xe / UHD, Vega
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
    size_t preferred_work_group_multiple = 32; // Warp 32 (NVIDIA/RDNA Wave32) ou Wavefront 64 (AMD GCN/CDNA)
    uint64_t global_mem_bytes = 0;
    uint64_t max_alloc_bytes = 0;
    uint64_t local_mem_bytes = 0;
    uint32_t clock_freq_mhz = 0;
    double compute_index = 0.0; // Pontuação teórica de paralelismo
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
    static HostProfile probe_all();
};

} // namespace hardware
} // namespace cryptowords
