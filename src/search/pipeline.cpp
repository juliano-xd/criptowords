#include "../../include/search/pipeline.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <print>
#include <span>
#include <string>

#include "../../include/cli/ui.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/pbkdf2_simd.hpp"
#include "../../include/gpu/gpu_backend.hpp"
#include "../../include/simd/factory.hpp"

using namespace cryptowords::ui;

namespace cryptowords {

// =========================================================================
// Construtor — resolve processador (Arch × ChecksumMode) e odômetro.
// =========================================================================
ExecutionPipeline::ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt)
    : cfg_(cfg), opt_(opt) {
    odometer_ = make_odometer(opt_);

    // Backend GPU: hoje só HIP. NVIDIA é detectada no host_probe mas ainda
    // não plugada; quando entrar, use_nvidia_ passa a consultar o engine.
    IGpuEngine* eng = get_gpu_engine();
    use_gpu_post_ = (eng != nullptr) &&
                    (eng->compute_mode() == GpuComputeMode::PostPbkdf2Only) &&
                    (cfg_.use_gpu || cfg_.use_hybrid);
    use_nvidia_ = false;

    const SimdArch arch = detect_best_simd();
    std::string cpu_name;
    switch (arch) {
        case SimdArch::AVX512: cpu_name = "AVX512 (16-way)"; break;
        case SimdArch::AVX2:   cpu_name = "AVX2 (8-way)";    break;
        case SimdArch::SSE:
        default:               cpu_name = "SSE4.1 (4-way)";  break;
    }

    processor_ = make_simd_processor(cfg_, opt_, arch);

    if (use_gpu_post_) {
        arch_name_ = "Híbrido (CPU SIMD " + cpu_name +
                     " + GPU pós-PBKDF2: " + eng->get_device_name() + ")";
    } else {
        arch_name_ = cpu_name;
    }

    build_salt_tables_();
}

ExecutionPipeline::~ExecutionPipeline() = default;

// =========================================================================
// Salt HMAC pré-computado: string canônica + bloco de 128 B + tabelas do
// key-schedule do PBKDF2 (por arquitetura SIMD).
// =========================================================================
void ExecutionPipeline::build_salt_tables_() {
    static constexpr size_t MAX_SALT = 107;

    std::string salt = "mnemonic";
    if (!cfg_.passphrase.empty()) salt += cfg_.passphrase;

    if (salt.size() > MAX_SALT) {
        std::println(std::cerr,
                     "\n[!] Aviso: salt (\"mnemonic\" + passphrase) tem {} bytes, "
                     "acima do limite de {} bytes. Truncando.\n",
                     salt.size(), MAX_SALT);
    }
    salt_shared_.len = std::min(salt.size(), MAX_SALT);
    std::memcpy(salt_shared_.buf.data(), salt.data(), salt_shared_.len);

    // Bloco de 128 B do salt: salt || 0x01 (boundary) || 0x80 (padding).
    alignas(64) std::array<uint8_t, 128> s_buf{};
    std::memcpy(s_buf.data(), salt.data(), salt_shared_.len);
    s_buf[salt_shared_.len + 3] = 0x01;
    s_buf[salt_shared_.len + 4] = 0x80;

    const uint64_t bit_len = static_cast<uint64_t>(128 + salt_shared_.len + 4) * 8;

    uint64_t s_blk[16];
    std::memcpy(s_blk, s_buf.data(), 128);
#pragma GCC unroll 15
    for (int w = 0; w < 15; ++w)
        salt_shared_.block64[w] = __builtin_bswap64(s_blk[w]);
    salt_shared_.block64[15] = bit_len;

    precompute_kw_salt(salt_shared_.block64.data(), salt_shared_.kw_salt.data());
    pbkdf2_simd_detail::precompute_kw_salt_tables(
        salt_shared_.kw_salt.data(),
        salt_shared_.kw_salt_sse.data(),
        salt_shared_.kw_salt_avx2.data(),
        salt_shared_.kw_salt_avx512.data());
}

// =========================================================================
// Cobertura — filtra snapshots por base_mnemonic compatível.
// Snapshots com base diferente nunca cobririam um candidato desta execução.
// =========================================================================
void ExecutionPipeline::set_coverage_snapshots(std::vector<CoverageSnapshot>&& v) noexcept {
    coverage_snapshots_.clear();
    coverage_snapshots_.reserve(v.size());
    for (auto& s : v) {
        if (s.base_mnemonic == opt_.base_mnemonic)
            coverage_snapshots_.push_back(std::move(s));
    }
}

void ExecutionPipeline::add_coverage_snapshot(CoverageSnapshot&& s) {
    for (const auto& e : coverage_snapshots_)
        if (e.hash == s.hash) return;
    coverage_snapshots_.push_back(std::move(s));
}

// =========================================================================
// Criação de contexto por thread.
// =========================================================================
std::unique_ptr<PipelineThreadContext> ExecutionPipeline::create_thread_context(
    size_t thread_idx, size_t num_threads) {
    auto ctx = std::make_unique<PipelineThreadContext>();

    if (opt_.has_target) ctx->decoded_target = opt_.target_bytes;
    ctx->coverage_snapshots = &coverage_snapshots_;

    // Salt pré-computado: cópia dos std::arrays (barato, 1x por thread).
    ctx->salt = salt_shared_;

    // GPU pós-PBKDF2: ping-pong de 2 buffers.
    if (use_gpu_post_) {
        IGpuEngine* eng = get_gpu_engine();
        ctx->gpu.engine = eng;
        ctx->gpu.mutex  = &gpu_post_mutex_;
        ctx->gpu.slot   = static_cast<uint32_t>(thread_idx) % 8u;

        for (int i = 0; i < 2; ++i) {
            ctx->gpu.seeds[i].resize(GPU_POST_BATCH * 64);
            ctx->gpu.mnems[i].resize(GPU_POST_BATCH * MAX_WORDS_PER_MNEMONIC);
            ctx->gpu.count[i]    = 0;
            ctx->gpu.inflight[i] = false;
            ctx->gpu.result[i]   = 0xFFFFFFFFu;
        }
        ctx->gpu.write_idx = 0;
    }

    // Backend NVIDIA: reservado; nada a inicializar por enquanto.

    odometer_->init_state(*ctx, thread_idx, num_threads, opt_);
    return ctx;
}

// =========================================================================
// Delegação ao processador SIMD.
// =========================================================================
void ExecutionPipeline::process(PipelineThreadContext& ctx, std::atomic<bool>& found,
                                std::atomic<uint64_t>& tested, std::atomic<uint64_t>& valid,
                                std::mutex& mutex, bool& success,
                                std::vector<uint16_t>& result) {
    processor_->enqueue_and_process(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
}

void ExecutionPipeline::flush(PipelineThreadContext& ctx, std::atomic<bool>& found,
                              std::atomic<uint64_t>& tested, std::atomic<uint64_t>& valid,
                              std::mutex& mutex, bool& success,
                              std::vector<uint16_t>& result) {
    processor_->flush(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
}

// =========================================================================
// Fase 5 — reporta resultado final.
// =========================================================================
void ExecutionPipeline::verify_and_print_result(const std::vector<uint16_t>& mnemonic) const {
    const char* pp = cfg_.passphrase.empty() ? nullptr : cfg_.passphrase.data();
    auto span = std::span<const uint16_t>(mnemonic);

    std::array<uint8_t, 32> priv_key{};
    const std::string addr =
        (cfg_.coin == CoinTarget::BTC)
            ? Bip39Deriver::derive_btc_address(mnemonic, cfg_.wordlist, pp,
                                               cfg_.passphrase.size(), cfg_.pbkdf2_rounds,
                                               cfg_.separator, &priv_key)
            : Bip39Deriver::derive_eth_address(span, cfg_.wordlist, pp,
                                               cfg_.passphrase.size(), cfg_.pbkdf2_rounds,
                                               cfg_.separator, &priv_key);

    std::string mnem_str;
    for (size_t i = 0; i < mnemonic.size(); ++i) {
        mnem_str += cfg_.wordlist[mnemonic[i]];
        if (i + 1 < mnemonic.size()) mnem_str += cfg_.separator;
    }

    static constexpr char HEX[] = "0123456789abcdef";
    auto to_hex = [&](const uint8_t* p, size_t n) {
        std::string s;
        s.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) {
            s.push_back(HEX[p[i] >> 4]);
            s.push_back(HEX[p[i] & 0x0F]);
        }
        return s;
    };

    const size_t C = mnemonic.size() / 3;
    uint8_t computed_cs = 0;
    (void)Bip39Deriver::extract_checksum(span, computed_cs);
    const uint8_t expected_cs = static_cast<uint8_t>(mnemonic.back() & ((1u << C) - 1));
    const char* cs_mark = (computed_cs == expected_cs) ? "\033[1;32m✓\033[0m"
                                                       : "\033[1;31m✗\033[0m";

    std::string cs_bin(C, '0');
    for (size_t i = 0; i < C; ++i)
        if ((computed_cs >> (C - 1 - i)) & 1) cs_bin[i] = '1';

    std::println("\n[!] CHAVE ENCONTRADA!");
    std::println("  • Mnemonic      : \033[1;33m{}\033[0m", mnem_str);
    std::println("  • Checksum      : 0b{} {} ({} bits)", cs_bin, cs_mark, C);
    std::println("  • Address       : \033[1;32m{}\033[0m", addr);
    std::println("  • Moeda         : {}",
                 (cfg_.coin == CoinTarget::BTC ? "Bitcoin (BTC)" : "Ethereum (ETH)"));
    std::println("  • Chave Privada : \033[1;35m0x{}\033[0m", to_hex(priv_key.data(), 32));
    if (!cfg_.passphrase.empty())
        std::println("  • Senha         : \"{}\"", cfg_.passphrase);
    std::println();
}

}  // namespace cryptowords
