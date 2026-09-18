#include "../../include/search/pipeline.hpp"
#include "../../include/simd/factory.hpp"
#include "../../include/gpu/gpu_batch_processor.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/pbkdf2_simd.hpp"
#include "../../include/cli/ui.hpp"

#include <cstring>
#include <iostream>
#include <print>

using namespace cryptowords::ui;

namespace cryptowords {

ExecutionPipeline::ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt)
    : cfg_(cfg), opt_(opt) {
    odometer_ = std::make_unique<GenericOdometer>();

    if (cfg_.use_hybrid) {
        processor_ = std::make_unique<GPUBatchProcessor>(cfg_);
        const SimdArch arch = detect_best_simd();
        cpu_processor_ = make_simd_processor(cfg_, opt_, arch);
        std::string cpu_name;
        switch (arch) {
            case SimdArch::AVX512: cpu_name = "AVX512 (16-way)"; break;
            case SimdArch::AVX2:   cpu_name = "AVX2 (8-way)";    break;
            case SimdArch::SSE:
            default:               cpu_name = "SSE4.1 (4-way)";  break;
        }
        const auto* dev = GPUEngine::get_instance().get_active_device();
        std::string gpu_name = dev ? (dev->device_name + " [" + std::to_string(dev->compute_units) + " CUs]") : "OpenCL GPU";
        arch_name_ = "Híbrido Cooperativo (GPU: " + gpu_name + " + CPU: " + cpu_name + ")";
    } else if (cfg_.use_gpu) {
        processor_ = std::make_unique<GPUBatchProcessor>(cfg_);
        const auto* dev = GPUEngine::get_instance().get_active_device();
        if (dev) {
            arch_name_ = "OpenCL: " + dev->device_name + " (" + std::to_string(dev->compute_units) + " CUs)";
        } else {
            arch_name_ = "OpenCL + Secp256k1 (Adaptive Auto-Tuned Mass Parallelism)";
        }
    } else {
        const SimdArch arch = detect_best_simd();
        processor_ = make_simd_processor(cfg_, opt_, arch);

        switch (arch) {
            case SimdArch::AVX512: arch_name_ = "AVX512 (16-way)"; break;
            case SimdArch::AVX2:   arch_name_ = "AVX2 (8-way)";    break;
            case SimdArch::SSE:
            default:               arch_name_ = "SSE4.1 (4-way)";  break;
        }
    }
}

ExecutionPipeline::~ExecutionPipeline() = default;

std::unique_ptr<PipelineThreadContext>
ExecutionPipeline::create_thread_context(size_t thread_idx, size_t num_threads) {
    auto ctx = std::make_unique<PipelineThreadContext>();
    ctx->thread_idx = thread_idx;
    ctx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx->ctx) {
        std::cerr << "Failed to create secp256k1 context\n";
        return nullptr;
    }

    if (opt_.has_target) {
        std::memcpy(ctx->decoded_target, opt_.target_bytes, 20);
    }

    std::string salt = "mnemonic";
    if (!cfg_.passphrase.empty()) salt += cfg_.passphrase;
    ctx->salt_len = std::min(salt.size(), sizeof(ctx->salt_buf));
    std::memcpy(ctx->salt_buf, salt.data(), ctx->salt_len);

    uint8_t s_buf[128] = {};
    std::memcpy(s_buf, salt.data(), ctx->salt_len);
    s_buf[ctx->salt_len]     = 0;
    s_buf[ctx->salt_len + 1] = 0;
    s_buf[ctx->salt_len + 2] = 0;
    s_buf[ctx->salt_len + 3] = 1;
    s_buf[ctx->salt_len + 4] = 0x80;

    uint64_t s_blk[16];
    std::memcpy(s_blk, s_buf, 128);
    for (int w = 0; w < 15; ++w) {
        ctx->salt_block64[w] = __builtin_bswap64(s_blk[w]);
    }
    ctx->salt_block64[15] = static_cast<uint64_t>(128 + ctx->salt_len + 4) * 8;
    precompute_kw_salt(ctx->salt_block64, ctx->kw_salt);

    if (opt_.slice0_static_len > 0) {
        for (size_t b = 0; b < 16; ++b) {
            std::memcpy(ctx->pw + b * PW_SLOT_SIZE, opt_.slices[0].text.data(), opt_.slice0_static_len);
        }
        ctx->prefix_initialized = true;
    }

    odometer_->init_state(*ctx, thread_idx, num_threads, opt_);
    return ctx;
}

void ExecutionPipeline::process(PipelineThreadContext& ctx,
                                std::atomic<bool>& found,
                                std::atomic<uint64_t>& tested,
                                std::atomic<uint64_t>& valid,
                                std::mutex& mutex,
                                bool& success,
                                std::vector<uint16_t>& result) {
    if (cfg_.use_hybrid) {
        if (ctx.thread_idx == 0) {
            processor_->enqueue_and_process(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
        } else {
            cpu_processor_->enqueue_and_process(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
        }
    } else {
        processor_->enqueue_and_process(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
    }
}

void ExecutionPipeline::flush(PipelineThreadContext& ctx,
                              std::atomic<bool>& found,
                              std::atomic<uint64_t>& tested,
                              std::atomic<uint64_t>& valid,
                              std::mutex& mutex,
                              bool& success,
                              std::vector<uint16_t>& result) {
    if (cfg_.use_hybrid) {
        if (ctx.thread_idx == 0) {
            processor_->flush(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
        } else {
            cpu_processor_->flush(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
        }
    } else {
        processor_->flush(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
    }
}

void ExecutionPipeline::verify_and_print_result(const std::vector<uint16_t>& mnemonic) const {
    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const char* pp = cfg_.passphrase.empty() ? nullptr : cfg_.passphrase.data();
    const std::string addr = (cfg_.coin == CoinTarget::BTC)
        ? Bip39Deriver::derive_btc_address(ctx, mnemonic, cfg_.wordlist, pp, cfg_.passphrase.size(), cfg_.pbkdf2_rounds, cfg_.separator)
        : Bip39Deriver::derive_eth_address(ctx, mnemonic, cfg_.wordlist, pp, cfg_.passphrase.size(), cfg_.pbkdf2_rounds, cfg_.separator);
    secp256k1_context_destroy(ctx);

    std::string mnem_str;
    for (size_t i = 0; i < mnemonic.size(); ++i) {
        mnem_str += cfg_.wordlist[mnemonic[i]];
        if (i + 1 < mnemonic.size()) mnem_str += cfg_.separator;
    }

    print_box_top("CHAVE ENCONTRADA!", DEFAULT_INNER_WIDTH);
    print_box_line(std::format("\033[1;37mFrase Mnemônica ({} palavras):\033[0m", mnemonic.size()), DEFAULT_INNER_WIDTH);

    std::string current;
    for (size_t i = 0; i < mnemonic.size(); ++i) {
        const std::string& w = cfg_.wordlist[mnemonic[i]];
        if (!current.empty() && current.size() + w.size() + 1 > 68) {
            print_box_line(std::format("   \033[1;33m{}\033[0m", current), DEFAULT_INNER_WIDTH);
            current.clear();
        }
        if (!current.empty()) current += cfg_.separator;
        current += w;
    }
    if (!current.empty()) {
        print_box_line(std::format("   \033[1;33m{}\033[0m", current), DEFAULT_INNER_WIDTH);
    }

    print_box_separator(DEFAULT_INNER_WIDTH);
    print_box_line(std::format("Moeda           : {}", (cfg_.coin == CoinTarget::BTC ? "Bitcoin (BTC)" : "Ethereum (ETH)")), DEFAULT_INNER_WIDTH);
    print_box_line(std::format("Endereço Alvo   : \033[1;32m{}\033[0m", addr), DEFAULT_INNER_WIDTH);
    if (!cfg_.passphrase.empty()) {
        print_box_line(std::format("Senha (Pass)    : \"{}\"", cfg_.passphrase), DEFAULT_INNER_WIDTH);
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);

    std::println("\n[!] CHAVE ENCONTRADA!");
    std::println("    [+] Mnemonic: {}", mnem_str);
    std::println("    [+] Address : {}\n", addr);
}

} // namespace cryptowords
