#include "../../include/search/pipeline.hpp"
#include "../../include/simd/factory.hpp"
#include "../../include/gpu/gpu_batch_processor.hpp"
#include "../../include/crypto/bip39.hpp"

#include <cstring>
#include <iostream>
#include <print>

namespace cryptowords {

ExecutionPipeline::ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt)
    : cfg_(cfg), opt_(opt) {
    odometer_ = std::make_unique<GenericOdometer>();

    if (cfg_.use_gpu) {
        processor_ = std::make_unique<GPUBatchProcessor>();
        arch_name_ = "OpenCL + Secp256k1 (Adaptive Auto-Tuned Mass Parallelism)";
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
    ctx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
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
    processor_->enqueue_and_process(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
}

void ExecutionPipeline::flush(PipelineThreadContext& ctx,
                              std::atomic<bool>& found,
                              std::atomic<uint64_t>& tested,
                              std::atomic<uint64_t>& valid,
                              std::mutex& mutex,
                              bool& success,
                              std::vector<uint16_t>& result) {
    processor_->flush(ctx, cfg_, opt_, found, tested, valid, mutex, success, result);
}

void ExecutionPipeline::verify_and_print_result(const std::vector<uint16_t>& mnemonic) const {
    std::println("\n[!] CHAVE ENCONTRADA!");
    std::print("    [+] Mnemonic: ");
    for (size_t i = 0; i < mnemonic.size(); ++i) {
        std::print("{}{}", cfg_.wordlist[mnemonic[i]],
                   (i + 1 == mnemonic.size() ? "" : " "));
    }
    std::println();

    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const char* pp = cfg_.passphrase.empty() ? nullptr : cfg_.passphrase.data();
    const std::string addr = (cfg_.coin == CoinTarget::BTC)
        ? Bip39Deriver::derive_btc_address(ctx, mnemonic, cfg_.wordlist, pp, cfg_.passphrase.size(), cfg_.pbkdf2_rounds)
        : Bip39Deriver::derive_eth_address(ctx, mnemonic, cfg_.wordlist, pp, cfg_.passphrase.size(), cfg_.pbkdf2_rounds);
    secp256k1_context_destroy(ctx);

    std::println("    [+] Address : {}", addr);
}

} // namespace cryptowords
