#include "../include/pipeline_builder.hpp"
#include "../include/batch_processors.hpp"
#include "../include/crypto_impl.hpp"
#include "../include/bip39.hpp"
#include <iostream>

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

namespace cryptowords {

static SimdArch detect_best_simd() {
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    bool has_sse41 = (ecx & bit_SSE4_1) != 0;
    
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    bool has_avx2 = (ebx & bit_AVX2) != 0;
    bool has_avx512f = (ebx & bit_AVX512F) != 0;
    
    if (has_avx512f) return SimdArch::AVX512;
    if (has_avx2) return SimdArch::AVX2;
    if (has_sse41) return SimdArch::SSE;
#endif
    return SimdArch::SSE;
}

// =========================================================
// ODOMETRO GENERICO
// =========================================================
class GenericOdometer : public IOdometer {
public:
    void init_state(PipelineThreadContext& ctx, size_t thread_idx, size_t num_threads, const OptimizedMnemonics& opt) override {
        ctx.step_size = num_threads;
        ctx.is_done = false;
        ctx.state.resize(opt.wheels.size(), 0);
        ctx.current_ids = opt.base_mnemonic;
        
        size_t temp = thread_idx;
        for (int i = static_cast<int>(opt.wheels.size()) - 1; i >= 0; --i) {
            ctx.state[i] = temp % opt.wheels[i].size();
            temp /= opt.wheels[i].size();
        }
        if (temp > 0) ctx.is_done = true;
        
        for (size_t i = 0; i < opt.wheels.size(); ++i) {
            ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][ctx.state[i]];
        }
    }

    bool advance(PipelineThreadContext& ctx, const OptimizedMnemonics& opt) override {
        if (ctx.is_done || opt.wheels.empty()) return false;
        
        size_t carry = ctx.step_size;
        for (int i = static_cast<int>(opt.wheels.size()) - 1; i >= 0 && carry > 0; --i) {
            size_t sum = ctx.state[i] + carry;
            ctx.state[i] = sum % opt.wheels[i].size();
            carry = sum / opt.wheels[i].size();
            ctx.current_ids[opt.unknown_positions[i]] = opt.wheels[i][ctx.state[i]];
        }
        
        if (carry > 0) {
            ctx.is_done = true;
            return false;
        }
        return true;
    }
};

std::unique_ptr<IBatchProcessor> build_batch_processor(const AppConfig& cfg, const OptimizedMnemonics& opt, SimdArch arch) {
    if (arch == SimdArch::AVX512) {
        if (cfg.only_valids) {
            if (opt.auto_deduce_last_word) return std::make_unique<SimdBatchProcessor<SimdArch::AVX512, true, true>>();
            return std::make_unique<SimdBatchProcessor<SimdArch::AVX512, false, true>>();
        }
        return std::make_unique<SimdBatchProcessor<SimdArch::AVX512, false, false>>();
    } else if (arch == SimdArch::AVX2) {
        if (cfg.only_valids) {
            if (opt.auto_deduce_last_word) return std::make_unique<SimdBatchProcessor<SimdArch::AVX2, true, true>>();
            return std::make_unique<SimdBatchProcessor<SimdArch::AVX2, false, true>>();
        }
        return std::make_unique<SimdBatchProcessor<SimdArch::AVX2, false, false>>();
    } else {
        if (cfg.only_valids) {
            if (opt.auto_deduce_last_word) return std::make_unique<SimdBatchProcessor<SimdArch::SSE, true, true>>();
            return std::make_unique<SimdBatchProcessor<SimdArch::SSE, false, true>>();
        }
        return std::make_unique<SimdBatchProcessor<SimdArch::SSE, false, false>>();
    }
}

ExecutionPipeline::ExecutionPipeline(const AppConfig& cfg, const OptimizedMnemonics& opt)
    : cfg_(cfg), opt_(opt), arch_(detect_best_simd()) {
    odometer_ = std::make_unique<GenericOdometer>();
    processor_ = build_batch_processor(cfg_, opt_, arch_);
}

std::unique_ptr<PipelineThreadContext> ExecutionPipeline::create_thread_context(size_t thread_idx, size_t num_threads) {
    auto ctx = std::make_unique<PipelineThreadContext>();
    ctx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    if (opt_.has_target) {
        std::memcpy(ctx->decoded_target, opt_.target_bytes, 20);
    }
    
    std::string salt_str = "mnemonic" + std::string(cfg_.passphrase);
    memcpy(ctx->salt_buf, salt_str.data(), salt_str.size());
    ctx->salt_len = salt_str.size();
    
    odometer_->init_state(*ctx, thread_idx, num_threads, opt_);
    return ctx;
}

std::string ExecutionPipeline::get_architecture_name() const {
    if (arch_ == SimdArch::AVX512) return "AVX512 (16-way)";
    if (arch_ == SimdArch::AVX2) return "AVX2 (8-way)";
    return "SSE4.1 (4-way)";
}

void ExecutionPipeline::verify_and_print_result(const std::vector<uint16_t>& result_mnemonic) const {
    std::cout << "\n[!] CHAVE ENCONTRADA!\n";
    std::cout << "    [+] Mnemonic: ";
    for (size_t i = 0; i < result_mnemonic.size(); ++i) {
        std::cout << cfg_.wordlist[result_mnemonic[i]] << (i == result_mnemonic.size() - 1 ? "" : " ");
    }
    std::cout << "\n";
    
    secp256k1_context* ctx_verify = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    std::string address;
    if (cfg_.coin == CoinTarget::BTC) {
        address = Bip39Deriver::derive_btc_address(ctx_verify, result_mnemonic, cfg_.wordlist, cfg_.passphrase.data(), cfg_.passphrase.size());
    } else {
        address = Bip39Deriver::derive_eth_address(ctx_verify, result_mnemonic, cfg_.wordlist, cfg_.passphrase.data(), cfg_.passphrase.size());
    }
    secp256k1_context_destroy(ctx_verify);
    
    std::cout << "    [+] Address : " << address << "\n";
}

} // namespace cryptowords
