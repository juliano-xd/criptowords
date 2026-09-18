#include "../include/config.hpp"
#include "../include/cli/parser.hpp"
#include "../include/cli/validator.hpp"
#include "../include/search/engine.hpp"
#include "../include/search/optimizer.hpp"
#include "../include/search/pipeline.hpp"
#include "../include/search/reporter.hpp"
#include "../include/crypto/bip39.hpp"
#include "../include/gpu/gpu_engine.hpp"
#include "../include/gpu/gpu_info.hpp"
#include "../include/benchmark/benchmark_runner.hpp"
#include "../include/cli/ui.hpp"

#include <print>
#include <variant>
#include <cstring>

using namespace cryptowords::ui;

static bool is_fully_known(const AppConfig& cfg) {
    for (const auto& w : cfg.mnemonics) {
        if (!std::holds_alternative<uint16_t>(w) ||
            std::get<uint16_t>(w) == AppConfig::UNKNOWN_WORD) {
            return false;
        }
    }
    return true;
}

static bool run_derivation_mode(const AppConfig& cfg) {
    std::vector<uint16_t> ids;
    ids.reserve(cfg.mnemonics.size());
    for (const auto& w : cfg.mnemonics) ids.push_back(std::get<uint16_t>(w));

    if (cfg.only_valids && !cryptowords::Bip39Deriver::verify_checksum(ids)) {
        std::println(stderr, "\n[✗] FALHA: A frase semente fornecida possui um Checksum inválido!");
        std::println(stderr, "    Se você tem certeza disso, rode novamente adicionando a flag --invalid_too");
        return false;
    }

    auto* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const char* pp = cfg.passphrase.empty() ? nullptr : cfg.passphrase.c_str();

    const std::string addr = (cfg.coin == CoinTarget::BTC)
        ? cryptowords::Bip39Deriver::derive_btc_address(ctx, ids, cfg.wordlist, pp, cfg.passphrase.size(), cfg.pbkdf2_rounds, cfg.separator)
        : cryptowords::Bip39Deriver::derive_eth_address(ctx, ids, cfg.wordlist, pp, cfg.passphrase.size(), cfg.pbkdf2_rounds, cfg.separator);
    secp256k1_context_destroy(ctx);

    std::print("\n");
    print_box_top("DERIVAÇÃO CONCLUÍDA", DEFAULT_INNER_WIDTH);
    print_box_line(std::format("Moeda           : {}", (cfg.coin == CoinTarget::BTC ? "Bitcoin (BTC)" : "Ethereum (ETH)")), DEFAULT_INNER_WIDTH);
    print_box_line(std::format("Tamanho Frase   : {} palavras (Checksum BIP-39 Válido)", ids.size()), DEFAULT_INNER_WIDTH);
    print_box_line(std::format("Endereço Gerado : \033[1;32m{}\033[0m", addr), DEFAULT_INNER_WIDTH);
    if (!cfg.passphrase.empty()) {
        print_box_line(std::format("Senha (Pass)    : \"{}\"", cfg.passphrase), DEFAULT_INNER_WIDTH);
    }
    print_box_bottom(DEFAULT_INNER_WIDTH);

    std::println("\n[✓] DERIVAÇÃO CONCLUÍDA COM SUCESSO");
    std::println("    [+] Endereço gerado: {}\n", addr);
    return true;
}



int main(int argc, char* argv[]) {
    auto raw = CLIParser::parse(argc, argv);
    if (!raw) {
        if (raw.error() == "HELP") return 0;
        std::println(stderr, "\n[✗] FALHA NA INICIALIZAÇÃO");
        std::println(stderr, "    Motivo: {}", raw.error());
        std::println(stderr, "\nUse '--help' para ver os exemplos de uso.");
        return 1;
    }

    auto config = ConfigValidator::validate(*raw);
    if (!config) {
        std::println(stderr, "\n[✗] FALHA NA INICIALIZAÇÃO");
        std::println(stderr, "    Motivo: {}", config.error());
        std::println(stderr, "\nUse '--help' para ver os exemplos de uso.");
        return 1;
    }
    const auto& cfg = *config;

    if (cfg.list_gpus) {
        cryptowords::gpu::print_device_list();
        return 0;
    }

    if (cfg.run_benchmark) {
        return cryptowords::BenchmarkRunner::run(cfg);
    }

    // Modo simples: todas as palavras conhecidas, sem target.
    if (is_fully_known(cfg) && cfg.target.empty()) {
        return run_derivation_mode(cfg) ? 0 : 1;
    }

    // Modo força bruta.
    if (cfg.use_gpu) {
        size_t slot_size = 128;
        bool is_cjk = (cfg.language == "ja" || cfg.language == "japanese" ||
                       cfg.language == "ko" || cfg.language == "korean" ||
                       cfg.language.starts_with("zh") || cfg.language.starts_with("chinese") ||
                       cfg.separator == "\xE3\x80\x80");
        if (is_cjk || cfg.mnemonics.size() >= 21) {
            slot_size = 512;
        } else if (cfg.mnemonics.size() > 12) {
            slot_size = 256;
        }

        // Pré-calcula o bloco de salt do PBKDF2 com suporte a passphrase
        uint64_t salt_block64[16] = {};
        std::string salt = "mnemonic" + cfg.passphrase;
        size_t salt_len = salt.size();
        uint8_t s_buf[128] = {};
        std::memcpy(s_buf, salt.data(), salt_len);
        s_buf[salt_len]     = 0;
        s_buf[salt_len + 1] = 0;
        s_buf[salt_len + 2] = 0;
        s_buf[salt_len + 3] = 1;
        s_buf[salt_len + 4] = 0x80;

        uint64_t s_blk[16];
        std::memcpy(s_blk, s_buf, 128);
        for (int w = 0; w < 15; ++w) {
            salt_block64[w] = __builtin_bswap64(s_blk[w]);
        }
        salt_block64[15] = static_cast<uint64_t>(128 + salt_len + 4) * 8;

        if (!cryptowords::GPUEngine::get_instance().init(cfg.gpu_platform, cfg.gpu_device, cfg.gpu_batch, salt_block64, false, slot_size)) {
            std::println(stderr, "\n[✗] FALHA NA INICIALIZAÇÃO DA GPU");
            std::println(stderr, "    Motivo: Não foi possível inicializar o dispositivo ou compilar os kernels OpenCL.");
            return 1;
        }
    }

    const auto plan = SearchOptimizer::build_plan(cfg);
    SearchReporter::print_plan(plan, cfg);

    cryptowords::ExecutionPipeline pipeline(cfg, plan);
    cryptowords::BruteForceEngine::run(pipeline, cfg.num_threads);
    return 0;
}
