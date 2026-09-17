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

#include <print>
#include <variant>

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
        ? cryptowords::Bip39Deriver::derive_btc_address(ctx, ids, cfg.wordlist, pp, cfg.passphrase.size(), cfg.pbkdf2_rounds)
        : cryptowords::Bip39Deriver::derive_eth_address(ctx, ids, cfg.wordlist, pp, cfg.passphrase.size(), cfg.pbkdf2_rounds);
    secp256k1_context_destroy(ctx);

    std::println("\n[✓] DERIVAÇÃO CONCLUÍDA COM SUCESSO");
    std::println("    [+] Endereço gerado: {}", addr);
    return true;
}

static void print_config_summary(const AppConfig& cfg) {
    std::println("\n[✓] Configurações validadas com sucesso!");
    std::println("    [+] Moeda: {}", cfg.coin == CoinTarget::BTC ? "bitcoin" : "ethereum");
    std::println("    [+] Password: \"{}\"", cfg.passphrase);
    std::println("    [+] Rounds: {}", cfg.pbkdf2_rounds);
    std::println("    [+] Size: {}", cfg.mnemonics.size());
    std::println("    [+] Words desconhecidas: {}", cfg.unknows);
    std::println("    [+] GPU: {}", cfg.use_gpu);
    std::println("    [+] Apenas chaves validas: {}", cfg.only_valids);
    std::println("    [+] Threads: {}", cfg.num_threads);
    if (!cfg.target.empty()) std::println("    [+] Target: {}", cfg.target);
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
    print_config_summary(cfg);

    // Modo simples: todas as palavras conhecidas, sem target.
    if (is_fully_known(cfg) && cfg.target.empty()) {
        std::println("\n[=] Iniciando Modo de Derivação Simples...");
        return run_derivation_mode(cfg) ? 0 : 1;
    }

    // Modo força bruta.
    if (cfg.use_gpu) {
        cryptowords::gpu::detect_and_print_capabilities();
        if (!cryptowords::GPUEngine::get_instance().init()) {
            std::println(stderr, "\n[✗] FALHA NA INICIALIZAÇÃO DA GPU");
            std::println(stderr, "    Motivo: Não foi possível compilar os kernels OpenCL.");
            return 1;
        }
    }

    const auto plan = SearchOptimizer::build_plan(cfg);
    SearchReporter::print_plan(plan, cfg);

    std::println("\n[=] Iniciando motor de processamento...\n");
    std::println("\n[+] Construindo pipeline otimizado (JIT)...");

    cryptowords::ExecutionPipeline pipeline(cfg, plan);
    cryptowords::BruteForceEngine::run(pipeline, cfg.num_threads);
    return 0;
}
