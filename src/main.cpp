#include <secp256k1.h>
#include "../include/bip39.hpp"
#include "../include/brute_force_engine.hpp"
#include "../include/cli_parser.hpp"
#include "../include/gpu_engine.hpp"
#include "../include/search_optimizer.hpp"
#include "../include/search_plan.hpp"
#include <print>

int main(int argc, char* argv[]) {
    // 1. CLI pega o input e manda para o Parser
    auto parse_result = CLIParser::parse_and_validate(argc, argv);

    // 2. Se o parser barrar algo nas regras de negócio, a CLI informa o usuário
    if (!parse_result) {
        std::println(stderr, "\n[✗] FALHA NA INICIALIZAÇÃO");
        std::println(stderr, "    Motivo: {}", parse_result.error());
        std::println(stderr, "\nUse '--help' para ver os exemplos de uso.");
        return 1;
    }

    // 3. Extrai a configuração garantidamente válida
    AppConfig config = std::move(*parse_result);

    // Tratamento de Help
    if (config.is_help_request) {
        std::print("{}", CLIParser::get_help_text());
        return 0;
    }

    // 4. Feedback visual de que tudo deu certo
    std::println("\n[✓] Configurações validadas com sucesso!");
    std::println("    [+] Moeda: {}", config.coin == CoinTarget::BTC ? "bitcon" : "etherium");
    std::println("    [+] Password: \"{}\"", config.passphrase);
    std::println("    [+] Rounds: {}", config.pbkdf2_rounds);
    std::println("    [+] Size: {}", config.mnemonics.size());
    std::println("    [+] Words desconhecidas: {}", config.unknows);
    std::println("    [+] GPU: {}", config.use_gpu);
    std::println("    [+] Apenas chaves validas: {}", config.only_valids);
    std::println("    [+] Threads: {}", config.num_threads);

    if (!config.target.empty()) {
        std::println("    [+] Target: {}", config.target);
    }

    // ==========================================================
    // 5. OTIMIZADOR DE BUSCA (Prepara a matriz de inteiros)
    // ==========================================================
    OptimizedMnemonics plan = SearchOptimizer::build_plan(config);

    // Imprime o relatório de como ficou a matriz e a matemática real
    SearchOptimizer::print_report(plan, config);

    std::println("\n[=] Iniciando motor de processamento...\n");

    // ==========================================================
    // 6. MOTOR DE FORÇA BRUTA (Executa o hodômetro)
    // ==========================================================

if (config.unknows == 0) {
        std::println("\n[=] Nenhuma palavra desconhecida. Derivando endereço direto...");
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        
        std::string derived = (config.coin == CoinTarget::BTC) ?
            cryptowords::Bip39Deriver::derive_btc_address(ctx, plan.base_mnemonic, config.wordlist, config.passphrase.data(), config.passphrase.size()) :
            cryptowords::Bip39Deriver::derive_eth_address(ctx, plan.base_mnemonic, config.wordlist, config.passphrase.data(), config.passphrase.size());
            
        std::println("    [+] Endereço derivado: {}", derived);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    // Tentar GPU primeiro se habilitado
    if (config.use_gpu) {
        gpu::Engine gpu;
        if (gpu.init("/home/trindade/temp/criptowords/src/pbkdf2_hmac512.cl")) {
            std::println("[GPU] Usando device: {}", gpu.device_name());
            config.gpu_engine = &gpu;
            BruteForceEngine::run_parallel_gpu(config, plan, gpu);
            return 0;
        } else {
            std::println("[GPU] OpenCL não disponível, usando CPU...");
        }
    }

    if (config.num_threads > 1) {
        BruteForceEngine::run_parallel_avx2(config, plan);
    } else {
        BruteForceEngine::run_sequential(config, plan);
    }

    return 0;
}
