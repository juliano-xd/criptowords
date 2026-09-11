#include <secp256k1.h>
#include "../include/bip39.hpp"
#include "../include/brute_force_engine.hpp"
#include "../include/cli_parser.hpp"
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
    std::println("    [+] Moeda: {}", config.coin == CoinTarget::BTC ? "bitcoin" : "ethereum");
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

    std::println("\n[+] Construindo pipeline otimizado (JIT)...");
    cryptowords::ExecutionPipeline pipeline(config, plan);
    cryptowords::BruteForceEngine::run(pipeline, config.num_threads);
    return 0;
}

