#include "../../include/cli/parser.hpp"

#include <CLI/CLI.hpp>
#include <iostream>
#include <string>
#include <vector>

using namespace cryptowords;

std::expected<RawOptions, std::string> CLIParser::parse(int argc, char* argv[]) {
    CLI::App app{"CriptoWords - BIP39 Mnemonic Recovery Engine"};

    RawOptions raw;

    app.add_option("--mnemonics", raw.mnemonics,
                   "Frase BIP-39 com '?' para posições desconhecidas")
        ->type_name("MNEMONIC");

    app.add_option("--target", raw.target,
                   "Endereço BTC/ETH alvo")
        ->type_name("ADDRESS");
    app.add_option("--target-file", raw.target_file,
                   "Arquivo com um endereço por linha (habilita multi-target)")
        ->type_name("PATH");

    app.add_option("--allow", raw.allow,
                   "Palavras permitidas por posição (pos:w1|w2|...)")
        ->type_name("CONSTRAINT");
    app.add_option("--allow-all", raw.allow_all,
                   "Palavras permitidas aplicadas a todas as incógnitas")
        ->type_name("WORDS");
    app.add_option("--prog", raw.prog,
                   "Modo de progresso: 'word' ou 'num'")
        ->type_name("MODE")->default_val("word")
        ->check(CLI::IsMember({"word", "num"}));

    app.add_option("--size", raw.size, "Tamanho do mnemônico: 12, 15, 18, 21, 24")
        ->type_name("NUM")->default_val(12)
        ->check(CLI::IsMember({12, 15, 18, 21, 24}));
    app.add_option("--lang", raw.lang, "Idioma da wordlist (en, pt, es, fr, ...)")
        ->type_name("ID")->default_val("en");

    const std::vector<std::pair<std::string, CoinTarget>> coin_map = {
        {"btc", CoinTarget::BTC}, {"eth", CoinTarget::ETH}};
    app.add_option("--coin", raw.coin, "Moeda alvo (btc ou eth)")
        ->type_name("COIN")
        ->transform(CLI::CheckedTransformer(coin_map, CLI::ignore_case))
        ->default_str("btc");

    app.add_option("--passphrase", raw.passphrase, "Passphrase BIP39")->type_name("STRING");
    app.add_option("--threads", raw.num_threads, "Número de threads")->type_name("NUM")->default_val(0);
    app.add_option("--rounds", raw.pbkdf2_rounds, "Iterações PBKDF2")->type_name("NUM")->default_val(2048);

    app.add_flag("--gpu", raw.use_gpu, "Ativar aceleração por GPU");
    app.add_flag("--cpu", raw.use_cpu, "Forçar execução SIMD em CPU (desliga auto-tune de GPU)");
    app.add_flag("--hybrid", raw.use_hybrid, "Execução híbrida CPU + GPU");
    app.add_flag("--list-gpus", raw.list_gpus,
                 "Listar plataformas/dispositivos OpenCL detectados e sair");
    app.add_option("--gpu-platform", raw.gpu_platform, "Índice da plataforma OpenCL (auto se -1)")
        ->type_name("ID")->default_val(-1);
    app.add_option("--gpu-device", raw.gpu_device, "Índice do dispositivo OpenCL (auto se -1)")
        ->type_name("ID")->default_val(-1);
    app.add_option("--gpu-batch", raw.gpu_batch, "Tamanho do batch de GPU (auto se 0)")
        ->type_name("NUM")->default_val(0);

    app.add_flag("--invalid_too", raw.invalid_too,
                 "Incluir candidatos com checksum BIP-39 inválido");

    app.add_flag("--distinct", raw.distinct,
                 "Assumir palavras distintas (poda palavras fixas dos wheels)");

    app.add_option("--strategy", raw.strategies,
                   "Estratégias de busca: default, hamming, frequency, typo")
        ->type_name("STRATEGY...")->delimiter(',');
    app.add_option("--max-distance", raw.max_distance,
                   "Distância máxima de edição para a estratégia typo (1-3)")
        ->type_name("NUM")->default_val(2);

    app.add_option("--save", raw.save_path,
                   "Caminho do checkpoint. Habilita gravação de progresso.")
        ->type_name("PATH");
    app.add_option("--save-interval", raw.save_interval_sec,
                   "Intervalo entre checkpoints em segundos (0 = só na saída). Padrão: 60.")
        ->type_name("SEC")->default_val(60);
    app.add_option("--load", raw.load_path,
                   "Retomar busca a partir deste checkpoint.")
        ->type_name("PATH");

    app.add_option("--repeat", raw.repeat,
                   "Palavras com contagem fixa: word1:N,word2:N")
        ->type_name("WORD:N")->delimiter(',');

    app.add_option("--checksum", raw.checksum,
                   "Restringe os candidatos ao conjunto de checksums que casam com o padrão. "
                   "Aceita decimal (7), hex (0x7) ou binário com wildcards (0b*1*0). "
                   "Múltiplos padrões separados por vírgula são OR'ed. "
                   "Sobrepõe --only_valids e --invalid_too.")
        ->type_name("PATTERN");

    app.add_flag("--profile-gpu", raw.profile_gpu,
                 "Perfilar latência/banda da GPU durante a recuperação");
    app.add_flag("--host-info,--probe", raw.probe_hardware,
                 "Diagnóstico do hardware com auto-tuning recomendado e saída");
    app.add_flag("-q,--quiet", raw.quiet,
                 "Suprimir banners e estatísticas finais; mantém progresso e resultado");
    app.add_flag("--resume-strict", raw.resume_strict,
                 "Erro se checkpoint incompatível (default: ignora progresso e continua)");

    app.add_flag("--random", raw.random,
                     "Enumerar o espaço em ordem pseudoaleatória. Preserva save/resume.");
    app.add_option("--seed", raw.random_seed, "Seed para --random (default: 2^64-59). Implica --random.")
        ->type_name("NUM")->default_val(0);

    bool no_pin = false;
    app.add_flag("--no-pin", no_pin,
                 "Desativar afinidade fixa a núcleos físicos de CPU");

    try {
        app.parse(argc, argv);
    } catch (const CLI::CallForHelp&) {
        std::cout << app.help() << std::endl;
        return std::unexpected("HELP");
    } catch (const CLI::Error& e) {
        return std::unexpected(e.what());
    }

    raw.pin_cores = !no_pin;
    return raw;
}
