#include "../../include/cli/parser.hpp"
#include <CLI/CLI.hpp>
#include <iostream>
#include <string>
#include <vector>

std::expected<RawOptions, std::string> CLIParser::parse(int argc, char* argv[]) {
    CLI::App app{"CriptoWords - BIP39 Mnemonic Recovery Engine"};

    RawOptions raw;

    app.add_option("--mnemonics", raw.mnemonics,
                   "Mnemonic phrase with '?' for unknown positions")
        ->type_name("MNEMONIC");

    app.add_option("--target", raw.target,
                   "Target BTC/ETH address to find")
        ->type_name("ADDRESS");

    app.add_option("--allow", raw.allow,
                   "Allowed words for unknown positions (pos:w1|w2|...)")
        ->type_name("CONSTRAINT");

    app.add_option("--size", raw.size,
                   "Mnemonic size: 12, 15, 18, 21 or 24")
        ->type_name("NUM")
        ->default_val(12)
        ->check(CLI::IsMember({12, 15, 18, 21, 24}));

    app.add_option("--lang", raw.lang,
                   "Wordlist language (en, pt, es, fr, etc.)")
        ->type_name("ID")
        ->default_val("en");

    const std::vector<std::pair<std::string, CoinTarget>> coin_map = {
        {"btc", CoinTarget::BTC},
        {"eth", CoinTarget::ETH}
    };

    app.add_option("--coin", raw.coin,
                   "Target coin (btc or eth)")
        ->type_name("COIN")
        ->transform(CLI::CheckedTransformer(coin_map, CLI::ignore_case))
        ->default_str("btc");

    app.add_option("--passphrase", raw.passphrase,
                   "BIP39 passphrase")
        ->type_name("STRING");

    app.add_option("--threads", raw.num_threads,
                   "Number of threads")
        ->type_name("NUM")
        ->default_val(0);

    app.add_option("--rounds", raw.pbkdf2_rounds,
                   "PBKDF2 iterations")
        ->type_name("NUM")
        ->default_val(2048);

    app.add_flag("--gpu", raw.use_gpu,
                 "Enable GPU acceleration via OpenCL");

    app.add_flag("--hybrid", raw.use_hybrid,
                 "Enable hybrid CPU (AVX2) + GPU co-processing");

    app.add_flag("--list-gpus", raw.list_gpus,
                 "List all detected OpenCL platforms and devices and exit");

    app.add_option("--gpu-platform", raw.gpu_platform,
                   "OpenCL platform index (default: auto)")
        ->type_name("ID")
        ->default_val(-1);

    app.add_option("--gpu-device", raw.gpu_device,
                   "OpenCL device index (default: auto)")
        ->type_name("ID")
        ->default_val(-1);

    app.add_option("--gpu-batch", raw.gpu_batch,
                   "GPU batch size (default: auto-tuned by VRAM/CUs)")
        ->type_name("NUM")
        ->default_val(0);

    app.add_flag("--invalid_too", raw.invalid_too,
                 "Include invalid checksums in search");

    app.add_flag("--distinct", raw.distinct,
                 "Assume distinct words in mnemonic (prunes known words from unknown wheels)");

    app.add_option("--strategy", raw.strategies,
                   "Search strategies: default, hamming, frequency, typo (can be combined)")
        ->type_name("STRATEGY...")
        ->delimiter(',');

    app.add_option("--max-distance", raw.max_distance,
                   "Maximum edit distance for typo strategy (1-3)")
        ->type_name("NUM")
        ->default_val(2);

    app.add_flag("--benchmark", raw.run_benchmark,
                 "Run full hardware & algorithmic performance benchmark suite and exit");

    app.add_flag("--profile-gpu", raw.profile_gpu,
                 "Profile GPU OpenCL latency and bandwidth metrics during recovery");

    app.add_flag("--host-info,--probe", raw.probe_hardware,
                 "Exibe diagnóstico profundo do hardware do host com auto-tuning recomendado e sai");

    bool no_pin = false;
    app.add_flag("--no-pin", no_pin,
                 "Desativa a afinidade fixa de núcleos físicos de CPU (Core Pinning)");

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
