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

    app.add_flag("--invalid_too", raw.invalid_too,
                 "Include invalid checksums in search");

    try {
        app.parse(argc, argv);
    } catch (const CLI::CallForHelp&) {
        std::cout << app.help() << std::endl;
        return std::unexpected("HELP");
    } catch (const CLI::Error& e) {
        return std::unexpected(e.what());
    }

    return raw;
}
