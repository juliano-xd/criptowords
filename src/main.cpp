#include <cstdint>
#include <cstring>
#include <print>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "../include/cli/parser.hpp"
#include "../include/cli/ui.hpp"
#include "../include/cli/validator.hpp"
#include "../include/config.hpp"
#include "../include/crypto/bip39.hpp"
#include "../include/crypto/secp256k1_point.hpp"
#include "../include/gpu/gpu_backend.hpp"
#include "../include/hardware/hardware_advisor.hpp"
#include "../include/hardware/host_probe.hpp"
#include "../include/search/engine.hpp"
#include "../include/search/optimizer.hpp"
#include "../include/search/pipeline.hpp"
#include "../include/search/reporter.hpp"

using namespace cryptowords;
using namespace std;

namespace {

bool is_fully_known(const AppConfig& cfg) {
    for (const auto& w : cfg.mnemonics)
        if (!holds_alternative<uint16_t>(w) ||
            get<uint16_t>(w) == AppConfig::UNKNOWN_WORD) return false;
    return true;
}

bool run_derivation_mode(const AppConfig& cfg) {
    vector<uint16_t> ids;
    ids.reserve(cfg.mnemonics.size());
    for (const auto& w : cfg.mnemonics) ids.push_back(get<uint16_t>(w));

    span<const uint16_t> ids_span(ids);

    if (cfg.only_valids && !cryptowords::Bip39Deriver::verify_checksum(ids)) {
        println(stderr, "\n[\033[1;31m✗\033[0m] Checksum BIP-39 inválido.");
        println(stderr, "    Se tem certeza, rode com --invalid_too.");
        return false;
    }

    const char* pp = cfg.passphrase.empty() ? nullptr : cfg.passphrase.c_str();
    std::array<uint8_t, 32> priv{};
    const string addr =
        (cfg.coin == CoinTarget::BTC)
            ? cryptowords::Bip39Deriver::derive_btc_address(
                  ids_span, cfg.wordlist, pp, cfg.passphrase.size(),
                  cfg.pbkdf2_rounds, cfg.separator, &priv)
            : cryptowords::Bip39Deriver::derive_eth_address(
                  ids_span, cfg.wordlist, pp, cfg.passphrase.size(),
                  cfg.pbkdf2_rounds, cfg.separator, &priv);

    if (cfg.quiet) {
        println("{}", addr);
        return true;
    }

    const size_t C = ids.size() / 3;
    uint8_t cs = 0;
    (void)cryptowords::Bip39Deriver::extract_checksum(ids_span, cs);
    std::string cs_bin(C, '0');
    for (size_t i = 0; i < C; ++i)
        if ((cs >> (C - 1 - i)) & 1) cs_bin[i] = '1';

    static constexpr char H[] = "0123456789abcdef";
    auto to_hex = [&](const uint8_t* p, size_t n_) {
        std::string s;
        for (size_t i = 0; i < n_; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 0x0F]; }
        return s;
    };

    println("\n[\033[1;32m✓\033[0m] DERIVAÇÃO CONCLUÍDA");
    println("  • Moeda           : {}",
            (cfg.coin == CoinTarget::BTC ? "Bitcoin (BTC)" : "Ethereum (ETH)"));
    println("  • Tamanho Frase   : {} palavras", ids.size());
    println("  • Checksum        : 0b{} ({} bits)", cs_bin, C);
    println("  • Endereço gerado : \033[1;32m{}\033[0m", addr);
    println("  • Chave Privada   : \033[1;35m0x{}\033[0m", to_hex(priv.data(), 32));
    if (!cfg.passphrase.empty())
        println("  • Senha (Pass)    : \"{}\"", cfg.passphrase);
    println();
    return true;
}

}  // namespace

int main(int argc, char* argv[]) {
    auto raw = CLIParser::parse(argc, argv);
    if (!raw) {
        if (raw.error() == "HELP") return 0;
        println(stderr, "\n[\033[1;31m✗\033[0m] FALHA NA INICIALIZAÇÃO");
        println(stderr, "    Motivo: {}", raw.error());
        println(stderr, "\nUse '--help' para ver os exemplos de uso.");
        return 1;
    }

    auto config = ConfigValidator::validate(*raw);
    if (!config) {
        println(stderr, "\n[\033[1;31m✗\033[0m] FALHA NA INICIALIZAÇÃO");
        println(stderr, "    Motivo: {}", config.error());
        println(stderr, "\nUse '--help' para ver os exemplos de uso.");
        return 1;
    }
    auto cfg = *config;

    crypto::warmup_secp256k1_table();

    const bool need_gpu_probe = cfg.use_gpu || cfg.use_hybrid || cfg.list_gpus || cfg.probe_hardware;
    const auto host_profile = cryptowords::hardware::HostProbe::probe_all(need_gpu_probe);
    const auto tuning = cryptowords::hardware::HardwareAdvisor::analyze(cfg, host_profile);

    if (cfg.probe_hardware) {
        cryptowords::hardware::HardwareAdvisor::print_host_report(host_profile, tuning);
        return 0;
    }

    cryptowords::hardware::HardwareAdvisor::apply_tuning(cfg, tuning);

    if (cfg.list_gpus) {
        cryptowords::print_gpu_device_list();
        return 0;
    }

    if (is_fully_known(cfg) && cfg.targets.empty())
        return run_derivation_mode(cfg) ? 0 : 1;

    if (cfg.use_gpu || cfg.use_hybrid) {
        const size_t slot_size = tuning.chosen_slot_size;

        uint64_t salt_block64[16] = {};
        std::string salt = "mnemonic" + cfg.passphrase;
        const size_t salt_len = salt.size();
        uint8_t s_buf[128] = {};
        std::memcpy(s_buf, salt.data(), salt_len);
        s_buf[salt_len + 3] = 1;
        s_buf[salt_len + 4] = 0x80;

        uint64_t s_blk[16];
        std::memcpy(s_blk, s_buf, 128);
        for (int w = 0; w < 15; ++w) salt_block64[w] = __builtin_bswap64(s_blk[w]);
        salt_block64[15] = static_cast<uint64_t>(128 + salt_len + 4) * 8;

        if (!cryptowords::init_gpu_engine(cfg, slot_size, salt_block64)) {
            println(stderr, "\n[\033[1;31m✗\033[0m] FALHA NA INICIALIZAÇÃO DA GPU");
            println(stderr, "    Verifique drivers (ROCm/CUDA) e permissões.");
            return 1;
        }
    }

    const auto plan = SearchOptimizer::build_plan(cfg);

    if (plan.impossible) {
        println(stderr,
                "\n[\033[1;31m✗\033[0m] Restrições impossíveis.\n"
                "    Verifique --repeat (Σ N ≤ K) e se cada palavra tem N ≥ 1.");
        return 1;
    }

    SearchReporter::print_plan(plan, cfg);
    cryptowords::hardware::HardwareAdvisor::print_tuning_summary(tuning, cfg.quiet);
    std::fflush(stdout);

    cryptowords::ExecutionPipeline pipeline(cfg, plan);
    cryptowords::BruteForceEngine::run(pipeline, cfg.num_threads);

    if (cfg.use_gpu) cryptowords::shutdown_gpu_engine();
    return 0;
}
