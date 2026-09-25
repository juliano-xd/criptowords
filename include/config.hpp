#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

enum class CoinTarget : uint8_t { BTC, ETH };
enum class SearchStrategy : uint8_t { Default, HammingGradient, Frequency, Typo };
using MnemonicSlot = std::variant<uint16_t, std::vector<uint16_t>>;

// Saída bruta da CLI — antes de qualquer validação.
struct RawOptions {
    std::string              mnemonics;
    std::string              target;
    std::string              allow;
    std::string              lang = "en";
    std::string              passphrase;
    std::vector<std::string> strategies;
    std::string              strategy;
    size_t                   max_distance  = 2;
    size_t                   size          = 12;
    size_t                   num_threads   = 0;
    size_t                   pbkdf2_rounds = 2048;
    CoinTarget               coin          = CoinTarget::BTC;
    bool                     use_gpu       = false;
    bool                     use_cpu       = false;
    bool                     list_gpus     = false;
    int                      gpu_platform  = -1;
    int                      gpu_device    = -1;
    size_t                   gpu_batch     = 0;
    bool                     use_hybrid    = false;
    bool                     invalid_too   = false;
    bool                     distinct      = false;
    bool                     run_benchmark = false;
    bool                     profile_gpu   = false;
    bool                     probe_hardware = false;
    bool                     pin_cores      = true;
};

// Configuração validada — pronta para o motor.
struct AppConfig {
    static constexpr uint16_t UNKNOWN_WORD = 0xFFFF;

    std::vector<MnemonicSlot> mnemonics;
    std::vector<std::string>  wordlist;

    std::string target;
    std::string separator  = " ";
    std::string passphrase;
    std::string language   = "en";

    uint64_t pbkdf2_rounds = 2048;
    size_t   num_threads   = 0;
    size_t   unknows       = 0;
    size_t   max_distance  = 2;

    CoinTarget                  coin       = CoinTarget::BTC;
    std::vector<SearchStrategy> strategies = {SearchStrategy::Default};
    SearchStrategy              strategy   = SearchStrategy::Default;

    bool has_strategy(SearchStrategy s) const {
        for (auto x : strategies) if (x == s) return true;
        return false;
    }

    bool only_valids   = true;
    bool use_gpu       = false;
    bool use_cpu       = false;
    bool use_hybrid    = false;
    bool list_gpus     = false;
    int  gpu_platform  = -1;
    int  gpu_device    = -1;
    size_t gpu_batch   = 0;
    bool distinct      = false;
    bool run_benchmark = false;
    bool profile_gpu   = false;
    bool probe_hardware = false;
    bool pin_cores      = true;
};
