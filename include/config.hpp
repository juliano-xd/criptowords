#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

enum class CoinTarget : uint8_t { BTC, ETH };
using MnemonicSlot = std::variant<uint16_t, std::vector<uint16_t>>;

// Saída bruta da CLI — antes de qualquer validação.
struct RawOptions {
    std::string mnemonics;
    std::string target;
    std::string allow;
    std::string lang = "en";
    std::string passphrase;
    size_t      size          = 12;
    size_t      num_threads   = 0;
    size_t      pbkdf2_rounds = 2048;
    CoinTarget  coin          = CoinTarget::BTC;
    bool        use_gpu       = false;
    bool        invalid_too   = false;
};

// Configuração validada — pronta para o motor.
struct AppConfig {
    static constexpr uint16_t UNKNOWN_WORD = 0xFFFF;

    std::vector<MnemonicSlot> mnemonics;
    std::vector<std::string>  wordlist;

    std::string target;
    std::string separator  = " ";
    std::string passphrase;

    uint64_t pbkdf2_rounds = 2048;
    size_t   num_threads   = 1;
    size_t   unknows       = 0;

    CoinTarget coin        = CoinTarget::BTC;
    bool       only_valids = true;
    bool       use_gpu     = false;
};
