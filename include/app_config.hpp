#pragma once
#include <cstddef>
#include <cstdint>
#include <flat_map>
#include <string>
#include <variant>
#include <vector>

enum class CoinTarget : uint8_t { BTC, ETH };

using MnemonicSlot = std::variant<uint16_t, std::vector<uint16_t>>;

struct AppConfig {
    uint64_t pbkdf2_rounds = 2048;
    size_t num_threads = 1;
    size_t unknows = 0;

    CoinTarget coin = CoinTarget::BTC;
    bool is_help_request = false;
    bool only_valids = true;
    bool use_gpu = false;

    static constexpr uint16_t UNKNOWN_WORD = 0xFFFF;
    std::vector<MnemonicSlot> mnemonics;
    std::vector<std::string> wordlist;

    std::string target;
    std::string separator = " ";
    std::string passphrase;

    void* gpu_engine = nullptr;
};
