#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace cryptowords {

class CuckooFilter;

enum class CoinTarget : uint8_t { BTC, ETH };

enum class SearchStrategy : uint8_t {
    None        = 0,
    HammingGrad = 1u << 0,
    Frequency   = 1u << 1,
    Typo        = 1u << 2,
    Default     = 1u << 3,
};

[[nodiscard]] constexpr SearchStrategy operator|(SearchStrategy a, SearchStrategy b) noexcept {
    return static_cast<SearchStrategy>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}
constexpr SearchStrategy& operator|=(SearchStrategy& a, SearchStrategy b) noexcept { return a = a | b; }
[[nodiscard]] constexpr bool has_bit(SearchStrategy mask, SearchStrategy s) noexcept {
    return (static_cast<uint8_t>(mask) & static_cast<uint8_t>(s)) != 0;
}

using MnemonicSlot = std::variant<uint16_t, std::vector<uint16_t>>;
enum class ProgressMode : uint8_t { Word, Num };

using Target160 = std::array<uint8_t, 20>;

// 2^64 - 59 (primo). Usado como seed padrão de --random.
inline constexpr uint64_t DEFAULT_RANDOM_SEED = 18446744073709551557ULL;

struct ChecksumPattern {
    uint16_t mask  = 0;
    uint16_t value = 0;
};

struct RawOptions {
    std::string mnemonics;
    std::string target;
    std::string target_file;
    std::string allow;
    std::string allow_all;
    std::string lang = "en";
    std::string prog = "word";
    std::string passphrase;
    std::string checksum;
    std::vector<std::string> strategies;
    std::vector<std::string> repeat;
    size_t max_distance = 2;
    size_t size = 12;
    size_t num_threads = 0;
    size_t pbkdf2_rounds = 2048;
    uint64_t random_seed = 0;
    CoinTarget coin = CoinTarget::BTC;
    bool random = false;
    bool use_gpu = false;
    bool use_cpu = false;
    bool list_gpus = false;
    int gpu_platform = -1;
    int gpu_device = -1;
    size_t gpu_batch = 0;
    bool use_hybrid = false;
    bool invalid_too = false;
    bool distinct = false;
    bool profile_gpu = false;
    bool probe_hardware = false;
    bool pin_cores = true;
    bool quiet = false;
    bool resume_strict = false;
    std::string save_path;
    std::string load_path;
    int save_interval_sec = 0;
};

struct AppConfig {
    static constexpr uint16_t UNKNOWN_WORD = 0xFFFF;

    std::vector<MnemonicSlot> mnemonics;
    std::vector<std::string> wordlist;
    ProgressMode prog_mode = ProgressMode::Word;
    std::string separator = " ";
    std::string passphrase;
    std::string language = "en";

    std::vector<std::pair<uint16_t, uint8_t>> repeat_ids;

    std::vector<ChecksumPattern> checksum_patterns;
    std::string checksum_repr;
    bool has_checksum_filter = false;

    std::vector<Target160> targets;
    std::string target;
    std::shared_ptr<const cryptowords::CuckooFilter> target_cuckoo;

    uint64_t pbkdf2_rounds = 2048;
    size_t num_threads = 0;
    size_t n_unknowns = 0;
    size_t raw_unknowns = 0;
    size_t max_distance = 2;

    CoinTarget coin = CoinTarget::BTC;
    SearchStrategy strategy_mask = SearchStrategy::Default;

    bool has_strategy(SearchStrategy s) const noexcept { return has_bit(strategy_mask, s); }

    bool only_valids = true;
    bool use_gpu = false;
    bool use_cpu = false;
    bool use_hybrid = false;
    bool list_gpus = false;
    int gpu_platform = -1;
    int gpu_device = -1;
    size_t gpu_batch = 0;
    bool distinct = false;
    bool profile_gpu = false;
    bool probe_hardware = false;
    bool pin_cores = true;
    bool quiet = false;
    bool resume_strict = false;

    // Modo pseudoaleatório.
    bool random = false;
    uint64_t random_seed = DEFAULT_RANDOM_SEED;

    std::string save_path;
    std::string load_path;
    int save_interval_sec = 0;
};

}  // namespace cryptowords
