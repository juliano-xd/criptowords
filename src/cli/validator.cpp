#include "../../include/cli/validator.hpp"
#include "../../include/cli/wordlist.hpp"
#include "../../include/crypto/bip39.hpp"
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <string>
#include <thread>
#include <map>
#include <unordered_map>
#include <format>

static std::expected<std::map<size_t, std::vector<std::string>>, std::string>
parse_constraint_map(std::string_view input) {
    std::map<size_t, std::vector<std::string>> result;
    for (const auto group : std::views::split(input, ',')) {
        std::string_view g(group);
        if (g.empty())
            continue;
        auto pos_colon = g.find(':');
        if (pos_colon == std::string_view::npos) {
            return std::unexpected(std::format("Faltando ':' em '{}'", g));
        }
        size_t pos = 0;
        std::string_view pos_str = g.substr(0, pos_colon);
        auto [ptr, ec] = std::from_chars(pos_str.data(), pos_str.data() + pos_str.size(), pos);
        if (ec != std::errc() || ptr != pos_str.data() + pos_str.size()) {
            return std::unexpected(std::format("Posição inválida no mapa: '{}'", pos_str));
        }
        auto words = g.substr(pos_colon + 1) | std::views::split('|') |
                     std::views::filter([](auto r) { return !r.empty(); }) |
                     std::views::transform([](auto r) { return std::string(r.begin(), r.end()); });
        result[pos].append_range(words);
    }
    return result;
}

std::expected<AppConfig, std::string> ConfigValidator::validate(const RawOptions& raw) {
    AppConfig cfg;

    cfg.list_gpus     = raw.list_gpus;
    cfg.run_benchmark = raw.run_benchmark;
    cfg.profile_gpu   = raw.profile_gpu;
    cfg.gpu_platform  = raw.gpu_platform;
    cfg.gpu_device    = raw.gpu_device;
    cfg.gpu_batch     = raw.gpu_batch;
    cfg.probe_hardware = raw.probe_hardware;
    cfg.pin_cores     = raw.pin_cores;
    cfg.num_threads   = raw.num_threads;

    if (raw.list_gpus || raw.run_benchmark || raw.probe_hardware) {
        return cfg;
    }


    size_t raw_size = raw.size;
    std::string raw_lang = raw.lang;
    std::string norm_lang = WordlistLoader::normalize_lang(raw_lang);

    cfg.language = norm_lang;
    cfg.coin = raw.coin;
    cfg.passphrase = raw.passphrase;
    cfg.num_threads = raw.num_threads;
    cfg.pbkdf2_rounds = raw.pbkdf2_rounds;
    cfg.use_gpu = raw.use_gpu;
    cfg.use_hybrid = raw.use_hybrid;
    if (cfg.use_hybrid) cfg.use_gpu = true;
    cfg.only_valids = !raw.invalid_too;
    cfg.distinct = raw.distinct;
    cfg.target = raw.target;
    cfg.max_distance = raw.max_distance;
    cfg.probe_hardware = raw.probe_hardware;
    cfg.pin_cores = raw.pin_cores;


    std::vector<std::string> tokenized_strategies;
    for (const auto& item : raw.strategies) {
        for (const auto part : std::views::split(item, '+')) {
            std::string s(part.begin(), part.end());
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
            if (!s.empty()) tokenized_strategies.push_back(std::move(s));
        }
    }
    if (tokenized_strategies.empty()) {
        tokenized_strategies.push_back("default");
    }

    cfg.strategies.clear();
    for (auto& s : tokenized_strategies) {
        std::ranges::transform(s, s.begin(), [](unsigned char c) { return std::tolower(c); });
        if (s == "default") {
            if (!cfg.has_strategy(SearchStrategy::Default)) cfg.strategies.push_back(SearchStrategy::Default);
        } else if (s == "hamming" || s == "hamming-gradient" || s == "hamming_gradient") {
            if (!cfg.has_strategy(SearchStrategy::HammingGradient)) cfg.strategies.push_back(SearchStrategy::HammingGradient);
        } else if (s == "frequency") {
            if (!cfg.has_strategy(SearchStrategy::Frequency)) cfg.strategies.push_back(SearchStrategy::Frequency);
        } else if (s == "typo") {
            if (!cfg.has_strategy(SearchStrategy::Typo)) cfg.strategies.push_back(SearchStrategy::Typo);
        } else {
            return std::unexpected(std::format("Estratégia de busca inválida: '{}'. Opções válidas: default, hamming, frequency, typo", s));
        }
    }
    if (cfg.strategies.empty()) {
        cfg.strategies.push_back(SearchStrategy::Default);
    }
    cfg.strategy = cfg.strategies[0];

    cfg.mnemonics.resize(raw_size, AppConfig::UNKNOWN_WORD);
    cfg.unknows = raw_size;

    auto wl_res = WordlistLoader::load(raw_lang);
    if (!wl_res)
        return std::unexpected(wl_res.error());
    cfg.wordlist = std::move(wl_res.value());

    std::unordered_map<std::string, uint16_t> word_to_id = WordlistLoader::build_index(cfg.wordlist);

    if (norm_lang == "japanese") {
        cfg.separator = "\xE3\x80\x80";
    }

    std::map<size_t, std::vector<std::string>> raw_allow;
    if (!raw.allow.empty()) {
        auto allow_res = parse_constraint_map(raw.allow);
        if (!allow_res)
            return std::unexpected(allow_res.error());
        raw_allow = std::move(*allow_res);
    }

    if (!raw.mnemonics.empty()) {
        std::string cleaned_mnemonics = raw.mnemonics;
        const std::string id_space = "\xE3\x80\x80";
        size_t p = 0;
        while ((p = cleaned_mnemonics.find(id_space, p)) != std::string::npos) {
            cleaned_mnemonics.replace(p, id_space.length(), " ");
            p += 1;
        }

        for (char& c : cleaned_mnemonics) {
            if (c == '\t' || c == '\n' || c == '\r') c = ' ';
        }

        auto words_view =
            cleaned_mnemonics | std::views::split(' ') |
            std::views::filter([](auto r) { return !r.empty(); }) |
            std::views::transform([](auto r) { return std::string(r.begin(), r.end()); });

        std::vector<std::string> temp_mnemonic;
        temp_mnemonic.append_range(words_view);

        if (temp_mnemonic.size() != raw_size) {
            const size_t sz = temp_mnemonic.size();
            if (raw_size == 12 && (sz == 15 || sz == 18 || sz == 21 || sz == 24)) {
                raw_size = sz;
                cfg.mnemonics.resize(raw_size, AppConfig::UNKNOWN_WORD);
                cfg.unknows = raw_size;
            } else {
                return std::unexpected(
                    std::format("Tamanho incorreto. --size é {}, mas você forneceu {} palavras (use '?' para posições desconhecidas).",
                                raw_size, temp_mnemonic.size()));
            }
        }

        for (size_t i = 0; i < temp_mnemonic.size(); ++i) {
            const auto& w = temp_mnemonic[i];
            if (w != "?") {
                auto it = word_to_id.find(w);
                if (it == word_to_id.end()) {
                    std::string nfc_w = WordlistLoader::to_nfc(w);
                    it = word_to_id.find(nfc_w);
                }
                if (it == word_to_id.end()) {
                    return std::unexpected(
                        std::format("A palavra '{}' não existe na wordlist '{}'.", w, raw_lang));
                }
                cfg.mnemonics[i] = it->second;
                cfg.unknows--;
            }
        }
    } else if (cfg.target.empty()) {
        return std::unexpected("Forneça um '--mnemonics' ou um '--target' para iniciar a busca.");
    }

    for (const auto& [pos, words] : raw_allow) {
        if (pos >= raw_size) {
            return std::unexpected(
                std::format("Posição {} do --allow é maior ou igual ao tamanho ({}).", pos, raw_size));
        }
        if (words.empty())
            continue;

        if (std::holds_alternative<uint16_t>(cfg.mnemonics[pos]) &&
            std::get<uint16_t>(cfg.mnemonics[pos]) != AppConfig::UNKNOWN_WORD) {
            return std::unexpected(std::format(
                "A posição {} já está preenchida pela mnemonic base. Não use --allow nela.", pos));
        }

        std::vector<uint16_t> translated_allows;
        translated_allows.reserve(words.size());

        for (const auto& w : words) {
            auto it = word_to_id.find(w);
            if (it == word_to_id.end()) {
                std::string nfc_w = WordlistLoader::to_nfc(w);
                it = word_to_id.find(nfc_w);
            }
            if (it == word_to_id.end()) {
                return std::unexpected(std::format("A palavra permitida '{}' não existe.", w));
            }
            translated_allows.push_back(it->second);
        }

        std::ranges::sort(translated_allows);
        auto [first, last] = std::ranges::unique(translated_allows);
        translated_allows.erase(first, last);

        if (translated_allows.size() == 1) {
            cfg.mnemonics[pos] = translated_allows.front();
            cfg.unknows--;
        } else {
            cfg.mnemonics[pos] = std::move(translated_allows);
        }
    }

    bool has_ambiguity = false;
    for (const auto& w : cfg.mnemonics) {
        if (std::holds_alternative<std::vector<uint16_t>>(w)) {
            if (std::get<std::vector<uint16_t>>(w).size() > 1) {
                has_ambiguity = true;
                break;
            }
        } else if (std::holds_alternative<uint16_t>(w)) {
            if (std::get<uint16_t>(w) == AppConfig::UNKNOWN_WORD) {
                has_ambiguity = true;
                break;
            }
        }
    }

    if (has_ambiguity && cfg.target.empty()) {
        return std::unexpected(
            "O parâmetro '--target' é obrigatório quando há posições desconhecidas ou com múltiplas opções (--allow).");
    }

    if (cfg.passphrase.size() > 99) {
        return std::unexpected("Passphrase suporta no máximo 99 caracteres.");
    }

    if (cfg.use_gpu) {
        if (cfg.pbkdf2_rounds != 2048) {
            return std::unexpected(std::format("Aceleração por GPU exige '--rounds 2048' (padrão BIP39), mas {} foi solicitado.", cfg.pbkdf2_rounds));
        }
        if (cfg.use_hybrid) {
            if (cfg.num_threads == 0) {
                cfg.num_threads = std::thread::hardware_concurrency();
            }
        } else {
            if (raw.num_threads > 1) {
                cfg.use_hybrid = true;
                cfg.num_threads = raw.num_threads;
            } else {
                cfg.num_threads = 1;
            }
        }
    } else {
        if (cfg.num_threads == 0) {
            cfg.num_threads = std::max(1u, std::thread::hardware_concurrency() / 2);
        }
    }

    if (!cfg.target.empty()) {
        uint8_t dummy[20];
        if (cfg.coin == CoinTarget::BTC) {
            if (!cryptowords::Bip39Deriver::decode_base58_btc_address(cfg.target, dummy)) {
                return std::unexpected(std::format("Endereço Bitcoin inválido: {}", cfg.target));
            }
        } else {
            if (!cryptowords::Bip39Deriver::decode_hex_eth_address(cfg.target, dummy)) {
                return std::unexpected(std::format("Endereço Ethereum inválido: {}", cfg.target));
            }
        }
    }

    return cfg;
}
