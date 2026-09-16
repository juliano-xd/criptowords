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

    size_t raw_size = raw.size;
    std::string raw_lang = raw.lang;

    cfg.coin = raw.coin;
    cfg.passphrase = raw.passphrase;
    cfg.num_threads = raw.num_threads;
    cfg.pbkdf2_rounds = raw.pbkdf2_rounds;
    cfg.use_gpu = raw.use_gpu;
    cfg.only_valids = !raw.invalid_too;
    cfg.target = raw.target;

    cfg.mnemonics.resize(raw_size, AppConfig::UNKNOWN_WORD);
    cfg.unknows = raw_size;

    auto wl_res = WordlistLoader::load(raw_lang);
    if (!wl_res)
        return std::unexpected(wl_res.error());
    cfg.wordlist = std::move(wl_res.value());

    std::unordered_map<std::string, uint16_t> word_to_id = WordlistLoader::build_index(cfg.wordlist);

    if (raw_lang == "ja" || raw_lang == "japanese") {
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
        auto words_view =
            raw.mnemonics | std::views::split(' ') |
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
                return std::unexpected(std::format("A palavra permitida '{}' não existe.", w));
            }
            translated_allows.push_back(it->second);
        }

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

    if (cfg.use_gpu) {
        if (!cfg.passphrase.empty()) {
            return std::unexpected("Aceleração por GPU não suporta '--passphrase'. O kernel OpenCL é ultra-otimizado e hardcodado para salt padrão.");
        }
        if (cfg.pbkdf2_rounds != 2048) {
            return std::unexpected(std::format("Aceleração por GPU exige '--rounds 2048' (padrão BIP39), mas {} foi solicitado.", cfg.pbkdf2_rounds));
        }
        if (cfg.mnemonics.size() > 12) {
            return std::unexpected("Aceleração por GPU suporta apenas mnemonics de até 12 palavras (devido ao limite estrito de 128 bytes do kernel Zero-Spill).");
        }
        if (raw_lang == "ja" || raw_lang == "japanese") {
            return std::unexpected("Aceleração por GPU não suporta o idioma Japonês (UTF-8 multi-byte excede o limite de 128 bytes do kernel).");
        }
        if (cfg.num_threads == 0) {
            cfg.num_threads = std::thread::hardware_concurrency();
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
