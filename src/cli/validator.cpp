#include "../../include/cli/validator.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <fstream>
#include <map>
#include <optional>
#include <print>
#include <ranges>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "../../include/cli/wordlist.hpp"
#include "../../include/crypto/bip39.hpp"
#include "../../include/crypto/cuckoo_filter.hpp"

using namespace cryptowords;

namespace {

std::expected<std::map<size_t, std::vector<std::string>>, std::string>
parse_constraint_map(std::string_view input) {
    std::map<size_t, std::vector<std::string>> result;
    for (const auto group : std::views::split(input, ',')) {
        std::string_view g(group);
        if (g.empty()) continue;
        auto pos_colon = g.find(':');
        if (pos_colon == std::string_view::npos)
            return std::unexpected(std::format("Faltando ':' em '{}'", g));
        size_t pos = 0;
        std::string_view pos_str = g.substr(0, pos_colon);
        auto [ptr, ec] = std::from_chars(pos_str.data(), pos_str.data() + pos_str.size(), pos);
        if (ec != std::errc() || ptr != pos_str.data() + pos_str.size())
            return std::unexpected(std::format("Posição inválida no mapa: '{}'", pos_str));
        auto words = g.substr(pos_colon + 1) | std::views::split('|') |
                     std::views::filter([](auto r) { return !r.empty(); }) |
                     std::views::transform([](auto r) { return std::string(r.begin(), r.end()); });
        for (auto&& w : words) result[pos].push_back(std::move(w));
    }
    return result;
}

std::optional<SearchStrategy> parse_strategy(std::string_view s) {
    if (s == "default")                                       return SearchStrategy::Default;
    if (s == "hamming" || s == "hamming-gradient" ||
        s == "hamming_gradient")                              return SearchStrategy::HammingGrad;
    if (s == "frequency")                                     return SearchStrategy::Frequency;
    if (s == "typo")                                          return SearchStrategy::Typo;
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// --checksum: aceita decimal (7), hex (0x7), binário com wildcards (0b*1*0).
// MSB-first na string.
// ---------------------------------------------------------------------------
std::expected<ChecksumPattern, std::string> parse_checksum_token(std::string_view tok,
                                                                  size_t checksum_bits) {
    ChecksumPattern pat{};

    auto is_binary = [&]() {
        return tok.find('*') != std::string_view::npos ||
               (tok.size() >= 2 && tok[0] == '0' && (tok[1] == 'b' || tok[1] == 'B'));
    };

    if (is_binary()) {
        std::string_view bits = tok;
        if (bits.size() >= 2 && bits[0] == '0' && (bits[1] == 'b' || bits[1] == 'B'))
            bits.remove_prefix(2);
        if (bits.size() != checksum_bits) {
            return std::unexpected(std::format(
                "--checksum: padrão binário '{}' tem {} bits, esperado {} (para {} palavras)",
                tok, bits.size(), checksum_bits, checksum_bits * 3));
        }
        for (size_t i = 0; i < bits.size(); ++i) {
            const char c = bits[i];
            const size_t pos = checksum_bits - 1 - i;
            if (c == '1')      { pat.mask |= (1u << pos); pat.value |= (1u << pos); }
            else if (c == '0') { pat.mask |= (1u << pos); }
            else if (c == '*') { /* wildcard */ }
            else {
                return std::unexpected(std::format(
                    "--checksum: caractere inválido '{}' em '{}' (esperado 0/1/*)", c, tok));
            }
        }
        return pat;
    }

    int radix = 10;
    std::string_view digits = tok;
    if (tok.size() >= 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
        radix = 16;
        digits = tok.substr(2);
    }
    if (digits.empty())
        return std::unexpected(std::format("--checksum: valor vazio em '{}'", tok));
    uint32_t v = 0;
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), v, radix);
    if (ec != std::errc() || ptr != digits.data() + digits.size()) {
        return std::unexpected(std::format(
            "--checksum: valor inválido '{}' (esperado inteiro {} de {} bits)",
            tok, radix == 16 ? "hex" : "decimal", checksum_bits));
    }
    const uint32_t max_val = 1u << checksum_bits;
    if (v >= max_val) {
        return std::unexpected(std::format(
            "--checksum: valor '{}' ({}) excede o máximo de {} bits (0..{})",
            tok, v, checksum_bits, max_val - 1));
    }
    pat.mask  = static_cast<uint16_t>(max_val - 1);
    pat.value = static_cast<uint16_t>(v);
    return pat;
}

// Decodifica e valida um endereço, devolvendo os 20 bytes.
std::expected<Target160, std::string>
decode_address(const std::string& addr, CoinTarget coin) {
    Target160 t{};
    if (coin == CoinTarget::BTC) {
        if (!cryptowords::Bip39Deriver::decode_base58_btc_address(addr, t.data()))
            return std::unexpected(std::format("Endereço Bitcoin inválido: {}", addr));
    } else {
        if (!cryptowords::Bip39Deriver::decode_hex_eth_address(addr, t.data()))
            return std::unexpected(std::format("Endereço Ethereum inválido: {}", addr));
    }
    return t;
}

// Lê um arquivo de alvos (uma linha = um endereço). Ignora linhas vazias e
// comentários começando com '#'.
std::expected<std::vector<std::string>, std::string>
read_target_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open())
        return std::unexpected(std::format("Não foi possível abrir '{}'", path));

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        if (line[first] == '#') continue;
        const size_t last = line.find_last_not_of(" \t");
        lines.push_back(line.substr(first, last - first + 1));
    }
    return lines;
}

}  // namespace

std::expected<AppConfig, std::string> ConfigValidator::validate(const RawOptions& raw) {
    AppConfig cfg;

    cfg.list_gpus      = raw.list_gpus;
    cfg.profile_gpu    = raw.profile_gpu;
    cfg.gpu_platform   = raw.gpu_platform;
    cfg.gpu_device     = raw.gpu_device;
    cfg.gpu_batch      = raw.gpu_batch;
    cfg.probe_hardware = raw.probe_hardware;
    cfg.pin_cores      = raw.pin_cores;
    cfg.num_threads    = raw.num_threads;
    cfg.quiet          = raw.quiet;
    cfg.resume_strict  = raw.resume_strict;

    if (raw.list_gpus || raw.probe_hardware) return cfg;

    size_t raw_size = raw.size;
    std::string raw_lang = raw.lang;
    std::string norm_lang = WordlistLoader::normalize_lang(raw_lang);

    cfg.language      = norm_lang;
    cfg.coin          = raw.coin;
    cfg.passphrase    = raw.passphrase;
    cfg.num_threads   = raw.num_threads;
    cfg.pbkdf2_rounds = raw.pbkdf2_rounds;
    cfg.use_gpu       = raw.use_gpu;
    cfg.use_cpu       = raw.use_cpu;
    cfg.use_hybrid    = raw.use_hybrid;
    if (cfg.use_hybrid) cfg.use_gpu = true;
    cfg.only_valids   = !raw.invalid_too;
    cfg.distinct      = raw.distinct;
    cfg.max_distance  = raw.max_distance;
    cfg.prog_mode     = (raw.prog == "num") ? ProgressMode::Num : ProgressMode::Word;
    cfg.save_path     = raw.save_path;
    cfg.load_path     = raw.load_path;
    cfg.save_interval_sec = raw.save_interval_sec;

    if (!cfg.save_path.empty() && cfg.save_interval_sec < 0)
        return std::unexpected("--save-interval deve ser >= 0.");

    // ---- Estratégias ----
    {
        std::vector<std::string> tokens;
        for (const auto& item : raw.strategies) {
            for (const auto part : std::views::split(item, '+')) {
                std::string s(part.begin(), part.end());
                while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
                while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
                if (!s.empty()) tokens.push_back(std::move(s));
            }
        }
        if (tokens.empty()) tokens.push_back("default");

        SearchStrategy mask = SearchStrategy::None;
        for (auto& s : tokens) {
            std::ranges::transform(s, s.begin(), [](unsigned char c) { return std::tolower(c); });
            auto parsed = parse_strategy(s);
            if (!parsed)
                return std::unexpected(std::format(
                    "Estratégia inválida: '{}'. Opções: default, hamming, frequency, typo", s));
            mask |= *parsed;
        }
        cfg.strategy_mask = (mask == SearchStrategy::None) ? SearchStrategy::Default : mask;
    }

    if (cfg.max_distance < 1 || cfg.max_distance > 3)
        return std::unexpected(std::format(
            "Valor inválido para --max-distance: {}. Intervalo: 1-3.", cfg.max_distance));

    // ---- Wordlist + índices ----
    cfg.mnemonics.resize(raw_size, AppConfig::UNKNOWN_WORD);
    cfg.n_unknowns = raw_size;

    auto wl_res = WordlistLoader::load(raw_lang);
    if (!wl_res) return std::unexpected(wl_res.error());
    cfg.wordlist = std::move(wl_res.value());

    std::unordered_map<std::string, uint16_t> word_to_id = WordlistLoader::build_index(cfg.wordlist);
    if (norm_lang == "japanese") cfg.separator = "\xE3\x80\x80";

    // ---- --allow ----
    std::map<size_t, std::vector<std::string>> raw_allow;
    if (!raw.allow.empty()) {
        auto allow_res = parse_constraint_map(raw.allow);
        if (!allow_res) return std::unexpected(allow_res.error());
        raw_allow = std::move(*allow_res);
    }

    // ---- Mnemônico base ----
    if (!raw.mnemonics.empty()) {
        std::string cleaned = raw.mnemonics;
        const std::string id_space = "\xE3\x80\x80";
        size_t p = 0;
        while ((p = cleaned.find(id_space, p)) != std::string::npos) {
            cleaned.replace(p, id_space.length(), " ");
            p += 1;
        }
        for (char& c : cleaned) if (c == '\t' || c == '\n' || c == '\r') c = ' ';

        auto words_view = cleaned | std::views::split(' ') |
                          std::views::filter([](auto r) { return !r.empty(); }) |
                          std::views::transform([](auto r) {
                              return std::string(r.begin(), r.end());
                          });
        std::vector<std::string> temp;
        for (auto&& w : words_view) temp.push_back(std::move(w));

        if (temp.size() != raw_size) {
            const size_t sz = temp.size();
            if (raw_size == 12 && (sz == 15 || sz == 18 || sz == 21 || sz == 24)) {
                raw_size = sz;
                cfg.mnemonics.resize(raw_size, AppConfig::UNKNOWN_WORD);
                cfg.n_unknowns = raw_size;
            } else {
                return std::unexpected(std::format(
                    "Tamanho incorreto. --size é {}, mas você forneceu {} palavras.",
                    raw_size, temp.size()));
            }
        }

        for (size_t i = 0; i < temp.size(); ++i) {
            const auto& w = temp[i];
            if (w == "?") continue;
            auto it = word_to_id.find(w);
            if (it == word_to_id.end()) it = word_to_id.find(WordlistLoader::to_nfc(w));
            if (it == word_to_id.end())
                return std::unexpected(std::format(
                    "A palavra '{}' não existe na wordlist '{}'.", w, raw_lang));
            cfg.mnemonics[i] = it->second;
            cfg.n_unknowns--;
        }
    } else if (raw.target.empty() && raw.target_file.empty()) {
        return std::unexpected("Forneça '--mnemonics' ou '--target'/'--target-file'.");
    }

    // Conta incógnitas originais (antes de --allow).
    {
        size_t n = 0;
        for (const auto& w : cfg.mnemonics)
            if (std::holds_alternative<uint16_t>(w) &&
                std::get<uint16_t>(w) == AppConfig::UNKNOWN_WORD) ++n;
        cfg.raw_unknowns = n;
    }

    // ---- --random / --seed ----
    if (raw.random || raw.random_seed != 0) {
        cfg.random = true;
        cfg.random_seed = (raw.random_seed != 0) ? raw.random_seed : DEFAULT_RANDOM_SEED;
    }

    // ---- --checksum ----
    if (!raw.checksum.empty()) {
        const size_t checksum_bits = raw_size / 3;
        cfg.has_checksum_filter = true;
        cfg.checksum_repr = raw.checksum;

        for (const auto part : std::views::split(raw.checksum, ',')) {
            std::string_view sv(part);
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
            while (!sv.empty() && (sv.back()  == ' ' || sv.back()  == '\t')) sv.remove_suffix(1);
            if (sv.empty())
                return std::unexpected(std::format("--checksum: padrão vazio em '{}'",
                                                   raw.checksum));
            auto parsed = parse_checksum_token(sv, checksum_bits);
            if (!parsed) return std::unexpected(parsed.error());
            cfg.checksum_patterns.push_back(*parsed);
        }
    }

    // ---- --allow (overrides por posição) ----
    for (const auto& [pos, words] : raw_allow) {
        if (pos >= raw_size)
            return std::unexpected(std::format(
                "Posição {} do --allow é maior ou igual ao tamanho ({}).", pos, raw_size));
        if (words.empty()) continue;
        if (std::holds_alternative<uint16_t>(cfg.mnemonics[pos]) &&
            std::get<uint16_t>(cfg.mnemonics[pos]) != AppConfig::UNKNOWN_WORD) {
            return std::unexpected(std::format(
                "A posição {} já está preenchida pela mnemonic base.", pos));
        }
        std::vector<uint16_t> translated;
        translated.reserve(words.size());
        for (const auto& w : words) {
            auto it = word_to_id.find(w);
            if (it == word_to_id.end()) it = word_to_id.find(WordlistLoader::to_nfc(w));
            if (it == word_to_id.end())
                return std::unexpected(std::format("Palavra permitida '{}' não existe.", w));
            translated.push_back(it->second);
        }
        std::ranges::sort(translated);
        auto [first, last] = std::ranges::unique(translated);
        translated.erase(first, last);
        if (translated.size() == 1) {
            cfg.mnemonics[pos] = translated.front();
            cfg.n_unknowns--;
        } else {
            cfg.mnemonics[pos] = std::move(translated);
        }
    }

    // ---- --allow-all ----
    if (!raw.allow_all.empty()) {
        std::vector<uint16_t> ids;
        for (const auto part : std::views::split(raw.allow_all, '|')) {
            std::string_view sv(part);
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
            while (!sv.empty() && (sv.back()  == ' ' || sv.back()  == '\t')) sv.remove_suffix(1);
            if (sv.empty()) continue;
            std::string w(sv);
            auto it = word_to_id.find(w);
            if (it == word_to_id.end()) it = word_to_id.find(WordlistLoader::to_nfc(w));
            if (it == word_to_id.end())
                return std::unexpected(std::format(
                    "Palavra de --allow-all '{}' não existe na wordlist '{}'.", w, raw_lang));
            ids.push_back(it->second);
        }
        if (!ids.empty()) {
            std::ranges::sort(ids);
            auto [first, last] = std::ranges::unique(ids);
            ids.erase(first, last);
            for (size_t i = 0; i < raw_size; ++i) {
                if (std::holds_alternative<uint16_t>(cfg.mnemonics[i]) &&
                    std::get<uint16_t>(cfg.mnemonics[i]) == AppConfig::UNKNOWN_WORD) {
                    if (ids.size() == 1) {
                        cfg.mnemonics[i] = ids.front();
                        cfg.n_unknowns--;
                    } else {
                        cfg.mnemonics[i] = ids;
                    }
                }
            }
        }
    }

    // ---- --repeat ----
    for (const auto& spec : raw.repeat) {
        auto colon = spec.rfind(':');
        if (colon == std::string::npos)
            return std::unexpected(std::format(
                "--repeat: formato inválido '{}'. Esperado 'palavra:N'.", spec));
        std::string w = spec.substr(0, colon);
        std::string n_str = spec.substr(colon + 1);
        while (!w.empty() && (w.front() == ' ' || w.front() == '\t')) w.erase(w.begin());
        while (!w.empty() && (w.back()  == ' ' || w.back()  == '\t')) w.pop_back();
        if (w.empty())
            return std::unexpected(std::format("--repeat: palavra vazia em '{}'.", spec));
        int n = 0;
        try { n = std::stoi(n_str); }
        catch (...) {
            return std::unexpected(std::format(
                "--repeat: contagem inválida '{}' em '{}'.", n_str, spec));
        }
        if (n < 1 || n > 24)
            return std::unexpected(std::format("--repeat: N deve estar em [1, 24] (recebi {}).", n));
        auto it = word_to_id.find(w);
        if (it == word_to_id.end()) it = word_to_id.find(WordlistLoader::to_nfc(w));
        if (it == word_to_id.end())
            return std::unexpected(std::format(
                "--repeat: palavra '{}' não existe na wordlist '{}'.", w, raw_lang));
        cfg.repeat_ids.emplace_back(it->second, static_cast<uint8_t>(n));
    }

    // ---- Alvos (target / target-file) ----
    {
        std::vector<std::string> raw_addrs;
        if (!raw.target.empty()) raw_addrs.push_back(raw.target);

        if (!raw.target_file.empty()) {
            auto file_res = read_target_file(raw.target_file);
            if (!file_res) return std::unexpected(file_res.error());
            for (auto& line : *file_res) raw_addrs.push_back(std::move(line));
        }

        if (!raw_addrs.empty()) {
            std::unordered_set<std::string> seen;  // dedup textual
            for (const auto& addr : raw_addrs) {
                if (!seen.insert(addr).second) continue;
                auto decoded = decode_address(addr, cfg.coin);
                if (!decoded) return std::unexpected(decoded.error());
                cfg.targets.push_back(*decoded);
            }
            cfg.target = raw_addrs.front();
        }

        // Cuckoo só vale a pena acima de alguns alvos; abaixo disso a
        // comparação direta é mais rápida e sem falso positivo.
        if (cfg.targets.size() >= 8) {
            auto cuckoo = std::make_shared<CuckooFilter>(cfg.targets.size());
            for (const auto& t : cfg.targets)
                cuckoo->insert(CuckooFilter::hash_key(t));
            cfg.target_cuckoo = std::move(cuckoo);
        }
    }

    // ---- Consistência geral ----
    bool has_ambiguity = false;
    for (const auto& w : cfg.mnemonics) {
        if (std::holds_alternative<std::vector<uint16_t>>(w)) {
            if (std::get<std::vector<uint16_t>>(w).size() > 1) { has_ambiguity = true; break; }
        } else if (std::holds_alternative<uint16_t>(w)) {
            if (std::get<uint16_t>(w) == AppConfig::UNKNOWN_WORD) {
                has_ambiguity = true; break;
            }
        }
    }
    if (has_ambiguity && cfg.targets.empty()) {
        return std::unexpected(
            "O parâmetro '--target' (ou '--target-file') é obrigatório quando há "
            "posições desconhecidas ou com múltiplas opções.");
    }
    if (cfg.passphrase.size() > 99)
        return std::unexpected("Passphrase suporta no máximo 99 caracteres.");

    // ---- GPU: rounds fixos, ajuste de threads ----
    if (cfg.use_gpu) {
        if (cfg.pbkdf2_rounds != 2048)
            return std::unexpected(std::format(
                "Aceleração por GPU exige '--rounds 2048', mas {} foi solicitado.",
                cfg.pbkdf2_rounds));
        if (cfg.use_hybrid) {
            cfg.num_threads = raw.num_threads;
        } else {
            if (raw.num_threads > 1) {
                cfg.use_hybrid = true;
                cfg.num_threads = raw.num_threads;
            } else if (raw.num_threads == 1) {
                cfg.num_threads = 1;
            } else {
                cfg.num_threads = 0;
            }
        }
    } else {
        cfg.num_threads = raw.num_threads;
    }

    return cfg;
}
