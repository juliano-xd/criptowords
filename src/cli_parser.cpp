#include "../include/cli_parser.hpp"
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <flat_map>
#include <format>
#include <fstream>
#include <map>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <variant>

AppConfig config;

// ============================================================================
// FUNÇÕES AUXILIARES INTERNAS
// ============================================================================

static std::expected<uint64_t, std::string> parse_uint64(std::string_view s) {
    uint64_t val = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);

    if (ec != std::errc() || ptr != s.data() + s.size()) {
        return std::unexpected(std::format("Valor numérico inválido: '{}'", s));
    }
    return val;
}

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

static std::expected<std::vector<std::string>, std::string>
load_wordlist(const std::string& lang) {
    std::string path = std::format("../wordlist/{}.txt", lang);
    std::ifstream f(path);

    if (!f.is_open()) {
        return std::unexpected(std::format("Arquivo de wordlist não encontrado: {}", path));
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    if (lines.empty()) {
        return std::unexpected(std::format("Wordlist vazia ou inválida: {}", path));
    }

    return lines;
}

// ============================================================================
// IMPLEMENTAÇÃO PRINCIPAL DO PARSER
// ============================================================================

std::expected<AppConfig, std::string> CLIParser::parse_and_validate(int argc, char* argv[]) {
    AppConfig cfg;

    // Passo 1: Verifica Help Imediatamente (antes de processar qualquer coisa)
    if (argc < 2) {
        cfg.is_help_request = true;
        return cfg;
    }

    std::span<char*> args(argv, argc);
    auto cli_args = args.subspan(1);

    // Variáveis temporárias para a varredura bruta
    std::string raw_mnemonics;
    std::map<size_t, std::vector<std::string>> raw_allow;
    size_t raw_size = 12;        // Padrão
    std::string raw_lang = "en"; // Padrão

    // ========================================================================
    // VARREDURA DE EXTRAÇÃO (Sem regras de negócio, apenas coleta o texto)
    // ========================================================================
    for (auto it = cli_args.begin(); it != cli_args.end(); ++it) {
        std::string_view arg = *it;

        if (arg == "--help" || arg == "-h") {
            cfg.is_help_request = true;
            return cfg;
        }
        if (arg == "--gpu") {
            cfg.use_gpu = true;
            continue;
        }
        if (arg == "--invalid_too") {
            cfg.only_valids = false;
            continue;
        }
        if (!arg.starts_with("--"))
            return std::unexpected(std::format("Argumento inválido: '{}'", arg));

        std::string_view key = arg.substr(2);
        std::string_view value;

        if (auto eq_pos = key.find('='); eq_pos != std::string_view::npos) {
            value = key.substr(eq_pos + 1);
            key = key.substr(0, eq_pos);
        } else {
            if (std::next(it) == cli_args.end())
                return std::unexpected(std::format("Faltando valor para --{}", key));
            value = *++it;
        }

        if (key == "mnemonics" || key == "mnemonic")
            raw_mnemonics = value;
        else if (key == "size") {
            auto res = parse_uint64(value);
            if (!res)
                return std::unexpected(res.error());
            if (*res < 12 || *res > 24 || *res % 3 != 0)
                return std::unexpected("O --size deve ser 12, 15, 18, 21 ou 24.");
            raw_size = *res;
        } else if (key == "lang")
            raw_lang = value;
        else if (key == "allow") {
            auto res = parse_constraint_map(value);
            if (!res)
                return std::unexpected(res.error());
            for (auto& [k, v] : *res)
                raw_allow[k].append_range(std::move(v));
        } else if (key == "target")
            cfg.target = value;
        else if (key == "passphrase")
            cfg.passphrase = value;
        else if (key == "coin") {
            std::string temp_coin = std::string(value);
            std::ranges::transform(temp_coin, temp_coin.begin(), ::tolower);

            if (temp_coin == "eth") {
                cfg.coin = CoinTarget::ETH;
            } else if (temp_coin == "btc") {
                cfg.coin = CoinTarget::BTC;
            } else {
                return std::unexpected(
                    std::format("Moeda não suportada: '{}'. Use 'btc' ou 'eth'.", value));
            }
        } else if (key == "threads") {
            auto res = parse_uint64(value);
            if (!res)
                return std::unexpected(res.error());
            cfg.num_threads = *res;
        } else if (key == "rounds") {
            auto res = parse_uint64(value);
            if (!res)
                return std::unexpected(res.error());
            cfg.pbkdf2_rounds = *res;
        }
    }

    // ========================================================================
    // APLICAÇÃO DA SEQUÊNCIA LÓGICA DO USUÁRIO
    // ========================================================================

    // Passo 2: Inicia o vetor com o tamanho correto e preenche com UNKNOWN_WORD
    cfg.mnemonics.resize(raw_size, AppConfig::UNKNOWN_WORD);
    cfg.unknows = raw_size; // Inicialmente, tudo é desconhecido

    // Passo 3: Carrega a wordlist usando o idioma (fornecido ou 'en' padrão)
    auto wl_res = load_wordlist(raw_lang);
    if (!wl_res)
        return std::unexpected(wl_res.error());
    cfg.wordlist = std::move(wl_res.value());

    // Passo 4: Verifica o --mnemonics e preenche as posições base
    if (!raw_mnemonics.empty()) {
        auto words_view =
            raw_mnemonics | std::views::split(' ') |
            std::views::filter([](auto r) { return !r.empty(); }) |
            std::views::transform([](auto r) { return std::string(r.begin(), r.end()); });

        std::vector<std::string> temp_mnemonic;
        temp_mnemonic.append_range(words_view);

        if (temp_mnemonic.size() > raw_size) {
            return std::unexpected(
                std::format("Tamanho incorreto. --size é {}, mas você forneceu {} palavras.",
                            raw_size, temp_mnemonic.size()));
        }

        // Valida contra a wordlist e preenche a matriz
        for (size_t i = 0; i < temp_mnemonic.size(); ++i) {
            const auto& w = temp_mnemonic[i];
            if (w != "?") {
                if (std::find(cfg.wordlist.begin(), cfg.wordlist.end(), w) == cfg.wordlist.end()) {
                    return std::unexpected(
                        std::format("A palavra '{}' não existe na wordlist '{}'.", w, raw_lang));
                }
                cfg.mnemonics[i] = static_cast<uint16_t>(std::distance(cfg.wordlist.begin(), std::find(cfg.wordlist.begin(), cfg.wordlist.end(), w))); // Guarda o ID
                cfg.unknows--;                      // Uma incógnita a menos!
            }
        }
    } else if (cfg.target.empty()) {
        return std::unexpected("Forneça um '--mnemonics' ou um '--target' para iniciar a busca.");
    }

    // Passo 5: Verifica os --allow
    for (const auto& [pos, words] : raw_allow) {
        if (pos >= raw_size) {
            return std::unexpected(
                std::format("Posição {} do --allow é maior que o tamanho ({}).", pos, raw_size));
        }
        if (words.empty())
            continue;

        // Se a posição já for uma palavra fixa base (vinda do --mnemonics), gerar erro
        if (std::holds_alternative<uint16_t>(cfg.mnemonics[pos]) &&
            std::get<uint16_t>(cfg.mnemonics[pos]) != AppConfig::UNKNOWN_WORD) {
            return std::unexpected(std::format(
                "A posição {} já está preenchida pela mnemonic base. Não use --allow nela.", pos));
        }

        std::vector<uint16_t> translated_allows;
        translated_allows.reserve(words.size());

        for (const auto& w : words) {
            if (std::find(cfg.wordlist.begin(), cfg.wordlist.end(), w) == cfg.wordlist.end()) {
                return std::unexpected(std::format("A palavra permitida '{}' não existe.", w));
            }
            translated_allows.push_back(static_cast<uint16_t>(std::distance(cfg.wordlist.begin(), std::find(cfg.wordlist.begin(), cfg.wordlist.end(), w))));
        }

        if (translated_allows.size() == 1) {
            // É a mesma coisa que deixar a palavra fixa
            cfg.mnemonics[pos] = translated_allows.front();
        } else {
            // Insere o vetor de opções
            cfg.mnemonics[pos] = std::move(translated_allows);
        }

        cfg.unknows--; // Independentemente de ser fixo ou allow, não é mais um "100% desconhecido"
    }

    if (cfg.unknows > 0 && cfg.target.empty()) {
        return std::unexpected(
            "O parâmetro '--target' é obrigatório quando há posições desconhecidas.");
    }

    if (cfg.num_threads == 0) {
        cfg.num_threads = std::max(1u, std::thread::hardware_concurrency() / 2);
    }

    return cfg;
}

std::string_view CLIParser::get_help_text() {
    return R"(
╔══════════════════════════════════════════════════════════════════════╗
║                        CRIPTOWORDS v2.0                              ║
║                   BIP39 Mnemonic Brute Force                         ║
╚══════════════════════════════════════════════════════════════════════╝

[=] Uso: criptowords [opções]

[=] Opções Obrigatórias:
    (Nenhuma estritamente obrigatória, o padrão assume inglês e tamanho 12)

[=] Modos de Operação (Escolha 1 ou ambos):
    --mnemonics "..."           Mnemonic com '?' para posições desconhecidas
    --target <endereço>         Endereço final (BTC/ETH) alvo da busca

[=] Opções de Restrição (Opcional):
    --allow "pos:p1|p2|..."     Palavras permitidas em posições desconhecidas

[=] Opções de Configuração (Opcional):
    --lang <id>                 Idioma da wordlist (Ex: en, pt, es) (padrão: en)
    --coin <btc|eth>            Moeda alvo da busca (padrão: btc)
    --size <n>                  Tamanho da mnemonic: 12, 15, 18, 21 ou 24 (padrão: 12)
    --passphrase <string>       BIP39 passphrase (padrão: vazio)
    --threads <n>               Número de threads (padrão: metade da CPU)
    --rounds <n>                PBKDF2 rounds (padrão: 2048)
    --gpu                       Habilita aceleração via GPU
    --invalid_too               Habilita a busca por chaves invalidas do padrão BIP39

[=] Exemplos:
    1. Derivação simples (Sem '?'):
       criptowords --mnemonics "abandon abandon ... about"

    2. Busca com tamanho customizado (15 palavras) e preenchimento automático:
       criptowords --size 15 --mnemonics "abandon ? abandon" --target 1MrkVr...
)";
}
