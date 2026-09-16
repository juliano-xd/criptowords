#include "../../include/cli/wordlist.hpp"

#include <fstream>
#include <format>
#include <filesystem>
#include <array>

std::expected<std::vector<std::string>, std::string>
WordlistLoader::load(const std::string& lang) {
    const std::array<std::string, 5> candidate_paths = {
        std::format("wordlist/{}.txt", lang),
        std::format("../wordlist/{}.txt", lang),
        std::format("../../wordlist/{}.txt", lang),
        std::format("/usr/local/share/criptowords/wordlist/{}.txt", lang),
        std::format("/usr/share/criptowords/wordlist/{}.txt", lang)
    };

    std::ifstream f;
    std::string found_path;
    for (const auto& path : candidate_paths) {
        f.open(path);
        if (f.is_open()) {
            found_path = path;
            break;
        }
    }

    if (!f.is_open()) {
        return std::unexpected(std::format("Arquivo de wordlist não encontrado para o idioma '{}' (procurado em wordlist/{}.txt)", lang, lang));
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(line);
    }

    if (lines.empty())
        return std::unexpected(std::format("Wordlist vazia ou inválida: {}", found_path));
    if (lines.size() != 2048)
        return std::unexpected(std::format(
            "A wordlist ({}) possui {} palavras, mas o protocolo BIP39 exige exatamente 2048.",
            found_path, lines.size()));
    return lines;
}

std::unordered_map<std::string, uint16_t>
WordlistLoader::build_index(const std::vector<std::string>& words) {
    std::unordered_map<std::string, uint16_t> idx;
    idx.reserve(words.size() * 2);
    for (size_t i = 0; i < words.size(); ++i)
        idx.emplace(words[i], static_cast<uint16_t>(i));
    return idx;
}
