#pragma once
#include <cstdint>
#include <expected>
#include <string>
#include <unordered_map>
#include <vector>

class WordlistLoader {
public:
    static std::string normalize_lang(std::string_view lang);

    static std::expected<std::vector<std::string>, std::string> load(const std::string& lang);

    static std::unordered_map<std::string, uint16_t>
    build_index(const std::vector<std::string>& words);

    static std::string to_nfc(std::string_view w);
};
