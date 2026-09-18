#include "../../include/cli/wordlist.hpp"

#include <fstream>
#include <format>
#include <filesystem>
#include <array>
#include <cctype>

std::string WordlistLoader::normalize_lang(std::string_view lang) {
    std::string l;
    l.reserve(lang.size());
    for (char c : lang) l += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (l == "en" || l == "english" || l == "en_us" || l == "en-us") return "en";
    if (l == "pt" || l == "portuguese" || l == "portugues" || l == "pt_br" || l == "pt-br") return "portuguese";
    if (l == "es" || l == "spanish" || l == "espanol" || l == "español") return "spanish";
    if (l == "fr" || l == "french" || l == "francais" || l == "français" || l == "frances") return "french";
    if (l == "it" || l == "italian" || l == "italiano") return "italian";
    if (l == "ja" || l == "japanese" || l == "jp" || l == "japones") return "japanese";
    if (l == "ko" || l == "korean" || l == "kr" || l == "coreano") return "korean";
    if (l == "cs" || l == "cz" || l == "czech" || l == "checo") return "czech";
    if (l == "zh" || l == "zh_cn" || l == "zh-cn" || l == "chinese" || l == "chinese_simplified" || l == "zh_hans" || l == "zh-hans") return "chinese_simplified";
    if (l == "zh_tw" || l == "zh-tw" || l == "chinese_traditional" || l == "zh_hant" || l == "zh-hant") return "chinese_traditional";

    return l;
}

std::expected<std::vector<std::string>, std::string>
WordlistLoader::load(const std::string& lang) {
    std::string norm_lang = normalize_lang(lang);
    const std::array<std::string, 10> candidate_paths = {
        std::format("wordlist/{}.txt", norm_lang),
        std::format("../wordlist/{}.txt", norm_lang),
        std::format("../../wordlist/{}.txt", norm_lang),
        std::format("/usr/local/share/criptowords/wordlist/{}.txt", norm_lang),
        std::format("/usr/share/criptowords/wordlist/{}.txt", norm_lang),
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
        return std::unexpected(std::format("Arquivo de wordlist não encontrado para o idioma '{}' (procurado em wordlist/{}.txt)", lang, norm_lang));
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

static std::vector<uint32_t> utf8_to_codepoints(std::string_view s) {
    std::vector<uint32_t> cps;
    for (size_t i = 0; i < s.size(); ) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            cps.push_back(c);
            i += 1;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < s.size()) {
            cps.push_back(((c & 0x1F) << 6) | (static_cast<unsigned char>(s[i+1]) & 0x3F));
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < s.size()) {
            cps.push_back(((c & 0x0F) << 12) | ((static_cast<unsigned char>(s[i+1]) & 0x3F) << 6) | (static_cast<unsigned char>(s[i+2]) & 0x3F));
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < s.size()) {
            cps.push_back(((c & 0x07) << 18) | ((static_cast<unsigned char>(s[i+1]) & 0x3F) << 12) | ((static_cast<unsigned char>(s[i+2]) & 0x3F) << 6) | (static_cast<unsigned char>(s[i+3]) & 0x3F));
            i += 4;
        } else {
            cps.push_back(c);
            i += 1;
        }
    }
    return cps;
}

static std::string codepoints_to_utf8(const std::vector<uint32_t>& cps) {
    std::string s;
    for (uint32_t cp : cps) {
        if (cp < 0x80) {
            s.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            s.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            s.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            s.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return s;
}

std::string WordlistLoader::to_nfc(std::string_view w) {
    auto cps = utf8_to_codepoints(w);
    std::vector<uint32_t> res;
    res.reserve(cps.size());

    constexpr uint32_t SBase = 0xAC00, LBase = 0x1100, VBase = 0x1161, TBase = 0x11A7;
    constexpr uint32_t NCount = 588, TCount = 28;

    for (size_t i = 0; i < cps.size(); ) {
        // Hangul Jamo composition
        if (cps[i] >= LBase && cps[i] < LBase + 19 && i + 1 < cps.size() && cps[i+1] >= VBase && cps[i+1] < VBase + 21) {
            uint32_t LIndex = cps[i] - LBase;
            uint32_t VIndex = cps[i+1] - VBase;
            uint32_t TIndex = 0;
            if (i + 2 < cps.size() && cps[i+2] > TBase && cps[i+2] <= TBase + 27) {
                TIndex = cps[i+2] - TBase;
                i += 3;
            } else {
                i += 2;
            }
            res.push_back(SBase + LIndex * NCount + VIndex * TCount + TIndex);
            continue;
        }

        // Combining mark composition
        if (i + 1 < cps.size()) {
            uint32_t base = cps[i], mark = cps[i+1];
            uint32_t composed = 0;
            if (mark == 0x301) { // Acute
                if (base == 0x61) composed = 0xe1; // á
                else if (base == 0x65) composed = 0xe9; // é
                else if (base == 0x69) composed = 0xed; // í
                else if (base == 0x6f) composed = 0xf3; // ó
                else if (base == 0x75) composed = 0xfa; // ú
                else if (base == 0x79) composed = 0xfd; // ý
            } else if (mark == 0x300) { // Grave
                if (base == 0x61) composed = 0xe0; // à
                else if (base == 0x65) composed = 0xe8; // è
                else if (base == 0x69) composed = 0xec; // ì
                else if (base == 0x6f) composed = 0xf2; // ò
                else if (base == 0x75) composed = 0xf9; // ù
            } else if (mark == 0x302) { // Circumflex
                if (base == 0x61) composed = 0xe2; // â
                else if (base == 0x65) composed = 0xea; // ê
                else if (base == 0x69) composed = 0xee; // î
                else if (base == 0x6f) composed = 0xf4; // ô
                else if (base == 0x75) composed = 0xfb; // û
            } else if (mark == 0x303) { // Tilde
                if (base == 0x61) composed = 0xe3; // ã
                else if (base == 0x6f) composed = 0xf5; // õ
                else if (base == 0x6e) composed = 0xf1; // ñ
            } else if (mark == 0x308) { // Diaeresis / Trema
                if (base == 0x65) composed = 0xeb; // ë
                else if (base == 0x69) composed = 0xef; // ï
                else if (base == 0x75) composed = 0xfc; // ü
                else if (base == 0x79) composed = 0xff; // ÿ
            } else if (mark == 0x327) { // Cedilla
                if (base == 0x63) composed = 0xe7; // ç
            } else if (mark == 0x30c) { // Caron / Háček (Czech)
                if (base == 0x63) composed = 0x10d; // č
                else if (base == 0x64) composed = 0x10f; // ď
                else if (base == 0x65) composed = 0x11b; // ě
                else if (base == 0x6e) composed = 0x148; // ň
                else if (base == 0x72) composed = 0x159; // ř
                else if (base == 0x73) composed = 0x161; // š
                else if (base == 0x74) composed = 0x165; // ť
                else if (base == 0x7a) composed = 0x17e; // ž
            } else if (mark == 0x30a) { // Ring above
                if (base == 0x75) composed = 0x16f; // ů
            }
            else if (mark == 0x3099) {
                switch (base) {
                    case 0x304b: composed = 0x304c; break; // が
                    case 0x304d: composed = 0x304e; break; // ぎ
                    case 0x304f: composed = 0x3050; break; // ぐ
                    case 0x3051: composed = 0x3052; break; // げ
                    case 0x3053: composed = 0x3054; break; // ご
                    case 0x3055: composed = 0x3056; break; // ざ
                    case 0x3057: composed = 0x3058; break; // じ
                    case 0x3059: composed = 0x305a; break; // ず
                    case 0x305b: composed = 0x305c; break; // ぜ
                    case 0x305d: composed = 0x305e; break; // ぞ
                    case 0x305f: composed = 0x3060; break; // だ
                    case 0x3064: composed = 0x3065; break; // づ
                    case 0x3066: composed = 0x3067; break; // で
                    case 0x3068: composed = 0x3069; break; // ど
                    case 0x306f: composed = 0x3070; break; // ば
                    case 0x3072: composed = 0x3073; break; // び
                    case 0x3075: composed = 0x3076; break; // ぶ
                    case 0x3078: composed = 0x3079; break; // べ
                    case 0x307b: composed = 0x307c; break; // ぼ
                }
            } else if (mark == 0x309a) {
                switch (base) {
                    case 0x306f: composed = 0x3071; break; // ぱ
                    case 0x3072: composed = 0x3074; break; // ぴ
                    case 0x3075: composed = 0x3077; break; // ぷ
                    case 0x3078: composed = 0x307a; break; // ぺ
                    case 0x307b: composed = 0x307d; break; // ぽ
                }
            }

            if (composed != 0) {
                res.push_back(composed);
                i += 2;
                continue;
            }
        }

        res.push_back(cps[i]);
        i += 1;
    }

    return codepoints_to_utf8(res);
}

std::unordered_map<std::string, uint16_t>
WordlistLoader::build_index(const std::vector<std::string>& words) {
    std::unordered_map<std::string, uint16_t> idx;
    idx.reserve(words.size() * 3);
    for (size_t i = 0; i < words.size(); ++i) {
        idx.emplace(words[i], static_cast<uint16_t>(i));
        std::string nfc = to_nfc(words[i]);
        if (nfc != words[i]) {
            idx.emplace(nfc, static_cast<uint16_t>(i));
        }
    }
    return idx;
}
