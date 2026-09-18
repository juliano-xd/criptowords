#pragma once

#include <string>
#include <string_view>
#include <format>
#include <algorithm>
#include <print>
#include <cstdint>

namespace cryptowords::ui {

inline constexpr size_t DEFAULT_INNER_WIDTH = 80;

inline std::string format_num(double val) {
    if (val < 0.0) return "0";
    if (val >= 1e19) {
        return std::format("{:.3e}", val);
    }
    uint64_t n = static_cast<uint64_t>(val);
    std::string s = std::to_string(n);
    std::string res;
    int count = 0;
    for (int i = static_cast<int>(s.size()) - 1; i >= 0; --i) {
        res += s[i];
        if (++count == 3 && i > 0) {
            res += '.';
            count = 0;
        }
    }
    std::reverse(res.begin(), res.end());
    return res;
}

inline size_t visible_length(std::string_view s) {
    size_t len = 0;
    bool in_escape = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\033') {
            in_escape = true;
        } else if (in_escape) {
            if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) in_escape = false;
        } else {
            // Conta codepoints UTF-8 (ignora bytes de continuação 10xxxxxx)
            unsigned char c = static_cast<unsigned char>(s[i]);
            if ((c & 0xC0) != 0x80) {
                len++;
            }
        }
    }
    return len;
}

inline void append_dashes(std::string& s, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        s += "─";
    }
}

inline void print_box_top(std::string_view title = "", size_t inner_width = DEFAULT_INNER_WIDTH) {
    std::string line = "╭───";
    if (!title.empty()) {
        line += " ";
        line += title;
        line += " ";
        size_t vis_title = visible_length(title);
        if (inner_width > vis_title + 1) {
            append_dashes(line, inner_width - 1 - vis_title);
        }
    } else {
        append_dashes(line, inner_width);
    }
    line += "╮";
    std::println("{}", line);
}

inline void print_box_line(std::string_view content, size_t inner_width = DEFAULT_INNER_WIDTH) {
    size_t vis_len = visible_length(content);
    std::string line = "│  ";
    line += content;
    if (vis_len < inner_width) {
        line.append(inner_width - vis_len, ' ');
    }
    line += "  │";
    std::println("{}", line);
}

inline void print_box_separator(size_t inner_width = DEFAULT_INNER_WIDTH) {
    std::string line = "├";
    append_dashes(line, inner_width + 4);
    line += "┤";
    std::println("{}", line);
}

inline void print_box_bottom(size_t inner_width = DEFAULT_INNER_WIDTH) {
    std::string line = "╰";
    append_dashes(line, inner_width + 4);
    line += "╯";
    std::println("{}", line);
}

inline std::string format_speed(double keys_per_sec) {
    if (keys_per_sec >= 1e6) {
        return std::format("{:.2f} Mkeys/s", keys_per_sec / 1e6);
    } else if (keys_per_sec >= 1e3) {
        return std::format("{:.2f} Kkeys/s", keys_per_sec / 1e3);
    } else {
        return std::format("{:.0f} keys/s", keys_per_sec);
    }
}

inline std::string format_eta(double seconds) {
    if (seconds < 0 || seconds > 86400 * 365) return "--:--";
    int total = static_cast<int>(seconds);
    int s = total % 60;
    int m = (total / 60) % 60;
    int h = total / 3600;
    if (h > 0) {
        return std::format("{:02d}h{:02d}m", h, m);
    }
    return std::format("{:02d}:{:02d}", m, s);
}

} // namespace cryptowords::ui
