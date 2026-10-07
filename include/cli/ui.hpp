#pragma once

#include <gmpxx.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
// #include "../math/UInt.hpp"
#pragma GCC diagnostic pop

namespace cryptowords::ui {

inline constexpr size_t DEFAULT_INNER_WIDTH = 80;

// Largura do terminal
inline size_t terminal_width() noexcept {
    struct winsize ws{};
    if (::ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    if (const char* env = std::getenv("COLUMNS")) {
        const int v = std::atoi(env);
        if (v > 0)
            return static_cast<size_t>(v);
    }
    return 120;
}

// Largura visual (ignora sequências ANSI, conta codepoints UTF-8)
inline size_t visible_length(std::string_view s) {
    size_t len = 0;
    bool in_escape = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\033') {
            in_escape = true;
        } else if (in_escape) {
            if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z'))
                in_escape = false;
        } else {
            const unsigned char c = static_cast<unsigned char>(s[i]);
            if ((c & 0xC0) != 0x80)
                ++len;
        }
    }
    return len;
}

// Formatação de números
inline std::string format_grouped_digits(std::string_view s) {
    std::string res;
    res.reserve(s.size() + s.size() / 3);
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

inline std::string format_num(double val) {
    if (std::isnan(val))
        return "nan";
    if (std::isinf(val))
        return val > 0 ? "∞" : "-∞";
    if (val < 0.0)
        return "0";
    if (val < 1e15)
        return format_grouped_digits(std::to_string(static_cast<uint64_t>(val)));
    if (val >= 1e30)
        return std::format("{:.3e}", val);
    return format_grouped_digits(std::format("{:.0f}", val));
}

// template <unsigned char N>
// inline std::string format_num(const UInt<N>& val) {
//     if (val.eqz())
//         return "0";
//     return format_grouped_digits(val.to_string());
// }

inline std::string format_num(const mpz_class& v) {
    if (v == 0)
        return "0";
    std::string s = v.get_str();
    if (s.size() > 42) {
        const std::string head = s.substr(0, 18);
        const std::string tail = s.substr(s.size() - 3);
        return format_grouped_digits(head) + " … " + tail + std::format(" ({} dígitos)", s.size());
    }
    return format_grouped_digits(s);
}

// Velocidade / tempo / probabilidade / viabilidade
inline std::string format_speed(double keys_per_sec) {
    if (keys_per_sec >= 1e9)
        return std::format("{:.2f} Gkeys/s", keys_per_sec / 1e9);
    if (keys_per_sec >= 1e6)
        return std::format("{:.2f} Mkeys/s", keys_per_sec / 1e6);
    if (keys_per_sec >= 1e3)
        return std::format("{:.2f} Kkeys/s", keys_per_sec / 1e3);
    return std::format("{:.0f} keys/s", keys_per_sec);
}

inline std::string format_eta(double seconds) {
    if (!std::isfinite(seconds) || seconds < 0)
        return "--:--";
    if (seconds < 3600.0) {
        const int t = static_cast<int>(seconds);
        return std::format("{:02d}:{:02d}", t / 60, t % 60);
    }
    if (seconds < 86400.0) {
        const int t = static_cast<int>(seconds);
        return std::format("{:02d}h{:02d}m", t / 3600, (t / 60) % 60);
    }
    constexpr double DAY = 86400.0;
    constexpr double YEAR = 365.25 * DAY;
    if (seconds < YEAR)
        return std::format("{:.1f}d", seconds / DAY);
    const double years = seconds / YEAR;
    if (years >= 1e18)
        return std::format("{:.3e} anos", years);
    if (years >= 1e15)
        return std::format("{:.2f} quatrilhões de anos", years / 1e15);
    if (years >= 1e12)
        return std::format("{:.2f} trilhões de anos", years / 1e12);
    if (years >= 1e9)
        return std::format("{:.2f} bilhões de anos", years / 1e9);
    if (years >= 1e6)
        return std::format("{:.2f} milhões de anos", years / 1e6);
    if (years >= 1e3)
        return std::format("{:.2f} mil anos", years / 1e3);
    return std::format("{} anos", format_num(years));
}

inline std::string format_probability(double rate_per_sec, double space, double window_sec) {
    if (space <= 0.0 || rate_per_sec <= 0.0)
        return "—";
    const double expected = rate_per_sec * window_sec;
    const double p = 1.0 - std::exp(-expected / space);
    if (p <= 0.0 || !std::isfinite(p))
        return "≈0";
    if (p >= 0.90)
        return ">90%";
    if (p >= 0.10)
        return std::format("{:.1f}%", p * 100.0);
    if (p >= 0.01)
        return std::format("{:.2f}%", p * 100.0);
    const double one_in = 1.0 / p;
    if (!std::isfinite(one_in))
        return "≈0";
    return std::format("1 em {}", format_num(one_in));
}

inline std::string format_ratio(double r) {
    if (r < 0.0)
        return "0";
    if (r < 100.0) {
        std::string s = std::format("{:.2f}", r);
        size_t last = s.find_last_not_of('0');
        if (last != std::string::npos && s[last] == '.')
            --last;
        if (last != std::string::npos && last + 1 < s.size())
            s.erase(last + 1);
        return s;
    }
    return format_num(r);
}

inline std::string format_feasibility(double eta_seconds) {
    if (!std::isfinite(eta_seconds) || eta_seconds < 0.0)
        return "\033[1;31mINVIÁVEL\033[0m";
    constexpr double Y = 365.25 * 86400.0;
    if (eta_seconds > 1e6 * Y)
        return "\033[1;31mIMPRATICÁVEL\033[0m";
    if (eta_seconds > 100 * Y)
        return "\033[1;31mMUITO LONGO\033[0m";
    if (eta_seconds > 10 * Y)
        return "\033[1;33mLONGO\033[0m";
    if (eta_seconds > Y)
        return "\033[1;33m1+ ANO\033[0m";
    return "";
}

// Caixas / molduras
inline void append_dashes(std::string& s, size_t count) {
    for (size_t i = 0; i < count; ++i)
        s += "─";
}

inline void print_box_top(std::string_view title = "", size_t inner_width = DEFAULT_INNER_WIDTH) {
    std::string line = "╭───";
    if (!title.empty()) {
        line += " ";
        line += title;
        line += " ";
        const size_t vis_title = visible_length(title);
        if (inner_width > vis_title + 1)
            append_dashes(line, inner_width - 1 - vis_title);
    } else {
        append_dashes(line, inner_width);
    }
    line += "╮";
    std::println("{}", line);
}

inline void print_box_line(std::string_view content, size_t inner_width = DEFAULT_INNER_WIDTH) {
    const size_t vis_len = visible_length(content);
    std::string line = "│  ";
    line += content;
    if (vis_len < inner_width)
        line.append(inner_width - vis_len, ' ');
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

// Helpers de terminal
inline void write_all(int fd, const char* data, size_t len) noexcept {
    while (len > 0) {
        const ssize_t w = ::write(fd, data, len);
        if (w <= 0)
            return;
        data += w;
        len -= static_cast<size_t>(w);
    }
}

// Reset de baixo nível para saída anormal. Só usa write() — signal-safe.
inline void panic_reset_terminal() noexcept {
    static constexpr char SEQ[] =
        "\033[r"
        "\033[?25h"
        "\033[0m"
        "\033[2J\033[H";
    write_all(STDERR_FILENO, SEQ, sizeof(SEQ) - 1);
}

// LiveFrame — frame multi-linha com atualização in-place.
//
// Invariantes:
//   1. Após `render()`, cursor está na ÚLTIMA linha do frame.
//   2. Após `clear()`, cursor está na primeira linha LIMPA abaixo do frame.
//
// Estratégia: movimento relativo puro (`\033[<N>A`, `\r`, `\033[2K`, `\n`),
// sem save/restore, sem scroll region, sem esconder cursor. Trunca cada
// linha a `terminal_width() - 1` para evitar autowrap.
class LiveFrame {
   public:
    LiveFrame() = default;
    ~LiveFrame() { clear(); }

    LiveFrame(const LiveFrame&) = delete;
    LiveFrame& operator=(const LiveFrame&) = delete;

    void render(const std::vector<std::string>& lines_in) {
        if (lines_in.empty()) {
            clear();
            return;
        }

        const size_t term_w = terminal_width();
        const size_t max_line_vis = (term_w > 1) ? (term_w - 1) : term_w;

        std::vector<std::string> lines;
        lines.reserve(lines_in.size());
        for (const auto& l : lines_in) {
            if (visible_length(l) <= max_line_vis) {
                lines.push_back(l);
            } else {
                std::string cut;
                cut.reserve(l.size());
                size_t vis = 0;
                bool in_escape = false;
                for (size_t i = 0; i < l.size() && vis < max_line_vis; ++i) {
                    const char c = l[i];
                    cut += c;
                    if (c == '\033') {
                        in_escape = true;
                    } else if (in_escape) {
                        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                            in_escape = false;
                    } else {
                        const unsigned char uc = static_cast<unsigned char>(c);
                        if ((uc & 0xC0) != 0x80)
                            ++vis;
                    }
                }
                cut += "\033[0m";
                lines.push_back(std::move(cut));
            }
        }

        const size_t N = lines.size();
        std::string buf;
        buf.reserve(512 + N * 256);

        // 1) Sobe para o topo do frame anterior.
        if (started_) {
            if (prev_lines_ > 1) {
                buf += "\033[";
                buf += std::to_string(prev_lines_ - 1);
                buf += "A";
            }
            buf += '\r';
        }

        // 2) Desenha cada linha com clear + conteúdo + \n entre elas.
        for (size_t i = 0; i < N; ++i) {
            buf += "\033[2K";
            buf += lines[i];
            if (i + 1 < N)
                buf += '\n';
        }

        // 3) Se o frame novo é menor, apaga as sobras.
        if (started_ && N < prev_lines_) {
            for (size_t i = N; i < prev_lines_; ++i)
                buf += "\n\033[2K";
            const size_t up = prev_lines_ - N;
            if (up > 0) {
                buf += "\033[";
                buf += std::to_string(up);
                buf += "A";
            }
            buf += '\r';
        }

        write_all(STDERR_FILENO, buf.data(), buf.size());
        prev_lines_ = N;
        started_ = true;
    }

    // Limpa o frame e deixa o cursor em uma linha fresca abaixo. Idempotente.
    void clear() {
        if (!started_)
            return;

        std::string buf;
        buf.reserve(prev_lines_ * 16 + 32);

        if (prev_lines_ > 1) {
            buf += "\033[";
            buf += std::to_string(prev_lines_ - 1);
            buf += "A";
        }
        buf += '\r';

        for (size_t i = 0; i < prev_lines_; ++i)
            buf += "\033[2K\n";
        buf += '\r';

        write_all(STDERR_FILENO, buf.data(), buf.size());
        prev_lines_ = 0;
        started_ = false;
    }

    size_t line_count() const noexcept { return prev_lines_; }

   private:
    size_t prev_lines_ = 0;
    bool started_ = false;
};

}  // namespace cryptowords::ui
