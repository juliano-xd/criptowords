#pragma once
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

// Miniframework de testes — sem dependência externa, ~80 linhas. Cada
// TEST_CASE registra-se num vetor global de função-ponteiro; test_main.cpp
// chama run_all() e devolve o código de saída. REQUIRE* lançam
// AssertionFailure que run_all captura para reportar e continuar a
// próxima suíte (diferente de std::abort, que derrubaria tudo).
namespace testfw {

using TestFn = void (*)();
struct Entry { const char* name; TestFn fn; };

inline std::vector<Entry>& registry() {
    static std::vector<Entry> r;
    return r;
}

struct Register {
    Register(const char* n, TestFn f) { registry().push_back({n, f}); }
};

struct AssertionFailure : std::exception {
    const char* msg;
    explicit AssertionFailure(const char* m) : msg(m) {}
    const char* what() const noexcept override { return msg; }
};

inline int run_all() {
    int failed = 0;
    for (const auto& e : registry()) {
        std::fprintf(stderr, "[ RUN  ] %s\n", e.name);
        try {
            e.fn();
            std::fprintf(stderr, "[  OK  ] %s\n", e.name);
        } catch (const AssertionFailure& ex) {
            std::fprintf(stderr, "[ FAIL ] %s\n        %s\n", e.name, ex.what());
            ++failed;
        } catch (const std::exception& ex) {
            std::fprintf(stderr, "[ FAIL ] %s\n        %s\n", e.name, ex.what());
            ++failed;
        } catch (...) {
            std::fprintf(stderr, "[ FAIL ] %s\n        unknown exception\n", e.name);
            ++failed;
        }
    }
    std::fprintf(stderr, "\n%d test(s) failed out of %zu.\n",
                 failed, registry().size());
    return failed == 0 ? 0 : 1;
}

}  // namespace testfw

#define TEST_CASE(NAME)                                              \
    static void NAME();                                              \
    static ::testfw::Register reg_##NAME(#NAME, &NAME);              \
    static void NAME()

#define REQUIRE(cond)                                                \
    do {                                                             \
        if (!(cond)) {                                               \
            std::fprintf(stderr, "  assertion failed: %s (%s:%d)\n", \
                         #cond, __FILE__, __LINE__);                 \
            throw ::testfw::AssertionFailure(#cond);                 \
        }                                                            \
    } while (0)

#define REQUIRE_EQ(a, b)                                             \
    do {                                                             \
        auto&& _va = (a);                                            \
        auto&& _vb = (b);                                            \
        if (!(_va == _vb)) {                                         \
            std::fprintf(stderr,                                     \
                         "  REQUIRE_EQ failed: %s == %s (%s:%d)\n",  \
                         #a, #b, __FILE__, __LINE__);                \
            throw ::testfw::AssertionFailure(#a " == " #b);          \
        }                                                            \
    } while (0)
