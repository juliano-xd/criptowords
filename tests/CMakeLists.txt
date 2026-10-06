# Suite de testes unitários — sem dependência externa (framework em
# test_framework.hpp). Target linkado a criptowords_core para reusar as
# compilações otimizadas (-march=native, LTO) e as bibliotecas já resolvidas
# (GMP para mpz_class, SHA-NI via -msha, etc.).
add_executable(criptowords_tests
    test_main.cpp
    test_crypto.cpp
    test_plan.cpp
)

target_include_directories(criptowords_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(criptowords_tests PRIVATE criptowords_core)

target_compile_features(criptowords_tests PRIVATE cxx_std_23)

# Silencia warnings comuns em testes (variáveis não usadas em REQUIRE de
# constantes, etc.) — mantém -Wall -Wextra do target principal.
target_compile_options(criptowords_tests PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
)

add_test(NAME criptowords_tests COMMAND criptowords_tests)
