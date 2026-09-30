cmake_minimum_required(VERSION 3.25)

project(criptowords
    VERSION     1.0.0
    DESCRIPTION "BIP39 Mnemonic Recovery Engine"
    LANGUAGES   CXX
)

# ---------- Proteção contra In-Source Build ----------
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "\n[ERRO] In-source builds são proibidos!\n"
        "Por favor, crie um diretório de build separado e execute CMake a partir dele:\n"
        "  cmake -B build -G Ninja\n"
        "  cmake --build build\n"
    )
endif()

# ---------- Acelerador de Compilação (ccache) ----------
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    message(STATUS "ccache encontrado: ${CCACHE_PROGRAM}")
endif()

# ---------- Padrão C++ e Defaults ----------
set(CMAKE_CXX_STANDARD          23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# O projeto usa <print> (C++23), que so existe no GCC 14+ e no Clang 17+.
# Sem esta checagem, quem tem GCC 13 passa pelo configure e so descobre no meio
# da compilacao com "fatal error: print: No such file or directory", que nao
# ajuda a entender que o problema e a versao do compilador.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
    message(FATAL_ERROR "GCC 14+ necessario (<print> do C++23). Detectado: ${CMAKE_CXX_COMPILER_VERSION}")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 17)
    message(FATAL_ERROR "Clang 17+ necessario (<print> do C++23). Detectado: ${CMAKE_CXX_COMPILER_VERSION}")
endif()
set(CMAKE_CXX_EXTENSIONS        OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Exporta compile_commands.json para a raiz se necessário (suporte a LSPs: clangd, etc.)
if(CMAKE_EXPORT_COMPILE_COMMANDS AND NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E create_symlink
                "${CMAKE_BINARY_DIR}/compile_commands.json"
                "${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json"
        RESULT_VARIABLE _symlink_res
        OUTPUT_QUIET ERROR_QUIET
    )
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Tipo de compilação (Release, Debug, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

# ---------- Opções de Compilação & Otimização ----------
option(CRYPTOWORDS_GPU     "Aceleração OpenCL (GPU)" ON)
option(CRYPTOWORDS_PCH     "Habilitar Precompiled Headers (PCH) para cabeçalhos pesados C++23" ON)
option(CRYPTOWORDS_LTO     "Link-Time Optimization (LTO / IPO)" ON)
option(CRYPTOWORDS_WERROR  "Tratar warnings do compilador como erros" OFF)
option(CRYPTOWORDS_ASAN    "Habilitar AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(CRYPTOWORDS_TSAN    "Habilitar ThreadSanitizer (Detecção de Data Races)" OFF)

# Seleção de Microarquitetura
set(CRYPTOWORDS_ARCH "native" CACHE STRING "Microarquitetura alvo: native, x86-64-v4, x86-64-v3, x86-64-v2, generic")
set_property(CACHE CRYPTOWORDS_ARCH PROPERTY STRINGS "native" "x86-64-v4" "x86-64-v3" "x86-64-v2" "generic")

# Retrocompatibilidade com CRYPTOWORDS_NATIVE
if(DEFINED CRYPTOWORDS_NATIVE)
    if(NOT CRYPTOWORDS_NATIVE AND CRYPTOWORDS_ARCH STREQUAL "native")
        set(CRYPTOWORDS_ARCH "generic")
    endif()
endif()

# Profile-Guided Optimization (PGO)
set(CRYPTOWORDS_PGO "OFF" CACHE STRING "Profile-Guided Optimization: OFF, GENERATE, USE")
set_property(CACHE CRYPTOWORDS_PGO PROPERTY STRINGS "OFF" "GENERATE" "USE")
set(CRYPTOWORDS_PGO_DIR "${CMAKE_BINARY_DIR}/pgo_profile" CACHE PATH "Diretório de perfis PGO")

# Otimização do FetchContent (evita checagens repetidas de rede após o primeiro download)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Desconectar checagem de atualizações do FetchContent" FORCE)

# ---------- Linker de Alta Performance (mold / lld) ----------
include(CheckLinkerFlag)
check_linker_flag(CXX "-fuse-ld=mold" HAS_MOLD)
if(HAS_MOLD)
    add_link_options("-fuse-ld=mold")
    message(STATUS "Linker de ultra-alta velocidade detectado: mold (-fuse-ld=mold)")
else()
    check_linker_flag(CXX "-fuse-ld=lld" HAS_LLD)
    if(HAS_LLD)
        add_link_options("-fuse-ld=lld")
        message(STATUS "Linker de alta velocidade detectado: lld (-fuse-ld=lld)")
    endif()
endif()

# ---------- Otimização em Tempo de Linkedição (LTO / IPO) ----------
if(CRYPTOWORDS_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)
    if(IPO_SUPPORTED)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
        message(STATUS "LTO/IPO: Habilitado globalmente (Interprocedural Optimization)")
    else()
        message(STATUS "LTO/IPO não suportado pelo compilador: ${IPO_ERROR}")
    endif()
endif()


# ---------- Dependências externas com fallback automático ----------
include(FetchContent)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SECP256K1 QUIET IMPORTED_TARGET libsecp256k1)
endif()

if(NOT TARGET PkgConfig::SECP256K1)
    message(STATUS "libsecp256k1 não encontrado no sistema. Baixando e compilando via FetchContent...")
    FetchContent_Declare(secp256k1
        GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
        GIT_TAG        v0.5.1
        GIT_SHALLOW    TRUE
    )
    set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(secp256k1)
    add_library(PkgConfig::SECP256K1 ALIAS secp256k1)
else()
    message(STATUS "libsecp256k1 encontrado no sistema via pkg-config.")
endif()

find_package(CLI11 QUIET)
if(NOT CLI11_FOUND)
    message(STATUS "CLI11 not found on system. Downloading...")
    FetchContent_Declare(CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG        v2.7.2
        GIT_SHALLOW    TRUE
        SYSTEM
    )
    FetchContent_MakeAvailable(CLI11)
else()
    message(STATUS "CLI11 found on system.")
endif()

if(CRYPTOWORDS_GPU)
    find_package(OpenCL QUIET)
    if(NOT OpenCL_FOUND)
        message(STATUS "OpenCL não encontrado — desabilitando GPU.")
        set(CRYPTOWORDS_GPU OFF)
    endif()
endif()

# ---------- Sondagem de SIMD ----------
include(CheckCXXCompilerFlag)

set(HAVE_SSE41  FALSE)
set(HAVE_AVX2   FALSE)
set(HAVE_AVX512 FALSE)
set(HAVE_SHA_NI FALSE)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    check_cxx_compiler_flag("-msse4.1"  _SSE41_OK)
    check_cxx_compiler_flag("-mavx2"    _AVX2_OK)
    check_cxx_compiler_flag("-mavx512f" _AVX512_OK)
    check_cxx_compiler_flag("-msha"     _SHA_OK)
    if(_SSE41_OK)
        set(HAVE_SSE41 TRUE)
    endif()
    if(_AVX2_OK)
        set(HAVE_AVX2 TRUE)
    endif()
    if(_AVX512_OK)
        set(HAVE_AVX512 TRUE)
    endif()
    if(_SHA_OK)
        set(HAVE_SHA_NI TRUE)
    endif()
endif()

message(STATUS "SIMD: SSE4.1=${HAVE_SSE41}  AVX2=${HAVE_AVX2}  AVX512=${HAVE_AVX512}  SHA-NI=${HAVE_SHA_NI}")

# ---------- Flags de Diagnóstico e Otimização ----------
set(WARN_FLAGS -Wall -Wextra -Wpedantic -Wno-ignored-attributes)
if(CRYPTOWORDS_WERROR)
    list(APPEND WARN_FLAGS -Werror)
endif()

set(PERF_FLAGS -pipe -fomit-frame-pointer -fstrict-aliasing -fno-math-errno -fno-trapping-math -funroll-loops -ftree-vectorize)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    list(APPEND PERF_FLAGS -floop-interchange -floop-unroll-and-jam -fno-semantic-interposition)
endif()

# Microarquitetura
if(CRYPTOWORDS_ARCH STREQUAL "native")
    list(APPEND PERF_FLAGS -march=native -mtune=native)
    message(STATUS "Microarquitetura: native (-march=native -mtune=native)")
elseif(CRYPTOWORDS_ARCH STREQUAL "x86-64-v4")
    list(APPEND PERF_FLAGS -march=x86-64-v4)
    message(STATUS "Microarquitetura: x86-64-v4 (AVX-512, FMA, BMI2)")
elseif(CRYPTOWORDS_ARCH STREQUAL "x86-64-v3")
    list(APPEND PERF_FLAGS -march=x86-64-v3)
    message(STATUS "Microarquitetura: x86-64-v3 (AVX2, FMA, BMI2)")
elseif(CRYPTOWORDS_ARCH STREQUAL "x86-64-v2")
    list(APPEND PERF_FLAGS -march=x86-64-v2)
    message(STATUS "Microarquitetura: x86-64-v2 (SSE4.2, POPCNT)")
elseif(CRYPTOWORDS_ARCH STREQUAL "generic")
    message(STATUS "Microarquitetura: generic (x86_64 baseline)")
endif()

# Flags PGO (Profile-Guided Optimization)
if(CRYPTOWORDS_PGO STREQUAL "GENERATE")
    message(STATUS "PGO: Modo GENERATE ativado (gerando perfis em ${CRYPTOWORDS_PGO_DIR})")
    file(MAKE_DIRECTORY "${CRYPTOWORDS_PGO_DIR}")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        add_compile_options(-fprofile-generate=${CRYPTOWORDS_PGO_DIR})
        add_link_options(-fprofile-generate=${CRYPTOWORDS_PGO_DIR})
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-fprofile-instr-generate=${CRYPTOWORDS_PGO_DIR}/default.profraw)
        add_link_options(-fprofile-instr-generate=${CRYPTOWORDS_PGO_DIR}/default.profraw)
    endif()
elseif(CRYPTOWORDS_PGO STREQUAL "USE")
    message(STATUS "PGO: Modo USE ativado (lendo perfis de ${CRYPTOWORDS_PGO_DIR})")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        add_compile_options(-fprofile-use=${CRYPTOWORDS_PGO_DIR} -fprofile-correction)
        add_link_options(-fprofile-use=${CRYPTOWORDS_PGO_DIR} -fprofile-correction)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-fprofile-instr-use=${CRYPTOWORDS_PGO_DIR}/default.profdata)
        add_link_options(-fprofile-instr-use=${CRYPTOWORDS_PGO_DIR}/default.profdata)
    endif()
endif()

# ---------- Sanitizers ----------
if(CRYPTOWORDS_ASAN)
    message(STATUS "Sanitizers: AddressSanitizer + UndefinedBehaviorSanitizer habilitados")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif(CRYPTOWORDS_TSAN)
    message(STATUS "Sanitizers: ThreadSanitizer habilitado")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()

# ---------- Núcleo da Aplicação (criptowords_core) ----------
set(CORE_SOURCES
    src/cli/parser.cpp
    src/cli/wordlist.cpp
    src/cli/validator.cpp

    src/search/optimizer.cpp
    src/search/reporter.cpp
    src/search/odometer.cpp
    src/search/pipeline.cpp
    src/search/engine.cpp

    src/simd/factory.cpp

    src/hardware/host_probe.cpp
    src/hardware/hardware_advisor.cpp

    src/crypto/base58.cpp
    src/crypto/bip39.cpp
    src/crypto/ripemd160.cpp
    src/crypto/sha256.cpp
    src/crypto/keccak256.cpp
    src/crypto/hmac_sha512.cpp
)

add_library(criptowords_core OBJECT ${CORE_SOURCES})
target_include_directories(criptowords_core PUBLIC include)
target_link_libraries(criptowords_core PUBLIC PkgConfig::SECP256K1 CLI11::CLI11)
target_compile_options(criptowords_core PRIVATE ${WARN_FLAGS} ${PERF_FLAGS})

# Precompiled Headers (PCH) para acelerar compilação do núcleo C++23
if(CRYPTOWORDS_PCH)
    message(STATUS "PCH: Precompiled Headers ativados para criptowords_core")
    target_precompile_headers(criptowords_core PRIVATE
        <algorithm>
        <array>
        <atomic>
        <chrono>
        <cstdint>
        <cstring>
        <format>
        <memory>
        <optional>
        <print>
        <span>
        <string>
        <string_view>
        <utility>
        <vector>
    )
endif()

if(CRYPTOWORDS_GPU)
    target_link_libraries(criptowords_core PUBLIC OpenCL::OpenCL)
    target_compile_definitions(criptowords_core PUBLIC CRYPTOWORDS_HAVE_GPU=1)
endif()

if(HAVE_SSE41)
    target_compile_definitions(criptowords_core PUBLIC CRYPTOWORDS_HAVE_SSE41=1)
endif()
if(HAVE_AVX2)
    target_compile_definitions(criptowords_core PUBLIC CRYPTOWORDS_HAVE_AVX2=1)
endif()
if(HAVE_AVX512)
    target_compile_definitions(criptowords_core PUBLIC CRYPTOWORDS_HAVE_AVX512=1)
endif()

# ---------- Unidades de Tradução SIMD Especializadas ----------
set(SIMD_OBJECTS "")

if(HAVE_SSE41)
    add_library(simd_sse OBJECT src/simd/factory_sse.cpp)
    target_include_directories(simd_sse PRIVATE include)
    target_link_libraries(simd_sse PRIVATE PkgConfig::SECP256K1)
    target_compile_options(simd_sse PRIVATE -msse4.1 ${WARN_FLAGS} ${PERF_FLAGS})
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_sse>)
endif()

if(HAVE_AVX2)
    add_library(simd_avx2 OBJECT src/simd/factory_avx2.cpp)
    target_include_directories(simd_avx2 PRIVATE include)
    target_link_libraries(simd_avx2 PRIVATE PkgConfig::SECP256K1)
    target_compile_options(simd_avx2 PRIVATE -mavx2 -mfma -mbmi -mbmi2 ${WARN_FLAGS} ${PERF_FLAGS})
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_avx2>)
endif()

if(HAVE_AVX512)
    add_library(simd_avx512 OBJECT src/simd/factory_avx512.cpp)
    target_include_directories(simd_avx512 PRIVATE include)
    target_link_libraries(simd_avx512 PRIVATE PkgConfig::SECP256K1)
    target_compile_options(simd_avx512 PRIVATE -mavx512f -mavx512dq -mavx512bw -mavx512vl -mavx512cd ${WARN_FLAGS} ${PERF_FLAGS})
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_avx512>)
endif()

# ---------- Fontes da GPU ----------
set(GPU_SOURCES "")
if(CRYPTOWORDS_GPU)
    set(GPU_SOURCES
        src/gpu/gpu_engine.cpp
        src/gpu/gpu_info.cpp
    )
endif()

# ---------- Executável Principal ----------
add_executable(criptowords
    src/main.cpp
    src/benchmark/benchmark_runner.cpp
    ${GPU_SOURCES}
    $<TARGET_OBJECTS:criptowords_core>
    ${SIMD_OBJECTS}
)

target_compile_options(criptowords PRIVATE ${WARN_FLAGS} ${PERF_FLAGS})
target_link_libraries(criptowords PRIVATE criptowords_core)
if(CRYPTOWORDS_PCH)
    target_precompile_headers(criptowords REUSE_FROM criptowords_core)
endif()

# ---------- Binário de Testes Comparativos SHA-512 ----------
add_executable(test_sha512_comparison
    tests/test_sha512_comparison.cpp
    $<TARGET_OBJECTS:criptowords_core>
    ${SIMD_OBJECTS}
)
target_compile_options(test_sha512_comparison PRIVATE ${WARN_FLAGS} ${PERF_FLAGS})
target_link_libraries(test_sha512_comparison PRIVATE criptowords_core)
if(CRYPTOWORDS_PCH)
    target_precompile_headers(test_sha512_comparison REUSE_FROM criptowords_core)
endif()

# ---------- Testes Automatizados e Integração CTest ----------
enable_testing()

add_test(NAME test_sha512 COMMAND test_sha512_comparison)
set_tests_properties(test_sha512 PROPERTIES TIMEOUT 60)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(
        NAME qa_suite
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/qa_suite.py $<TARGET_FILE:criptowords>
    )
    set_tests_properties(qa_suite PROPERTIES
        TIMEOUT 240
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --test-dir ${CMAKE_BINARY_DIR}
    DEPENDS criptowords test_sha512_comparison
    COMMENT "Executando bateria de testes do CTest..."
)

# ---------- Ferramentas de Qualidade de Código (clang-format) ----------
find_program(CLANG_FORMAT_EXE clang-format)
if(CLANG_FORMAT_EXE)
    file(GLOB_RECURSE ALL_FORMAT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.hpp
    )
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXE} -i -style=file ${ALL_FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Formatando código-fonte C++ com clang-format..."
    )
    add_custom_target(check-format
        COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror -style=file ${ALL_FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Verificando conformidade do código com clang-format..."
    )
endif()

# ---------- Instalação e Empacotamento de Distribuição (CPack) ----------
install(TARGETS criptowords RUNTIME DESTINATION bin)
install(DIRECTORY wordlist/ DESTINATION share/criptowords/wordlist)
install(FILES README.md DESTINATION share/doc/criptowords OPTIONAL)

set(CPACK_PACKAGE_NAME "criptowords")
set(CPACK_PACKAGE_VENDOR "CriptoWords Core Team")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Motor Ultrarrápido de Recuperação de Mnemonics BIP39 em C++23")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# Geradores de pacotes suportados
set(CPACK_GENERATOR "TGZ;TXZ")

# Configurações Debian (.deb)
set(CPACK_DEBIAN_PACKAGE_NAME "criptowords")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Juliano Trindade <juliano@criptowords.local>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include(CPack)
