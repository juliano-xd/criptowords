cmake_minimum_required(VERSION 3.25)

project(criptowords
    VERSION     1.0.0
    DESCRIPTION "BIP39 Mnemonic Recovery Engine"
    LANGUAGES   CXX
)

# ---------- Padrão e defaults ----------
set(CMAKE_CXX_STANDARD          23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------- Opções ----------
option(CRYPTOWORDS_GPU    "Aceleração OpenCL"       ON)
option(CRYPTOWORDS_NATIVE "Compilar com -march=native (só para builds locais)" OFF)
option(CRYPTOWORDS_WERROR "Tratar warnings como erros" OFF)

# ---------- Dependências externas ----------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED IMPORTED_TARGET libsecp256k1)

find_package(CLI11 QUIET)
if(NOT CLI11_FOUND)
    include(FetchContent)
    FetchContent_Declare(CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG        v2.4.2
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(CLI11)
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

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    check_cxx_compiler_flag("-msse4.1"  _SSE41_OK)
    check_cxx_compiler_flag("-mavx2"    _AVX2_OK)
    check_cxx_compiler_flag("-mavx512f" _AVX512_OK)
    if(_SSE41_OK)
        set(HAVE_SSE41 TRUE)
    endif()
    if(_AVX2_OK)
        set(HAVE_AVX2 TRUE)
    endif()
    if(_AVX512_OK)
        set(HAVE_AVX512 TRUE)
    endif()
endif()

message(STATUS "SIMD: SSE4.1=${HAVE_SSE41}  AVX2=${HAVE_AVX2}  AVX512=${HAVE_AVX512}")

# ---------- Flags de aviso (aplicadas só ao código nosso) ----------
set(WARN_FLAGS -Wall -Wextra -Wpedantic)
if(CRYPTOWORDS_WERROR)
    list(APPEND WARN_FLAGS -Werror)
endif()

# ---------- Núcleo (portável) ----------
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

    src/crypto/base58.cpp
    src/crypto/bip39.cpp
    src/crypto/ripemd160.cpp
    src/crypto/sha256.cpp
    src/crypto/sha512.cpp
    src/crypto/hmac_sha512.cpp
    src/crypto/keccak256.cpp
)

add_library(criptowords_core OBJECT ${CORE_SOURCES})
target_include_directories(criptowords_core PUBLIC include)
target_link_libraries(criptowords_core PUBLIC PkgConfig::SECP256K1 CLI11::CLI11)
target_compile_options(criptowords_core PRIVATE ${WARN_FLAGS})

if(CRYPTOWORDS_NATIVE)
    target_compile_options(criptowords_core PRIVATE -march=native)
endif()

# ---------- TUs SIMD compiladas por arquitetura ----------
set(SIMD_OBJECTS "")

if(HAVE_SSE41)
    add_library(simd_sse OBJECT src/simd/factory_sse.cpp)
    target_include_directories(simd_sse PRIVATE include)
    target_link_libraries(simd_sse PRIVATE PkgConfig::SECP256K1)
    target_compile_options(simd_sse PRIVATE -msse4.1 ${WARN_FLAGS})
    target_compile_definitions(criptowords_core PRIVATE CRYPTOWORDS_HAVE_SSE41=1)
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_sse>)
endif()

if(HAVE_AVX2)
    add_library(simd_avx2 OBJECT src/simd/factory_avx2.cpp)
    target_include_directories(simd_avx2 PRIVATE include)
    target_link_libraries(simd_avx2 PRIVATE PkgConfig::SECP256K1)
    target_compile_options(simd_avx2 PRIVATE -mavx2 -mfma -mbmi -mbmi2 ${WARN_FLAGS})
    target_compile_definitions(criptowords_core PRIVATE CRYPTOWORDS_HAVE_AVX2=1)
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_avx2>)
endif()

if(HAVE_AVX512)
    add_library(simd_avx512 OBJECT src/simd/factory_avx512.cpp)
    target_include_directories(simd_avx512 PRIVATE include)
    target_link_libraries(simd_avx512 PRIVATE PkgConfig::SECP256K1)
    target_compile_options(simd_avx512 PRIVATE -mavx512f ${WARN_FLAGS})
    target_compile_definitions(criptowords_core PRIVATE CRYPTOWORDS_HAVE_AVX512=1)
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_avx512>)
endif()

# ---------- GPU (opcional) ----------
set(GPU_SOURCES "")
if(CRYPTOWORDS_GPU)
    set(GPU_SOURCES
        src/gpu/gpu_engine.cpp
        src/gpu/gpu_info.cpp
    )
endif()

# ---------- Executável ----------
add_executable(criptowords
    src/main.cpp
    ${GPU_SOURCES}
    $<TARGET_OBJECTS:criptowords_core>
    ${SIMD_OBJECTS}
)

target_include_directories(criptowords PRIVATE include)
target_link_libraries(criptowords PRIVATE
    PkgConfig::SECP256K1
    CLI11::CLI11
)

if(CRYPTOWORDS_GPU)
    target_link_libraries(criptowords PRIVATE OpenCL::OpenCL)
    target_compile_definitions(criptowords PRIVATE CRYPTOWORDS_HAVE_GPU=1)
endif()

# ---------- Install ----------
install(TARGETS criptowords RUNTIME DESTINATION bin)
install(DIRECTORY wordlist/ DESTINATION share/criptowords/wordlist)
