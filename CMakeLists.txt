cmake_minimum_required(VERSION 3.25)

project(criptowords
    VERSION     1.0.0
    DESCRIPTION "BIP39 Mnemonic Recovery Engine"
    LANGUAGES   CXX
)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR
        "\n[ERRO] In-source builds são proibidos!\n"
        "Crie um diretório de build separado:\n"
        "  cmake -B build -G Ninja\n"
        "  cmake --build build\n"
    )
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  message(STATUS "ccache: ${CCACHE_PROGRAM}")
endif()

set(CMAKE_CXX_STANDARD          23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
  message(FATAL_ERROR "GCC 14+ necessario. Detectado: ${CMAKE_CXX_COMPILER_VERSION}")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 17)
  message(FATAL_ERROR "Clang 17+ necessario. Detectado: ${CMAKE_CXX_COMPILER_VERSION}")
endif()

set(CMAKE_CXX_EXTENSIONS         OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Tipo de compilação" FORCE)
endif()

# =========================================================================
# Opções
# =========================================================================
option(CRYPTOWORDS_ENABLE_HIP "Habilita backend AMD ROCm/HIP" ON)
option(CRYPTOWORDS_PCH        "Precompiled Headers"          ON)
option(CRYPTOWORDS_LTO        "Link-Time Optimization"       ON)
option(CRYPTOWORDS_WERROR     "Warnings como erros"          OFF)
option(CRYPTOWORDS_ASAN       "AddressSanitizer + UBSan"     OFF)
option(CRYPTOWORDS_TSAN       "ThreadSanitizer"              OFF)

set(CRYPTOWORDS_ARCH "native" CACHE STRING
    "Microarquitetura alvo: native, x86-64-v4, x86-64-v3, x86-64-v2, generic")
set_property(CACHE CRYPTOWORDS_ARCH PROPERTY STRINGS "native" "x86-64-v4" "x86-64-v3" "x86-64-v2" "generic")

set(CRYPTOWORDS_PGO "OFF" CACHE STRING "PGO: OFF, GENERATE, USE")
set_property(CACHE CRYPTOWORDS_PGO PROPERTY STRINGS "OFF" "GENERATE" "USE")
set(CRYPTOWORDS_PGO_DIR "${CMAKE_BINARY_DIR}/pgo_profile" CACHE PATH "Diretório PGO")

set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)

# =========================================================================
# Arquitetura: x86 vs ARM64 (Termux)
# =========================================================================
set(CW_X86 FALSE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i386|i686")
  set(CW_X86 TRUE)
endif()
message(STATUS "Arch: ${CMAKE_SYSTEM_PROCESSOR} (x86=${CW_X86})")

# =========================================================================
# Linker de alta velocidade
# =========================================================================
include(CheckLinkerFlag)
check_linker_flag(CXX "-fuse-ld=mold" HAS_MOLD)
if(HAS_MOLD)
  add_link_options("-fuse-ld=mold")
  message(STATUS "Linker: mold")
else()
  check_linker_flag(CXX "-fuse-ld=lld" HAS_LLD)
  if(HAS_LLD)
    add_link_options("-fuse-ld=lld")
    message(STATUS "Linker: lld")
  endif()
endif()

# =========================================================================
# LTO / IPO
# =========================================================================
if(CRYPTOWORDS_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)
  if(IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
    message(STATUS "LTO/IPO: habilitado")
  else()
    message(STATUS "LTO/IPO não suportado: ${IPO_ERROR}")
  endif()
endif()

# =========================================================================
# GMP
# =========================================================================
include(FetchContent)
find_package(GMP QUIET)
if(NOT GMP_FOUND)
  find_library(GMP_LIB   NAMES gmp   REQUIRED)
  find_library(GMPXX_LIB NAMES gmpxx REQUIRED)
  set(GMP_LIBRARIES "${GMP_LIB};${GMPXX_LIB}")
endif()
if(NOT GMP_LIBRARIES)
  message(FATAL_ERROR "GMP não encontrado. Instale libgmp-dev (Termux: pkg install libgmp).")
endif()
message(STATUS "GMP: ${GMP_LIBRARIES}")

# =========================================================================
# CLI11
# =========================================================================
find_package(CLI11 QUIET)
if(NOT CLI11_FOUND)
  FetchContent_Declare(CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG        v2.7.2
        GIT_SHALLOW    TRUE
        SYSTEM
    )
  FetchContent_MakeAvailable(CLI11)
endif()

# =========================================================================
# Backend HIP (AMD ROCm) — desabilitado em ARM/Termux
# =========================================================================
set(CRYPTOWORDS_HAVE_HIP  FALSE)
set(CRYPTOWORDS_HIP_OBJECT "")
set(CRYPTOWORDS_HIP_LIBS   "")

if(CRYPTOWORDS_ENABLE_HIP AND CW_X86)
  find_program(HIPCC_EXECUTABLE    hipcc)
  find_program(ROCMINFO_EXECUTABLE rocminfo HINTS /opt/rocm/bin /usr/bin)

  if(NOT HIPCC_EXECUTABLE)
    message(STATUS "hipcc não encontrado — backend AMD desabilitado")
  else()
    set(_HIP_NATIVE_ARCH "")
    if(ROCMINFO_EXECUTABLE)
      execute_process(
                COMMAND ${ROCMINFO_EXECUTABLE}
                OUTPUT_VARIABLE _ROCMINFO_OUT
                ERROR_QUIET
            )
      string(REGEX MATCH "gfx[0-9a-f]+" _HIP_NATIVE_ARCH "${_ROCMINFO_OUT}")
    endif()

    if(NOT _HIP_NATIVE_ARCH MATCHES "^gfx")
      execute_process(
                COMMAND ${HIPCC_EXECUTABLE} --print-target-id
                OUTPUT_VARIABLE _HIP_NATIVE_ARCH
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
            )
    endif()

    if(NOT _HIP_NATIVE_ARCH MATCHES "^gfx")
      message(STATUS "ROCm presente mas arch não detectável — backend AMD desabilitado")
    else()
      message(STATUS "HIP: arch nativa detectada = ${_HIP_NATIVE_ARCH}")

      find_library(HIP_RUNTIME_LIB NAMES amdhip64
              HINTS /opt/rocm/lib /opt/rocm/lib64 /usr/lib/x86_64-linux-gnu)
      find_library(HSA_RUNTIME_LIB NAMES hsa-runtime64
              HINTS /opt/rocm/lib /opt/rocm/lib64 /usr/lib/x86_64-linux-gnu)

      if(HIP_RUNTIME_LIB AND HSA_RUNTIME_LIB)
        set(HIP_OBJECT "${CMAKE_BINARY_DIR}/hip_engine.o")

        add_custom_command(
            OUTPUT  ${HIP_OBJECT}
            COMMAND ${HIPCC_EXECUTABLE}
                    -O2 -ffast-math
                    --offload-arch=${_HIP_NATIVE_ARCH}
                    -std=c++23 -fPIC
                    -Xclang -fno-cuda-host-device-constexpr
                    -Wno-unused-value
                    -DCRYPTOWORDS_HAVE_HIP=1
                    -I${CMAKE_SOURCE_DIR}/include
                    -I${CMAKE_SOURCE_DIR}/include/gpu/hip
                    -c ${CMAKE_SOURCE_DIR}/src/gpu/hip/hip_engine.hip
                    -o ${HIP_OBJECT}
            DEPENDS ${CMAKE_SOURCE_DIR}/src/gpu/hip/hip_engine.hip
                    ${CMAKE_SOURCE_DIR}/include/gpu/hip/hip_engine.hpp
                    ${CMAKE_SOURCE_DIR}/include/gpu/hip/pbkdf2_sha512.cuh
            COMMENT "hipcc: compilando hip_engine.hip (${_HIP_NATIVE_ARCH})"
            VERBATIM
        )

        add_custom_target(criptowords_hip_obj DEPENDS ${HIP_OBJECT})

        set(CRYPTOWORDS_HAVE_HIP  TRUE)
        set(CRYPTOWORDS_HIP_OBJECT ${HIP_OBJECT})
        set(CRYPTOWORDS_HIP_LIBS   ${HIP_RUNTIME_LIB} ${HSA_RUNTIME_LIB})
      endif()
    endif()
  endif()
elseif(CRYPTOWORDS_ENABLE_HIP AND NOT CW_X86)
  message(STATUS "HIP: desabilitado (arch ${CMAKE_SYSTEM_PROCESSOR} não é x86)")
endif()

# =========================================================================
# Detecção SIMD (só em x86; ARM usa fallback escalar do SSE)
# =========================================================================
include(CheckCXXCompilerFlag)

set(HAVE_SSE41  FALSE)
set(HAVE_AVX2   FALSE)
set(HAVE_AVX512 FALSE)
set(HAVE_SHA_NI FALSE)

if(CW_X86)
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
else()
  # Termux/ARM64: único "backend" é o 4-lane escalar (nome histórico: SSE).
  set(HAVE_SSE41 TRUE)
endif()

message(STATUS "SIMD: SSE4.1=${HAVE_SSE41}  AVX2=${HAVE_AVX2}  AVX512=${HAVE_AVX512}  SHA-NI=${HAVE_SHA_NI}")

# =========================================================================
# Flags de compilação
# =========================================================================
set(WARN_FLAGS -Wall -Wextra -Wpedantic -Wno-ignored-attributes)
if(CRYPTOWORDS_WERROR)
  list(APPEND WARN_FLAGS -Werror)
endif()

set(PERF_FLAGS
    -pipe
    -fomit-frame-pointer
    -fstrict-aliasing
    -fno-math-errno
    -fno-trapping-math
    -funroll-loops
    -ftree-vectorize
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  list(APPEND PERF_FLAGS -fno-semantic-interposition)
  if(CW_X86)
    list(APPEND PERF_FLAGS -floop-interchange -floop-unroll-and-jam)
  endif()
endif()

if(CW_X86)
  if(CRYPTOWORDS_ARCH STREQUAL "native")
    list(APPEND PERF_FLAGS -march=native -mtune=native)
    message(STATUS "Microarquitetura: native (x86)")
  elseif(CRYPTOWORDS_ARCH STREQUAL "x86-64-v4")
    list(APPEND PERF_FLAGS -march=x86-64-v4)
  elseif(CRYPTOWORDS_ARCH STREQUAL "x86-64-v3")
    list(APPEND PERF_FLAGS -march=x86-64-v3)
  elseif(CRYPTOWORDS_ARCH STREQUAL "x86-64-v2")
    list(APPEND PERF_FLAGS -march=x86-64-v2)
  elseif(CRYPTOWORDS_ARCH STREQUAL "generic")
    message(STATUS "Microarquitetura: generic")
  endif()
else()
  # ARM64 / Termux: usa tuning nativo quando disponível.
  if(CRYPTOWORDS_ARCH STREQUAL "native")
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-mcpu=native" HAS_MCPU_NATIVE)
    if(HAS_MCPU_NATIVE)
      list(APPEND PERF_FLAGS -mcpu=native -mtune=native)
    endif()
  endif()
  message(STATUS "Microarquitetura: ARM (${CMAKE_SYSTEM_PROCESSOR})")
endif()

# ---------- PGO ----------
if(CRYPTOWORDS_PGO STREQUAL "GENERATE")
  file(MAKE_DIRECTORY "${CRYPTOWORDS_PGO_DIR}")
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-fprofile-generate=${CRYPTOWORDS_PGO_DIR})
    add_link_options(-fprofile-generate=${CRYPTOWORDS_PGO_DIR})
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-fprofile-instr-generate=${CRYPTOWORDS_PGO_DIR}/default.profraw)
    add_link_options(-fprofile-instr-generate=${CRYPTOWORDS_PGO_DIR}/default.profraw)
  endif()
elseif(CRYPTOWORDS_PGO STREQUAL "USE")
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
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
elseif(CRYPTOWORDS_TSAN)
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
  add_link_options(-fsanitize=thread)
endif()

# =========================================================================
# Núcleo
# =========================================================================
set(CORE_SOURCES

    src/cli/parser.cpp
    src/cli/wordlist.cpp
    src/cli/validator.cpp

    src/search/optimizer.cpp
    src/search/reporter.cpp
    src/search/odometer.cpp
    src/search/pipeline.cpp
    src/search/engine.cpp
    src/search/checkpoint.cpp

    src/simd/factory.cpp

    src/hardware/host_probe.cpp
    src/hardware/hardware_advisor.cpp

    src/gpu/gpu_backend.cpp

    src/crypto/base58.cpp
    src/crypto/bip39.cpp
    src/crypto/ripemd160.cpp
    src/crypto/sha256.cpp
    src/crypto/keccak256.cpp
    src/crypto/hmac_sha512.cpp
)

add_library(criptowords_core OBJECT ${CORE_SOURCES})

target_include_directories(criptowords_core PUBLIC include)
target_include_directories(criptowords_core PRIVATE ${CMAKE_SOURCE_DIR}/include/gpu/hip)

target_link_libraries(criptowords_core PUBLIC
    CLI11::CLI11
    ${GMP_LIBRARIES}
)

target_compile_options(criptowords_core PRIVATE ${WARN_FLAGS} ${PERF_FLAGS})

if(CRYPTOWORDS_HAVE_HIP)
  target_compile_definitions(criptowords_core PRIVATE CRYPTOWORDS_HAVE_HIP=1)
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

if(CRYPTOWORDS_PCH)
  message(STATUS "PCH: ativado")
  target_precompile_headers(criptowords_core PRIVATE
        <algorithm>
        <array>
        <atomic>
        <chrono>
        <cstdint>
        <cstring>
        <format>
        <iostream>
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

# =========================================================================
# Objetos SIMD especializados
# =========================================================================
set(SIMD_OBJECTS "")

if(HAVE_SSE41)
    add_library(simd_sse OBJECT src/simd/factory_sse.cpp)
    target_include_directories(simd_sse PRIVATE include)
    target_link_libraries(simd_sse PRIVATE ${GMP_LIBRARIES})
    if(CW_X86)
      target_compile_options(simd_sse PRIVATE -msse4.1 ${WARN_FLAGS} ${PERF_FLAGS})
    else()
      # ARM/Termux: sem -msse4.1; o template usa fallback escalar interno.
      target_compile_options(simd_sse PRIVATE ${WARN_FLAGS} ${PERF_FLAGS})
    endif()
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_sse>)
endif()

if(HAVE_AVX2)
    add_library(simd_avx2 OBJECT src/simd/factory_avx2.cpp)
    target_include_directories(simd_avx2 PRIVATE include)
    target_link_libraries(simd_avx2 PRIVATE ${GMP_LIBRARIES})
    target_compile_options(simd_avx2 PRIVATE -mavx2 -mfma -mbmi -mbmi2 ${WARN_FLAGS} ${PERF_FLAGS})
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_avx2>)
endif()

if(HAVE_AVX512)
    add_library(simd_avx512 OBJECT src/simd/factory_avx512.cpp)
    target_include_directories(simd_avx512 PRIVATE include)
    target_link_libraries(simd_avx512 PRIVATE ${GMP_LIBRARIES})
    target_compile_options(simd_avx512 PRIVATE
        -mavx512f -mavx512dq -mavx512bw -mavx512vl -mavx512cd
        ${WARN_FLAGS} ${PERF_FLAGS})
    list(APPEND SIMD_OBJECTS $<TARGET_OBJECTS:simd_avx512>)
endif()

# =========================================================================
# Executável
# =========================================================================
add_executable(criptowords
    src/main.cpp
    $<TARGET_OBJECTS:criptowords_core>
    ${SIMD_OBJECTS}
)

if(CRYPTOWORDS_HAVE_HIP)
    add_dependencies(criptowords criptowords_hip_obj)
    target_sources(criptowords PRIVATE ${CRYPTOWORDS_HIP_OBJECT})
    target_link_libraries(criptowords PRIVATE ${CRYPTOWORDS_HIP_LIBS})
endif()

target_compile_options(criptowords PRIVATE ${WARN_FLAGS} ${PERF_FLAGS})
target_link_libraries(criptowords PRIVATE criptowords_core ${GMP_LIBRARIES})

# =========================================================================
# clang-format
# =========================================================================
find_program(CLANG_FORMAT_EXE clang-format)
if(CLANG_FORMAT_EXE)
  file(GLOB_RECURSE ALL_FORMAT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
    )
  add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXE} -i -style=file ${ALL_FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "clang-format..."
    )
  add_custom_target(check-format
        COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror -style=file ${ALL_FORMAT_SOURCES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Verificando formatação..."
    )
endif()

# =========================================================================
# Testes
# =========================================================================
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# =========================================================================
# Install / CPack
# =========================================================================
install(TARGETS criptowords RUNTIME DESTINATION bin)
install(DIRECTORY wordlist/ DESTINATION share/criptowords/wordlist OPTIONAL)
install(FILES README.md DESTINATION share/doc/criptowords OPTIONAL)

set(CPACK_PACKAGE_NAME "criptowords")
set(CPACK_PACKAGE_VENDOR "CriptoWords Core Team")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Motor Ultrarrápido de Recuperação de Mnemonics BIP39 em C++23")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_GENERATOR "TGZ;TXZ")

set(CPACK_DEBIAN_PACKAGE_NAME "criptowords")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Juliano Xavier Diniz <juliano.prog.dev@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include(CPack)
