# ==============================================================================
# Makefile de Automação & Alta Performance - CriptoWords
# ==============================================================================
# Backend: Detecta automaticamente Ninja (preferencial) ou Make.
# Linker:  Auto-detecção de mold / lld para linking ultrarrápido (< 1s).
# PCH:     Precompiled Headers ativados por padrão para aceleração de build C++23.
# ==============================================================================

BUILD_DIR ?= build
NINJA     := $(shell which ninja 2>/dev/null)
CMAKE     ?= cmake
PYTHON    ?= python3
CPACK     ?= cpack

# Gerador padrão: prioriza Ninja se disponível
ifeq ($(NINJA),)
  GENERATOR ?= "Unix Makefiles"
  BUILD_CMD ?= $(CMAKE) --build $(BUILD_DIR) -j
else
  GENERATOR ?= Ninja
  BUILD_CMD ?= ninja -C $(BUILD_DIR)
endif

# Cores ANSI para saída no terminal
BOLD   := \033[1m
CYAN   := \033[1;36m
GREEN  := \033[1;32m
YELLOW := \033[1;33m
BLUE   := \033[1;34m
MAGENTA:= \033[1;35m
RESET  := \033[0m

.PHONY: all native v3 v4 release fast debug asan tsan cpu pgo \
        test check qa bench format check-format package install clean clean-all help

all: native

# ------------------------------------------------------------------------------
# 🔨 COMPILAÇÃO E MICROARQUITETURAS
# ------------------------------------------------------------------------------

# Build Nativo (Máximo Throughput Local: -march=native + LTO + PCH)
native:
	@echo -e "$(CYAN)==> Configurando e compilando versão Nativa (-march=native + LTO + PCH)...$(RESET)"
	@$(CMAKE) -B $(BUILD_DIR) -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=native -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_PCH=ON -DCRYPTOWORDS_GPU=ON
	@$(BUILD_CMD)
	@echo -e "$(GREEN)[✓] Build nativo concluído: $(BUILD_DIR)/criptowords$(RESET)"

# Build Cloud x86-64-v3 (AVX2 + FMA + BMI2 - Ideal para instâncias em nuvem modernas)
v3:
	@echo -e "$(CYAN)==> Configurando e compilando versão Cloud x86-64-v3 (AVX2 + BMI2)...$(RESET)"
	@$(CMAKE) -B build/v3 -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=x86-64-v3 -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_PCH=ON -DCRYPTOWORDS_GPU=ON
	@$(CMAKE) --build build/v3 -j
	@echo -e "$(GREEN)[✓] Build x86-64-v3 concluído: build/v3/criptowords$(RESET)"

# Build Cloud x86-64-v4 (AVX-512 - Para servidores Xeon/EPYC de alta densidade)
v4:
	@echo -e "$(CYAN)==> Configurando e compilando versão Cloud x86-64-v4 (AVX-512)...$(RESET)"
	@$(CMAKE) -B build/v4 -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=x86-64-v4 -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_PCH=ON -DCRYPTOWORDS_GPU=ON
	@$(CMAKE) --build build/v4 -j
	@echo -e "$(GREEN)[✓] Build x86-64-v4 concluído: build/v4/criptowords$(RESET)"

# Build Portável Release (Compatível com qualquer CPU x86_64 baseline)
release:
	@echo -e "$(CYAN)==> Compilando versão Release Portável (x86_64 generic)...$(RESET)"
	@$(CMAKE) -B build/release -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=generic -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_PCH=ON
	@$(CMAKE) --build build/release -j
	@echo -e "$(GREEN)[✓] Build release portável concluído: build/release/criptowords$(RESET)"

# Build Rápido para Desenvolvimento (Sem LTO, link instantâneo com Mold + PCH)
fast:
	@echo -e "$(CYAN)==> Compilando versão de Desenvolvimento Rápido (sem LTO)...$(RESET)"
	@$(CMAKE) -B $(BUILD_DIR) -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=native -DCRYPTOWORDS_LTO=OFF -DCRYPTOWORDS_PCH=ON
	@$(BUILD_CMD)
	@echo -e "$(GREEN)[✓] Build rápido concluído: $(BUILD_DIR)/criptowords$(RESET)"

# Build Exclusivo para CPU (Sem dependências ou chamadas OpenCL)
cpu:
	@echo -e "$(CYAN)==> Compilando versão pura de CPU (sem suporte GPU/OpenCL)...$(RESET)"
	@$(CMAKE) -B build/cpu -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=native -DCRYPTOWORDS_GPU=OFF -DCRYPTOWORDS_LTO=ON
	@$(CMAKE) --build build/cpu -j
	@echo -e "$(GREEN)[✓] Build CPU concluído: build/cpu/criptowords$(RESET)"

# ------------------------------------------------------------------------------
# 🚀 OTIMIZAÇÃO EXTREMA: PROFILE-GUIDED OPTIMIZATION (PGO)
# ------------------------------------------------------------------------------

pgo:
	@echo -e "$(MAGENTA)==============================================================================$(RESET)"
	@echo -e "$(MAGENTA) ==> [PGO 1/3] Compilando com instrumentação de perfil (-fprofile-generate)...$(RESET)"
	@echo -e "$(MAGENTA)==============================================================================$(RESET)"
	@$(CMAKE) -B build/pgo -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=native -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_PCH=ON -DCRYPTOWORDS_PGO=GENERATE
	@$(CMAKE) --build build/pgo -j
	@echo -e "$(MAGENTA)==============================================================================$(RESET)"
	@echo -e "$(MAGENTA) ==> [PGO 2/3] Executando calibração e treinamento de branches de máquina...$(RESET)"
	@echo -e "$(MAGENTA)==============================================================================$(RESET)"
	@./build/pgo/test_sha512_comparison > /dev/null 2>&1 || true
	@./build/pgo/criptowords --benchmark > /dev/null 2>&1 || true
	@echo -e "$(MAGENTA)==============================================================================$(RESET)"
	@echo -e "$(MAGENTA) ==> [PGO 3/3] Recompilando com otimização guiada por perfil (-fprofile-use)...$(RESET)"
	@echo -e "$(MAGENTA)==============================================================================$(RESET)"
	@$(CMAKE) -B build/pgo -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_ARCH=native -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_PCH=ON -DCRYPTOWORDS_PGO=USE
	@$(CMAKE) --build build/pgo -j
	@echo -e "$(GREEN)[✓] Binário PGO ultra-otimizado gerado com sucesso: build/pgo/criptowords$(RESET)"

# ------------------------------------------------------------------------------
# 🔍 DEPURAÇÃO & ANÁLISE DINÂMICA (SANITIZERS)
# ------------------------------------------------------------------------------

# Build de Depuração com Símbolos (-g3 -O0)
debug:
	@echo -e "$(CYAN)==> Compilando versão Debug com símbolos completos (-g3)...$(RESET)"
	@$(CMAKE) -B build/debug -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Debug -DCRYPTOWORDS_LTO=OFF -DCRYPTOWORDS_PCH=ON
	@$(CMAKE) --build build/debug -j
	@echo -e "$(GREEN)[✓] Build debug concluído: build/debug/criptowords$(RESET)"

# AddressSanitizer + UndefinedBehaviorSanitizer
asan:
	@echo -e "$(YELLOW)==> Compilando com AddressSanitizer + UBSan...$(RESET)"
	@$(CMAKE) -B build/asan -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Debug -DCRYPTOWORDS_ASAN=ON -DCRYPTOWORDS_LTO=OFF
	@$(CMAKE) --build build/asan -j
	@echo -e "$(GREEN)[✓] Build ASan concluído: build/asan/criptowords$(RESET)"

# ThreadSanitizer (Detecção de Data Races)
tsan:
	@echo -e "$(YELLOW)==> Compilando com ThreadSanitizer...$(RESET)"
	@$(CMAKE) -B build/tsan -G $(GENERATOR) -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCRYPTOWORDS_TSAN=ON -DCRYPTOWORDS_LTO=OFF
	@$(CMAKE) --build build/tsan -j
	@echo -e "$(GREEN)[✓] Build TSan concluído: build/tsan/criptowords$(RESET)"

# ------------------------------------------------------------------------------
# 🧪 TESTES & BENCHMARKS
# ------------------------------------------------------------------------------

test: check

check: native
	@echo -e "$(CYAN)==> Executando bateria de testes automatizados (CTest)...$(RESET)"
	@ctest --test-dir $(BUILD_DIR) --output-on-failure

qa: native
	@echo -e "$(CYAN)==> Executando suíte completa de QA em Python (85 casos de teste)...$(RESET)"
	@$(PYTHON) tests/qa_suite.py $(BUILD_DIR)/criptowords

bench: native
	@echo -e "$(CYAN)==> Executando Benchmark Completo de Hardware & Criptografia...$(RESET)"
	@./$(BUILD_DIR)/criptowords --benchmark

# ------------------------------------------------------------------------------
# 🧹 QUALIDADE DE CÓDIGO & FORMATAÇÃO
# ------------------------------------------------------------------------------

format: native
	@echo -e "$(CYAN)==> Formatando código-fonte com clang-format...$(RESET)"
	@$(CMAKE) --build $(BUILD_DIR) --target format
	@echo -e "$(GREEN)[✓] Código formatado com sucesso.$(RESET)"

check-format: native
	@echo -e "$(CYAN)==> Verificando conformidade de formatação com clang-format...$(RESET)"
	@$(CMAKE) --build $(BUILD_DIR) --target check-format
	@echo -e "$(GREEN)[✓] Conformidade de formatação aprovada.$(RESET)"

# ------------------------------------------------------------------------------
# 📦 EMPACOTAMENTO & INSTALAÇÃO
# ------------------------------------------------------------------------------

package: native
	@echo -e "$(CYAN)==> Gerando pacotes de distribuição com CPack (.tar.gz, .tar.xz)...$(RESET)"
	@$(CPACK) --config $(BUILD_DIR)/CPackConfig.cmake -B $(BUILD_DIR)/package
	@echo -e "$(GREEN)[✓] Pacotes gerados em: $(BUILD_DIR)/package/$(RESET)"

install: native
	@echo -e "$(CYAN)==> Instalando binários e wordlists no sistema...$(RESET)"
	@$(CMAKE) --install $(BUILD_DIR)
	@echo -e "$(GREEN)[✓] Instalação concluída.$(RESET)"

# ------------------------------------------------------------------------------
# 🗑️ LIMPEZA & MANUTENÇÃO
# ------------------------------------------------------------------------------

clean:
	@echo -e "$(YELLOW)==> Limpando diretório padrão ($(BUILD_DIR))...$(RESET)"
	@rm -rf $(BUILD_DIR)
	@echo -e "$(GREEN)[✓] Diretório padrão limpo.$(RESET)"

clean-all:
	@echo -e "$(YELLOW)==> Limpando todos os diretórios de build gerados...$(RESET)"
	@rm -rf build build/v3 build/v4 build/release build/fast build/debug build/asan build/tsan build/cpu build/pgo
	@echo -e "$(GREEN)[✓] Todos os builds removidos.$(RESET)"

# ------------------------------------------------------------------------------
# 📖 CATÁLOGO DE AJUDA
# ------------------------------------------------------------------------------

help:
	@echo -e ""
	@echo -e "$(BOLD)$(CYAN)CriptoWords — Catálogo de Automação & Compilação$(RESET)"
	@echo -e "=================================================================="
	@echo -e "$(BOLD)🔨 Compilação & Microarquiteturas:$(RESET)"
	@echo -e "  $(GREEN)make$(RESET) / $(GREEN)make native$(RESET)   : Otimização nativa local (-march=native + LTO + PCH)"
	@echo -e "  $(GREEN)make v3$(RESET)             : Otimizado para Cloud x86-64-v3 (AVX2 + FMA + BMI2)"
	@echo -e "  $(GREEN)make v4$(RESET)             : Otimizado para Cloud x86-64-v4 (AVX-512)"
	@echo -e "  $(GREEN)make release$(RESET)        : Portável para qualquer CPU x86_64 generic"
	@echo -e "  $(GREEN)make fast$(RESET)           : Desenvolvimento rápido (sem LTO, link instantâneo)"
	@echo -e "  $(GREEN)make cpu$(RESET)            : Compilação exclusiva para CPU (sem dependência OpenCL)"
	@echo -e ""
	@echo -e "$(BOLD)🚀 Otimização Extrema:$(RESET)"
	@echo -e "  $(MAGENTA)make pgo$(RESET)            : Pipeline automatizado de Profile-Guided Optimization (3 etapas)"
	@echo -e ""
	@echo -e "$(BOLD)🔍 Depuração & Sanitizers:$(RESET)"
	@echo -e "  $(YELLOW)make debug$(RESET)          : Compilação com símbolos de depuração (-g3 -O0)"
	@echo -e "  $(YELLOW)make asan$(RESET)           : AddressSanitizer + UndefinedBehaviorSanitizer"
	@echo -e "  $(YELLOW)make tsan$(RESET)           : ThreadSanitizer (detecção de condições de corrida)"
	@echo -e ""
	@echo -e "$(BOLD)🧪 Testes & Benchmarks:$(RESET)"
	@echo -e "  $(BLUE)make test$(RESET) / $(BLUE)make check$(RESET): Bateria de testes automatizados via CTest"
	@echo -e "  $(BLUE)make qa$(RESET)             : Suíte completa de QA em Python (85 casos de teste)"
	@echo -e "  $(BLUE)make bench$(RESET)          : Benchmark completo de hardware e criptografia"
	@echo -e ""
	@echo -e "$(BOLD)🧹 Qualidade de Código:$(RESET)"
	@echo -e "  $(CYAN)make format$(RESET)         : Aplica clang-format a todos os arquivos C++"
	@echo -e "  $(CYAN)make check-format$(RESET)   : Valida conformidade do código com clang-format"
	@echo -e ""
	@echo -e "$(BOLD)📦 Empacotamento & Instalação:$(RESET)"
	@echo -e "  $(GREEN)make package$(RESET)        : Gera arquivos .tar.gz e .tar.xz via CPack"
	@echo -e "  $(GREEN)make install$(RESET)        : Instala binário e wordlists no sistema"
	@echo -e ""
	@echo -e "$(BOLD)🗑️ Limpeza:$(RESET)"
	@echo -e "  $(YELLOW)make clean$(RESET)          : Remove o diretório padrão build/"
	@echo -e "  $(YELLOW)make clean-all$(RESET)      : Remove todos os diretórios de build"
	@echo -e "=================================================================="
	@echo -e ""
