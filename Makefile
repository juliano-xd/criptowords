# ==============================================================================
# Makefile de Conveniência - CriptoWords
# ==============================================================================
# Detecta automaticamente Ninja ou Make para o backend de compilação.
# ==============================================================================

BUILD_DIR ?= build
NINJA := $(shell which ninja 2>/dev/null)
CMAKE ?= cmake
PYTHON ?= python3

# Gerador padrão: prioriza Ninja se disponível
ifeq ($(NINJA),)
  GENERATOR ?= "Unix Makefiles"
  BUILD_CMD ?= $(CMAKE) --build $(BUILD_DIR) -j
else
  GENERATOR ?= Ninja
  BUILD_CMD ?= ninja -C $(BUILD_DIR)
endif

# Cores ANSI
CYAN   := \033[1;36m
GREEN  := \033[1;32m
YELLOW := \033[1;33m
RESET  := \033[0m

.PHONY: all native release fast debug asan tsan cpu test check qa bench clean clean-all help

all: native

# Build Nativo (Máximo Throughput Local: -march=native + LTO + Mold)
native:
	@echo -e "$(CYAN)==> Configurando e compilando versão Nativa (-march=native + LTO)...$(RESET)"
	@$(CMAKE) -B $(BUILD_DIR) -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_NATIVE=ON -DCRYPTOWORDS_LTO=ON -DCRYPTOWORDS_GPU=ON
	@$(BUILD_CMD)
	@echo -e "$(GREEN)[✓] Build nativo concluído: $(BUILD_DIR)/criptowords$(RESET)"

# Build Portável Release (Compatível com qualquer CPU x86_64)
release:
	@echo -e "$(CYAN)==> Compilando versão Release Portável...$(RESET)"
	@$(CMAKE) -B build/release -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_NATIVE=OFF -DCRYPTOWORDS_LTO=ON
	@$(CMAKE) --build build/release -j
	@echo -e "$(GREEN)[✓] Build release concluído: build/release/criptowords$(RESET)"

# Build Rápido para Desenvolvimento (Sem LTO, link instantâneo com Mold)
fast:
	@echo -e "$(CYAN)==> Compilando versão de Desenvolvimento Rápido (sem LTO)...$(RESET)"
	@$(CMAKE) -B $(BUILD_DIR) -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_NATIVE=ON -DCRYPTOWORDS_LTO=OFF
	@$(BUILD_CMD)
	@echo -e "$(GREEN)[✓] Build rápido concluído: $(BUILD_DIR)/criptowords$(RESET)"

# Build de Depuração com Símbolos (-g3 -O0)
debug:
	@echo -e "$(CYAN)==> Compilando versão Debug...$(RESET)"
	@$(CMAKE) -B build/debug -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Debug -DCRYPTOWORDS_LTO=OFF
	@$(CMAKE) --build build/debug -j
	@echo -e "$(GREEN)[✓] Build debug concluído: build/debug/criptowords$(RESET)"

# Build com AddressSanitizer + UndefinedBehaviorSanitizer
asan:
	@echo -e "$(CYAN)==> Compilando com AddressSanitizer + UBSan...$(RESET)"
	@$(CMAKE) -B build/asan -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Debug -DCRYPTOWORDS_ASAN=ON -DCRYPTOWORDS_LTO=OFF
	@$(CMAKE) --build build/asan -j
	@echo -e "$(GREEN)[✓] Build ASan concluído: build/asan/criptowords$(RESET)"

# Build com ThreadSanitizer (Detecção de Condições de Corrida)
tsan:
	@echo -e "$(CYAN)==> Compilando com ThreadSanitizer...$(RESET)"
	@$(CMAKE) -B build/tsan -G $(GENERATOR) -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCRYPTOWORDS_TSAN=ON -DCRYPTOWORDS_LTO=OFF
	@$(CMAKE) --build build/tsan -j
	@echo -e "$(GREEN)[✓] Build TSan concluído: build/tsan/criptowords$(RESET)"

# Build exclusivo para CPU (sem dependências OpenCL)
cpu:
	@echo -e "$(CYAN)==> Compilando versão exclusiva para CPU (sem GPU)...$(RESET)"
	@$(CMAKE) -B build/cpu -G $(GENERATOR) -DCMAKE_BUILD_TYPE=Release -DCRYPTOWORDS_NATIVE=ON -DCRYPTOWORDS_GPU=OFF
	@$(CMAKE) --build build/cpu -j
	@echo -e "$(GREEN)[✓] Build CPU concluído: build/cpu/criptowords$(RESET)"

# Execução de Testes Automatizados via CTest
test: check

check: native
	@echo -e "$(CYAN)==> Executando testes automatizados (CTest)...$(RESET)"
	@ctest --test-dir $(BUILD_DIR) --output-on-failure

# Execução Completa da Bateria de Testes QA (85 casos)
qa: native
	@echo -e "$(CYAN)==> Executando bateria completa de QA em Python...$(RESET)"
	@$(PYTHON) tests/qa_suite.py $(BUILD_DIR)/criptowords

# Execução de Benchmark Nativo de Hardware
bench: native
	@echo -e "$(CYAN)==> Executando Benchmark de Hardware...$(RESET)"
	@./$(BUILD_DIR)/criptowords --benchmark

# Limpeza do diretório padrão de build
clean:
	@echo -e "$(YELLOW)==> Limpando diretório $(BUILD_DIR)...$(RESET)"
	@rm -rf $(BUILD_DIR)
	@echo -e "$(GREEN)[✓] Limpo.$(RESET)"

# Limpeza de todos os diretórios de build
clean-all:
	@echo -e "$(YELLOW)==> Limpando todos os diretórios de build...$(RESET)"
	@rm -rf build build/release build/native build/fast build/debug build/asan build/tsan build/cpu
	@echo -e "$(GREEN)[✓] Todos os builds removidos.$(RESET)"

# Ajuda / Catálogo de Comandos
help:
	@echo -e ""
	@echo -e "$(CYAN)CriptoWords - Comandos de Compilação & Automação$(RESET)"
	@echo -e "==================================================="
	@echo -e "  $(GREEN)make$(RESET) / $(GREEN)make native$(RESET)  : Compila versão otimizada (-march=native + LTO)"
	@echo -e "  $(GREEN)make fast$(RESET)         : Compilação rápida sem LTO (ideal p/ desenvolvimento)"
	@echo -e "  $(GREEN)make release$(RESET)      : Compila versão portável x86_64"
	@echo -e "  $(GREEN)make debug$(RESET)        : Compila versão de depuração (-g3)"
	@echo -e "  $(GREEN)make asan$(RESET)         : Compila com AddressSanitizer + UBSan"
	@echo -e "  $(GREEN)make tsan$(RESET)         : Compila com ThreadSanitizer (data races)"
	@echo -e "  $(GREEN)make cpu$(RESET)          : Compila versão pura de CPU (sem OpenCL)"
	@echo -e "  $(GREEN)make test$(RESET)         : Executa os testes via CTest"
	@echo -e "  $(GREEN)make qa$(RESET)           : Executa a suíte completa de QA em Python (85 casos)"
	@echo -e "  $(GREEN)make bench$(RESET)        : Executa o benchmark nativo de hardware"
	@echo -e "  $(GREEN)make clean$(RESET)        : Remove o diretório build/"
	@echo -e "  $(GREEN)make clean-all$(RESET)    : Remove todas as pastas de build"
	@echo -e ""
