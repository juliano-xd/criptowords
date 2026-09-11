# =====================================================================
# CriptoWords - High-Performance BIP39 Mnemonic Recovery Engine
# =====================================================================

# Compilador e Flags de Otimização Extrema (SIMD + Native Math)
CXX = g++
CXXFLAGS = -O3 -mavx2 -march=native -std=c++23 -Iinclude -Wall -Wextra -Wpedantic -Wno-deprecated-declarations
LDFLAGS = -lsecp256k1 -lOpenCL -pthread

# Diretórios
SRC_DIR = src
INC_DIR = include
OBJ_DIR = build
BIN_DIR = bin

# Arquivos de código-fonte e objetos
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Nome do executável
TARGET = $(BIN_DIR)/cryptowords

# Cores para o terminal (puramente estético)
GREEN = \033[1;32m
YELLOW = \033[1;33m
RESET = \033[0m

# Regra principal (default)
all: dir $(TARGET)

# Cria os diretórios necessários
dir:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Linkagem final
$(TARGET): $(OBJS)
	@echo "$(YELLOW)[+] Linkando o executável: $(TARGET)$(RESET)"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)[✓] Build concluído com sucesso! Execute com ./bin/cryptowords -h$(RESET)"

# Compilação dos objetos
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@echo "[+] Compilando $<"
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# Limpeza
clean:
	@echo "$(YELLOW)[+] Limpando os diretórios de build...$(RESET)"
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "$(GREEN)[✓] Limpo!$(RESET)"

# Reconstrução total
rebuild: clean all

.PHONY: all clean rebuild dir
