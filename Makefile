# Makefile para Cryptowords

# Compilador e Flags
CXX = g++
CXXFLAGS = -O3 -mavx2 -march=native -std=c++23 -Iinclude -Wall -Wextra
LDFLAGS = -lsecp256k1 -lOpenCL -pthread

# Diretórios
SRC_DIR = src
INC_DIR = include
OBJ_DIR = build
BIN_DIR = bin

# Arquivos de código-fonte
SRCS = $(wildcard $(SRC_DIR)/*.cpp)

# Gerar lista de objetos substituindo .cpp por .o e prefixando o build folder
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Nome do executável
TARGET = $(BIN_DIR)/cryptowords

# Regra principal
all: dir $(TARGET)

# Criar os diretórios se não existirem
dir:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Compilar e linkar o executável
$(TARGET): $(OBJS)
	@echo "Linkando o executável: $(TARGET)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)


# Compilar objetos SIMD com flags AVX512 (as funcoes fazem dispatch dynamico)
$(OBJ_DIR)/sha256_simd.o: $(SRC_DIR)/sha256_simd.cpp
	@echo "Compilando $< com AVX512"
	$(CXX) $(CXXFLAGS) -mavx512f -mavx512vl -c $< -o $@

$(OBJ_DIR)/sha512_simd.o: $(SRC_DIR)/sha512_simd.cpp
	@echo "Compilando $< com AVX512"
	$(CXX) $(CXXFLAGS) -mavx512f -mavx512vl -c $< -o $@

# Compilar objetos
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@echo "Compilando $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Limpeza
clean:
	@echo "Limpando os binários..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Alias para reconstrução total
rebuild: clean all

.PHONY: all clean rebuild dir
