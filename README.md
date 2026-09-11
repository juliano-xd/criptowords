# CriptoWords v2.0 - Motor de Busca BIP39

CriptoWords é um motor de força bruta e recuperação mnemônica BIP39 construído em **C++23** focado em altíssimo desempenho e eficiência criptográfica. Ele foi desenhado para contornar gargalos matemáticos durante a recuperação de frases semente perdidas (Bitcoin e Ethereum) utilizando vetorização de CPU (SIMD AVX2/AVX512), otimização de pipeline JIT (Just-in-Time) e *Early Rejection*.

## 🚀 Funcionalidades e Inovações

- **Vetorização SIMD (AVX2/AVX512)**: Implementação brutal e *lock-free* do PBKDF2-HMAC-SHA512. Em processadores AVX2, computa até 8 *rounds* inteiros de *hash* simultaneamente por núcleo físico (16 no AVX512), mitigando a maior barreira da recuperação de sementes (as famosas 2048 iterações).
- **Target Early Rejection (Corte O(1))**: Em vez de fazer uma lenta comparação em array byte a byte do alvo final (`memcmp`), o programa *faz engenharia reversa visual* do Endereço Target (Base58/Hex) antes do motor inicializar. Um *token* de 32-bits é extraído para realizar saltos condicionais nos registradores do processador. O motor aborta os endereços falsos em um ciclo de relógio (99.9999% dos casos).
- **Auto-Dedução de Checksum Reverso**: Se as posições da frase fornecidas tiverem vazios, a palavra que carrega o *checksum* é inteiramente deduzida validando sub-blocos reversos de SHA256 sem invocar processamentos desnecessários em PBKDF2.
- **Isolamento de Curva Elíptica Avançado**: Utiliza o core oficial padrão `libsecp256k1` otimizado para lidar com a matemática restrita da criptografia. O Motor foi escrito visando evitar instanciações e contextos de memória em loop fechado, deixando o *Heap* intocável durante bilhões de testes.

## 🛠️ Requisitos de Instalação

Para compilar, o ambiente precisa possuir os pacotes de cabeçalho da *libsecp256k1* e *OpenCL* (para os headers passivos, embora todo o motor atual extraia processamento direto via vetorização de CPU nativa). 

No Ubuntu/Debian Linux:
```bash
sudo apt-get update
sudo apt-get install build-essential g++ libsecp256k1-dev opencl-headers ocl-icd-opencl-dev
```

## 🔨 Compilação

O projeto foi modernizado com um `Makefile` configurado para abstrair toda complexidade do GCC e ativar máxima flag `-O3` com arquitetura `-march=native`.

```bash
# Para compilar o motor do zero
make

# Para limpar o projeto e binários antigos
make clean

# Para reconstrução total
make rebuild
```
O executável ficará salvo como `./bin/cryptowords`.

## 🎮 Como Usar (Exemplos)

A interface de linha de comando (`CLI`) foi redesenhada para permitir o uso de posições curingas ("?") no meio ou no fim da Mnemônica.

### 1. Testando e Gerando um endereço simples
```bash
./bin/cryptowords --mnemonics "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

### 2. Tentando Recuperar Palavras Perdidas (Brute-Force)
Para recuperar palavras no final da frase (com 2 incógnitas e a carteira `1A1zP1eP...` como alvo):
```bash
./bin/cryptowords --mnemonics "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ? ?" --target 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --threads 8
```

### 3. Recuperação Dinâmica para Ethereum (Tamanho Customizável)
```bash
./bin/cryptowords --size 15 --mnemonics "abandon abandon abandon abandon ? ? abandon abandon abandon abandon abandon abandon abandon abandon abandon" --target 0xYourEthAddress --coin eth
```

## 🏗️ Estrutura Arquitetural (PIMPL & Clean Code)

A arquitetura do `v2.0` segue severos padrões de abstração para manter os loops rápidos (`inline`, vetorizados, *cache localized*) totalmente isolados:
- `include/bip39.hpp` -> Declarações da estrutura em memória e das lógicas de derivações. Otimizado para não vazar lógicas pesadas para os demais processadores.
- `src/bip39.cpp` -> Esconde a engenharia crua, limitando as re-compilações e permitindo isolamento das bibliotecas pesadas de criptografia.
- `SearchOptimizer` -> Avalia a string, deduz complexidade O(N), destrincha o target matematicamente e devolve para as threads um *plano de voo* `OptimizedMnemonics` já mastigado e perfeitamente dimensionado.
- `BruteForceEngine` -> Alojado sob as chamadas do Odometer. Realiza despachos simultâneos nas filas SIMD, absorve interrupções e cuida apenas de matemática (0 requisições dinâmicas de memória ao SO ao longo de toda execução).

