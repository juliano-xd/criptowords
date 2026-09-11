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
make          # Compila o motor do zero
make clean    # Limpa os diretórios de build
make rebuild  # Realiza uma reconstrução total
```
O executável ficará salvo em `./bin/cryptowords`.

## ⚙️ Interface de Linha de Comando (CLI)

O programa suporta argumentos extremamente flexíveis para configurar o modelo da carteira e a topologia matemática da sua busca:

| Parâmetro | Descrição | Exemplo / Padrão |
| :--- | :--- | :--- |
| `--mnemonics` | A frase semente separada por espaços. Use `?` para posições que você não lembra. | `"abandon ... ? ? about"` |
| `--target` | Endereço público de destino em Base58 (BTC) ou Hexadecimal (ETH). Obrigatório caso haja `?`. | `1A1zP1eP...` |
| `--allow` | Restringe as permutações de um `?` a palavras específicas separadas por `|` (base zero). | `"11:able|ability, 0:zoo"` |
| `--size` | Total de palavras do Mnemônico (12, 15, 18, 21, ou 24). | Padrão: `12` |
| `--coin` | Criptomoeda do endereço `--target` (`btc` ou `eth`). | Padrão: `btc` |
| `--lang` | Idioma oficial do BIP39 (`en`, `pt`, `es`, `fr`, etc). Deve possuir um .txt na pasta `wordlist/`. | Padrão: `en` |
| `--passphrase`| Aplica a 25ª palavra extra estipulada pelo usuário (salt extra no PBKDF2). | Padrão: (Vazio) |
| `--threads` | Quantidade de threads de CPU alocadas. Recomenda-se no máximo o Nº de núcleos físicos. | Padrão: Metade da CPU |
| `--rounds` | Rodadas do PBKDF2 (Customizável para brute-force em forks com parâmetros diferentes). | Padrão: `2048` |
| `--invalid_too` | Por padrão o motor burla/anula hashes corrompidos no Checksum. Habilite isso para testá-los. | (Flag booleana) |
| `--gpu` | Ativa o pipeline experimental OpenCL/GPU (Atualmente bypassado pela vetorização CPU SIMD). | (Flag booleana) |

## 🎮 Exemplos Práticos de Uso

### 1. Validar e Derivar uma Frase Intacta
Ideal para verificar se a frase (e passphrase) fornecem o endereço final desejado.
```bash
./bin/cryptowords --mnemonics "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

### 2. Recuperar Últimas Palavras (Modo Auto-Dedução Ativo)
Busca cega nas últimas 2 palavras. O motor ativará a Dedução Reversa e fará bilhões de cortes de Checksum sem tocar na Curva Elíptica.
```bash
./bin/cryptowords --mnemonics "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ? ?" \
  --target 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \
  --threads 8
```

### 3. Recuperação Dinâmica usando --allow e Customizações (ETH)
Busca Ethereum usando Mnemônico de 15 palavras. O usuário não se lembra da palavra 5 e da 6, mas tem certeza que a palavra 5 (índice 4) é `actor`, `able` ou `absent`.
```bash
./bin/cryptowords \
  --size 15 \
  --coin eth \
  --mnemonics "abandon abandon abandon abandon ? ? abandon abandon abandon abandon abandon abandon abandon abandon abandon" \
  --allow "4:actor|able|absent" \
  --target 0xSuaCarteiraEth...
```

## 🏗️ Estrutura Arquitetural (PIMPL & Clean Code)

A arquitetura do `v2.0` segue severos padrões de abstração para manter os loops rápidos (`inline`, vetorizados, *cache localized*) totalmente isolados:
- `include/bip39.hpp` -> Declarações da estrutura em memória e das lógicas de derivações.
- `src/bip39.cpp` -> Esconde a engenharia crua, limitando as re-compilações.
- `SearchOptimizer` -> Avalia a string, deduz complexidade O(N), destrincha o target matematicamente e devolve um *plano de voo* mastigado.
- `BruteForceEngine` -> Realiza despachos simultâneos nas filas SIMD, absorve interrupções e cuida apenas de matemática.

