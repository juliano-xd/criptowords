# CriptoWords v2.0

> **Motor C++23 de Alta Performance para Recuperação, Poda Analítica e Derivação de Frases Mnemônicas BIP-39 / BIP-44 (Bitcoin & Ethereum).**

O **CriptoWords** é uma ferramenta de engenharia reversa e recuperação de chaves criptográficas projetada para restaurar frases sementes (*seed phrases*) BIP-39 com palavras perdidas, corrompidas ou desconhecidas (`?`).

Diferente de ferramentas de força bruta convencionais que testam combinações de forma cega, o CriptoWords adota uma abordagem fundamentada em **Teoria da Informação e Poda Analítica em $\mathbb{F}_2^C$**. O motor analisa a estrutura algébrica do checksum do BIP-39 antes de despachar qualquer combinação para o gargalo computacional pesado (**PBKDF2 com 2048 rodadas de HMAC-SHA512**), descartando antecipadamente até **99,6%** do espaço de busca em nanossegundos via instruções nativas de hardware (**SHA-NI** e **SIMD AVX2/AVX-512**), com suporte opcional a aceleração por **GPU OpenCL** e modo cooperativo **Híbrido (CPU + GPU)**.

---

## Sumário

- [Visão Geral e Filosofia de Projeto](#visão-geral-e-filosofia-de-projeto)
- [Funcionalidades Detalhadas](#funcionalidades-detalhadas)
  - [1. Recuperação de Incógnitas e Poda Matemática](#1-recuperação-de-incógnitas-e-poda-matemática)
  - [2. Restrições Combinatórias e Afunilamento](#2-restrições-combinatórias-e-afunilamento)
  - [3. Suporte Multi-Idioma BIP-39 Oficial](#3-suporte-multi-idioma-bip-39-oficial)
  - [4. Suporte a Todos os Tamanhos de Frase (12 a 24 palavras)](#4-suporte-a-todos-os-tamanhos-de-frase-12-a-24-palavras)
  - [5. Derivação Criptográfica BIP-32 / BIP-44 (BTC e ETH)](#5-derivação-criptográfica-bip-32--bip-44-btc-e-eth)
  - [6. Filtro Precoce C1 (Rejeição em 32 bits)](#6-filtro-precoce-c1-rejeição-em-32-bits)
  - [7. Aceleração de Hardware: CPU SIMD e GPU OpenCL](#7-aceleração-de-hardware-cpu-simd-e-gpu-opencl)
  - [8. Estratégias de Afunilamento Heurístico](#8-estratégias-de-afunilamento-heurístico)
  - [9. Suíte de Benchmark e Profiling Integrada](#9-suíte-de-benchmark-e-profiling-integrada)
- [Compilação e Instalação](#compilação-e-instalação)
- [Guia de Uso e Exemplos Práticos Reais](#guia-de-uso-e-exemplos-práticos-reais)
- [Métricas Reais de Desempenho (Medidas em Hardware)](#métricas-reais-de-desempenho-medidas-em-hardware)
- [Fraquezas Conhecidas e Limitações Atuais](#fraquezas-conhecidas-e-limitações-atuais)
- [Metas de Futuras Otimizações (Roadmap Técnico)](#metas-de-futuras-otimizações-roadmap-técnico)
- [Licença](#licença)

---

## Visão Geral e Filosofia de Projeto

A especificação BIP-39 define a derivação da semente através de:
$$\text{Seed} = \text{PBKDF2}(\text{senha} = \text{frase mnemônica}, \text{salt} = \text{"mnemonic"} + \text{passphrase}, \text{rounds} = 2048, \text{prf} = \text{HMAC-SHA512})$$

Cada candidato requer **4.098 blocos de compressão SHA-512**. Em um espaço de apenas 2 palavras desconhecidas ($2048^2 = 4.194.304$ combinações), uma busca cega exigiria calcular mais de **17 bilhões de hashes SHA-512**.

O CriptoWords inverte esse paradigma através de três pilares:
1. **Poda Analítica em $\mathbb{F}_2^C$**: O checksum do BIP-39 consiste nos $C = N/3$ bits mais significativos de $\text{SHA256}(\text{entropia})$. Para qualquer topologia de incógnitas, o CriptoWords mapeia o espaço em classes de equivalência afins e resolve o checksum antes de tocar no PBKDF2, reduzindo o volume de cálculo em **16x (12 palavras)** até **256x (24 palavras)**.
2. **Zero-Copy e Fatiamento em Memória (N-Slices)**: As partes estáticas da frase mnemônica residem imutáveis no cache L1 da CPU. O odômetro sobrescreve apenas os deslocamentos dos bytes variáveis (*in-place patching*), eliminando concatenações de strings e chamadas de alocação de memória no loop crítico.
3. **Paralelismo em Camadas**: Vetorização SIMD na CPU (AVX-512, AVX2, SSE4.1 e SHA-NI) combinada com um pipeline assíncrono em GPU via OpenCL com *double-buffering* e sobreposição de DMA.

---

## Funcionalidades Detalhadas

### 1. Recuperação de Incógnitas e Poda Matemática
- **Dedução Reversa da Última Palavra ($w_{N-1} = ?$)**: Quando a última palavra da semente é desconhecida, seus $C$ bits de checksum são determinados unicamente pela entropia das palavras anteriores. O algoritmo deduz o checksum diretamente via hardware SHA-NI e sintetiza a palavra correta em $\mathcal{O}(1)$, sem testar palavras inválidas.
- **Pruning Analítico de Pares em $\mathbb{F}_2^C$ ($K=2$)**: Para 2 palavras perdidas em qualquer posição, o motor pré-computa o bloco base e sintetiza uma tabela de pares válidos antes do início da busca. Em 12 palavras, das 4.194.304 combinações possíveis, apenas **262.144** pares matematicamente válidos são processados (redução exata de 16x).
- **Poda Streaming ($K \ge 3$)**: Para 3 ou mais incógnitas, emprega geração sob demanda com descarte prévio de candidatos que não satisfazem o checksum, mantendo consumo de memória constante ($\mathcal{O}(1)$ em RAM).

### 2. Restrições Combinatórias e Afunilamento
- **Restrição de Não-Repetição (`--distinct`)**: Baseia-se no princípio de que a maioria dos geradores de carteira e usuários não repetem palavras em sementes curtas. Remove todas as palavras conhecidas das rodas de busca das incógnitas, eliminando centenas de milhares de ramificações inúteis.
- **Restrição Pontual (`--allow <pos>:<palavras>`)**: Permite restringir posições específicas a um subconjunto delimitado de palavras (ex: `--allow 10:desk|door|dog`). Inclui de-duplicação canônica e ordenação interna automática.
- **Busca em Modo Aberto (`--invalid_too`)**: Permite desativar a exigência de checksum válido caso a carteira de origem utilize regras customizadas ou caso o usuário queira auditar sementes com integridade corrompida.

### 3. Suporte Multi-Idioma BIP-39 Oficial
Suporte nativo e completo a todas as listas de palavras oficiais do padrão BIP-39, com detecção e normalização automática Unicode (NFC / NFD):
- **Inglês (`en`)** (Padrão)
- **Português (`pt`)**
- **Espanhol (`es`)** (com composição de acentos agudos)
- **Francês (`fr`)**
- **Italiano (`it`)**
- **Tcheco (`cs`)**
- **Japonês (`ja`)** (com suporte e preservação do caractere separador ideográfico `U+3000` / `\xE3\x80\x80`)
- **Coreano (`ko`)**
- **Chinês Simplificado (`zh` / `zh_cn`)**
- **Chinês Tradicional (`zh_tw`)**

### 4. Suporte a Todos os Tamanhos de Frase (12 a 24 palavras)
Detecção automática e configuração de limites com base na especificação BIP-39:

| Tamanho | Entropia | Checksum ($C$) | Fator de Poda Máximo ($\mathbb{F}_2^C$) |
| :---: | :---: | :---: | :---: |
| **12 palavras** | 128 bits | 4 bits | **16x** (93,75% de descarte) |
| **15 palavras** | 160 bits | 5 bits | **32x** (96,87% de descarte) |
| **18 palavras** | 192 bits | 6 bits | **64x** (98,43% de descarte) |
| **21 palavras** | 224 bits | 7 bits | **128x** (99,21% de descarte) |
| **24 palavras** | 256 bits | 8 bits | **256x** (99,61% de descarte) |

### 5. Derivação Criptográfica BIP-32 / BIP-44 (BTC e ETH)
- **Bitcoin (BTC)**:
  - Caminho de derivação padrão BIP-44: `m/44'/0'/0'/0/0`
  - Compressão de chave pública secp256k1 (33 bytes).
  - Hashing SHA-256 seguido de RIPEMD-160 (Hash160).
  - Codificação Base58Check com validação de checksum de 4 bytes.
- **Ethereum (ETH)**:
  - Caminho de derivação padrão BIP-44: `m/44'/60'/0'/0/0`
  - Chave pública não comprimida (65 bytes, descartando o prefixo `0x04`).
  - Hashing Keccak-256 nos 64 bytes de coordenadas $(X, Y)$ da curva.
  - Endereço hexadecimal de 20 bytes (40 caracteres hex com prefixo `0x`).
- **Passphrase BIP-39 Arbitrária (`--passphrase`)**: Suporte completo a carteiras protegidas com senha de extensão de semente (*salt* dinâmico).
- **Modo Derivação Direta**: Caso o usuário forneça a frase completa sem incógnitas e sem alvo (`--target`), o programa deriva e exibe instantaneamente os endereços gerados.

### 6. Filtro Precoce C1 (Rejeição em 32 bits)
Para evitar chamadas caras a `memcmp(20)` e reconstruções de string, o CriptoWords pré-computa um token de 32 bits correspondente aos primeiros 4 bytes do alvo decodificado:
```cpp
uint32_t ripemd_fast;
std::memcpy(&ripemd_fast, ripemd_buf, 4);
if (ripemd_fast != target_fast) return false; // Elimina 99.999% dos candidatos falsos em 1 instrução
return std::memcmp(ripemd_buf + 4, target_ripemd + 4, 16) == 0;
```

### 7. Aceleração de Hardware: CPU SIMD e GPU OpenCL
- **CPU SIMD Auto-Vectoring**:
  - **AVX-512**: Processamento de PBKDF2 em lote de 16 vias paralelas.
  - **AVX2 + FMA**: Processamento em lote de 8 vias paralelas.
  - **SSE4.1**: Processamento em lote de 4 vias paralelas.
  - **SHA-NI Nativo**: Instruções `_mm_sha256rnds2_epu32` executando verificações de checksum a mais de 3.500.000 ops/s por núcleo.
- **GPU OpenCL Pipelining**:
  - Kernel customizado de PBKDF2-HMAC-SHA512 compilado em runtime para a arquitetura alvo.
  - **Double-Buffering Assíncrono (Ping-Pong DMA)**: 2 slots de VRAM intercalados; enquanto o slot $0$ executa o kernel computacional na GPU, a CPU transfere o lote do slot $1$ via DMA e colhe os resultados do lote anterior.
  - **Detecção de Memória Unificada (Zero-Copy)**: Otimizado para APUs e GPUs integradas (Intel UHD/Iris, AMD Radeon 600M/700M/Vega), alocando buffers hospedeiros mapeados sem duplicação de tráfego PCI-e.
  - **Auto-Tuning de WorkGroup**: Seleção dinâmica de tamanho de lote e workgroup em múltiplos exatos de Wavefronts (Wave32 em RDNA, Wave64 em GCN/NVIDIA Warp).
- **Modo Híbrido Cooperativo (`--hybrid`)**: Permite que a GPU execute os lotes massivos em segundo plano enquanto a CPU executa seus núcleos SIMD AVX2 em paralelo.
- **Core Pinning em Linux**: Vinculação estrita de threads a núcleos físicos da CPU via `pthread_setaffinity_np`, prevenindo migrações de contexto pelo escalonador do kernel Linux.

### 8. Sondagem Profunda de Hardware e Auto-Tuning Adaptativo (`HostProbe` & `HardwareAdvisor`)
O CriptoWords incorpora um mecanismo avançado de inspeção arquitetural que sonda o computador hospedeiro antes da execução e calibra automaticamente os parâmetros ótimos:
- **Inspeção de CPU e Caches**:
  - Extração da *Brand String* e fabricante via CPUID (`AMD Zen 2/3/4/5`, `Intel Raptor/Arrow Lake`, `Xeon`, `Threadripper`, `EPYC`).
  - Mapeamento topológico: núcleos físicos reais, threads lógicas (SMT / Hyper-Threading), soquetes e nós NUMA.
  - Medição de hierarquia de caches: tamanhos de L1d, L1i, L2 e L3.
  - Detecção de silício criptográfico: **SHA-NI** (aceleração por hardware de SHA-256) e **Intel SHA-512** nativo.
- **Inspeção e Classificação de GPU**:
  - Detecção e categorização de todas as placas OpenCL instaladas (dGPU High-End, dGPU Mid-Range, iGPU SoC/APU).
  - Determinação do tamanho ótimo de Work-Group com base no Warp/Wavefront nativo (Wave32 para RDNA/NVIDIA vs Wave64 para GCN/CDNA).
  - Dimensionamento dinâmico de lotes de memória VRAM (*batch tuning*) para máxima ocupação sem *throttling*.
- **Auto-Tuning de Threads e Core Pinning**:
  - Ajusta dinamicamente a contagem de workers e ativa a afinidade fixa de núcleos físicos (`pthread_setaffinity_np`), prevenindo invalidação de cache L1/L2 por migração entre núcleos do sistema operacional (desativável via `--no-pin`).
- **Diagnóstico Completo de Hardware (`--host-info` / `--probe`)**:
  - Exibe um relatório técnico estruturado com todas as métricas do processador, memória, placas de vídeo e a recomendação de orquestração ótima para aquela máquina.

### 9. Estratégias de Afunilamento Heurístico
O parâmetro `--strategy` permite priorizar e reordenar as palavras das incógnitas com base em modelos probabilísticos:
- **`default`**: Varredura baseada estritamente em espaço afim $\mathbb{F}_2^C$.
- **`hamming`**: Gradiente de transições de bits e entropia de borda nos limites de 11 bits.
- **`frequency`**: Ponderação lexicográfica baseada na Lei de Zipf e extensão média de palavras.
- **`typo`**: Autômatos finitos de distância de edição de Levenshtein (`--max-distance`), calculando semelhança ortográfica contra palavras adjacentes.
- **Composições**: Combinações como `--strategy hamming,frequency` ou `--strategy hamming+typo`.

### 10. Suíte de Benchmark e Profiling Integrada
- **`--host-info` / `--probe`**: Exibe o diagnóstico completo do hardware hospedeiro (CPU, Topologia, Caches, ISA, GPUs, VRAM e auto-tuning recomendado) e finaliza.
- **`--benchmark`**: Avalia em tempo real a velocidade máxima de todos os subsistemas de hardware da máquina local (Checksum SHA-NI, PBKDF2 multithread, throughput de VRAM e kernel OpenCL, derivações secp256k1).
- **`--profile-gpu`**: Mede com precisão de nanossegundos via OpenCL Profiling Events a latência de transferência Host-to-Device (H2D), tempo de execução do kernel e largura de banda efetiva em GB/s.
- **`--list-gpus`**: Varre o subsistema OpenCL, listando placas dedicadas e integradas com pontuação de relevância heurística.

---

## Compilação e Instalação

### Pré-requisitos
- Compilador C++ com suporte a **C++23** (GCC 13+ ou Clang 16+).
- **CMake** versão 3.25 ou superior.
- **OpenCL** (Opcional, para aceleração por placa de vídeo): drivers proprietários NVIDIA, AMD ROCm/AMDGPU-PRO ou Mesa Rusticl/Clover.
- **pkg-config** (recomendado).

> **Compilação Otimizada por Padrão**:
> O sistema de build CMake habilita automaticamente **`-march=native -mtune=native`** e **Link-Time Optimization (`LTO / IPO`)** em compilações `Release`, garantindo que o compilador utilize todas as extensões do seu processador (AVX-512, AVX2, SHA-NI, BMI2) com inlining inter-procedural entre arquivos fonte.


> **Nota sobre Dependências**: O arquivo de build está configurado com **download automático via CMake FetchContent**. Se `libsecp256k1` ou `CLI11` não estiverem instalados no seu sistema operacional, o CMake baixará, configurará e compilará as bibliotecas oficiais do Bitcoin Core automaticamente durante a montagem do projeto!

### Passo a Passo de Compilação

```bash
# 1. Clone o repositório
git clone https://github.com/juliano-xd/criptowords.git
cd criptowords

# 2. Configure o build em modo Release
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 3. Compile utilizando todos os núcleos do processador
cmake --build build -j$(nproc)
```

O executável binário otimizado será gerado em `build/criptowords` (ou `./criptowords` caso execute o make na raiz).

---

## Guia de Uso e Exemplos Práticos Reais

### 1. Derivação Direta (Conferência de Endereço)
Caso possua todas as palavras e queira conferir o endereço gerado sem efetuar busca:
```bash
./criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut desk annual" --coin btc
```
*Gera o endereço Bitcoin correspondente:* `1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS`.

### 2. Recuperação de 1 Palavra Perdida no Fim (Dedução Instantânea em $\mathcal{O}(1)$)
A última palavra contém o checksum. O CriptoWords utiliza SHA-NI para derivar a palavra em menos de 0,06 segundos:
```bash
./criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 3. Recuperação de 2 Palavras Perdidas com Poda Analítica (16x mais rápida)
```bash
./criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS \
  --threads 4
```

### 4. Recuperação com Restrição de Não-Repetição (`--distinct`)
Caso tenha certeza de que as palavras que faltam não se repetem na semente:
```bash
./criptowords \
  --distinct \
  --mnemonics "arena huge owner legend diet smart spread truth file ? ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 5. Recuperação com Restrição Pontual (`--allow`)
Se você lembra anotações parciais das palavras perdidas:
```bash
./criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? annual" \
  --allow "10:desk|door|dog|dark" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 6. Recuperação de Carteira Ethereum com Passphrase
```bash
./criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --passphrase "MinhaSenhaSegura" \
  --coin eth \
  --target 0x71C8084A3B4380Dfc51F5FCE874b348EFeC0179F
```

### 7. Aceleração por GPU OpenCL e Seleção de Dispositivo
```bash
# Listar as placas de vídeo disponíveis no sistema
./criptowords --list-gpus

# Executar a busca acelerada por GPU
./criptowords \
  --gpu \
  --gpu-platform 0 --gpu-device 0 \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 8. Recuperação em Frases de 24 Palavras em Outros Idiomas (ex: Espanhol ou Japonês)
```bash
# Frase em Espanhol com acentuação
./criptowords \
  --lang es \
  --mnemonics "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ?" \
  --coin btc \
  --target 1...

# Frase em Japonês com separador U+3000
./criptowords \
  --lang ja \
  --mnemonics "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　?" \
  --coin btc \
  --target 1MKBt4zk1g9YeVKNxqkxreZJJhmrk3gCCf
```

### 9. Execução da Bateria de Benchmarks do Hardware
```bash
./criptowords --benchmark
```

### 10. Diagnóstico Arquitetural do Host e Auto-Tuning (`--host-info`)
```bash
./criptowords --host-info
```
*Exibe todas as características do processador (núcleos físicos, threads lógicas, SMT, caches L1/L2/L3, ISA criptográfica), capacidade de memória RAM, dispositivos OpenCL com Compute Index e a orquestração ótima recomendada para aquele hardware.*


---

## Métricas Reais de Desempenho (Medidas em Hardware)

Os números a seguir foram obtidos via medição direta em tempo real utilizando a suíte `--benchmark` no hardware de desenvolvimento:
- **Processador Host (CPU)**: AMD Ryzen 5 7520U (4 Núcleos / 8 Threads Zen 2 @ 2.80 - 4.30 GHz, com extensões AVX2, SSE4.1 e SHA-NI).
- **Processador Gráfico (GPU)**: AMD Radeon 610M Integrada (2 Compute Units RDNA2 @ 1899 MHz / VRAM compartilhada).

### 1. Poda Analítica de Checksum (Hardware SHA-NI)
| Operação | Iterações Testadas | Throughput | Latência Média |
| :--- | :---: | :---: | :---: |
| **BIP-39 Checksum Validation** | 1.000.000 | **3,56 Mop/s** | **280,80 ns/op** |

### 2. CPU Multithread PBKDF2-HMAC-SHA512 (2048 Rodadas)
| Threads Ativas | Chaves/Thread | Throughput Efetivo | Fator de Aceleração | Eficiência por Núcleo |
| :---: | :---: | :---: | :---: | :---: |
| **1 Thread** | 128 | **1.013,68 keys/s** | 1.00x | 100,0% |
| **2 Threads** | 128 | **1.847,38 keys/s** | 1.82x | 91,1% |
| **4 Threads** | 128 | **2.711,71 keys/s** | 2.68x | 66,9% |
| **8 Threads** | 128 | **3.900,59 keys/s** | 3.85x | 48,1% |

### 3. Aceleração por GPU OpenCL (Medição via Hardware Profiling Events)
*Dispositivo: `gfx1036` (Plataforma 0, Dispositivo 0 - 2 Compute Units / 1 WGP RDNA2)*:

| Tamanho do Lote | Latência H2D (ms) | Largura de Banda H2D | Tempo de Kernel (ms) | Vazão do Kernel | Throughput Efetivo |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1.024 chaves** | 0,041 ms | 3,30 GB/s | 301,22 ms | 3.400 keys/s | 3.400 keys/s |
| **2.048 chaves** | 0,068 ms | 3,96 GB/s | 596,72 ms | 3.430 keys/s | 3.430 keys/s |
| **4.096 chaves** | 0,159 ms | 3,41 GB/s | 1.147,03 ms | 3.570 keys/s | 3.570 keys/s |
| **8.192 chaves** | 0,216 ms | 5,01 GB/s | 875,36 ms | **9.360 keys/s** | **9.360 keys/s** |
| **16.384 chaves** | 0,576 ms | 3,76 GB/s | 1.769,50 ms | 9.260 keys/s | 9.260 keys/s |

*Dispositivo: `Radeon 610M (rusticl)` (Plataforma 1 - Mesa Zero-Copy Host Pointer)*:
- Largura de banda de transferência Host-to-Device (H2D) com memória unificada: **até 66,91 GB/s**.

### 4. Derivação Criptográfica BIP-32 / secp256k1 (com Filtro Precoce C1)
| Métrica | Valor Medido |
| :--- | :---: |
| **Derivações Completas BIP-32** | **16.403,18 derivações/s** |
| **Custo Médio Computacional** | **60,96 µs por chave candidata** |
| **Taxa de Descarte Precoce em C1** | **100,0%** (25.000 de 25.000 alvos descartados antes de `memcmp` ou codificação) |

---

## Fraquezas Conhecidas e Limitações Atuais

Com o objetivo de manter total transparência e rigor técnico, destacamos as limitações intrínsecas da implementação atual:

1. **Complexidade Intratável para $K \ge 4$ Incógnitas sem Restrições**:
   Apesar da redução matemática de até 256x proporcionada pelo checksum, o espaço combinatório para 4 palavras abertas sem restrições atinge $2048^4 / 16 \approx 1,09 \times 10^{12}$ chaves. A uma velocidade de ~10.000 chaves/segundo em hardware doméstico, a recuperação exigiria mais de **3 anos** de processamento ininterrupto. Buscas com 4 ou mais incógnitas só são viáveis caso o usuário utilize restrições com `--allow` ou `--distinct`.
2. **Custo Fixo Inviolável do PBKDF2 (BIP-39 Standard)**:
   O algoritmo PBKDF2 com 2048 rodadas foi deliberadamente projetado pelos autores do BIP-39 para ser lento contra ataques de força bruta. Nenhuma otimização de software ou hardware pode eliminar a dependência estrita entre as 2048 iterações de HMAC-SHA512 para um candidato válido.
3. **Mecanismo de Watchdog / TDR em Drivers Gráficos de Desktop**:
   Sistemas operacionais desktop (Linux com DRM e Windows) possuem temporizadores de detecção de travamento (TDR). Em GPUs integradas modestas (1 a 2 CUs), lotes de GPU superiores a 8.192 chaves podem exceder 1.500 ms de execução ininterrupta, acionando o reset do driver gráfico pelo sistema operacional. Por essa razão, o CriptoWords ajusta lotes conservadores automaticamente.
4. **Ausência de Alvos SegWit Nativo (Bech32 / Bech32m)**:
   A versão atual possui decodificadores e derivadores nativos para endereços **Bitcoin Legacy (P2PKH - formato `1...`)** e **Ethereum (`0x...`)**. Endereços SegWit nativos (P2WPKH `bc1q...`) e Taproot (P2TR `bc1p...`) utilizam caminhos de derivação BIP-84/BIP-86 e ainda não estão integrados como alvos automáticos de busca.
5. **Comprimento Máximo de Passphrase Limitado a 99 Caracteres**:
   Para permitir que o bloco de salt do PBKDF2 seja pré-computado e processado em um único bloco de compressão SHA-512 de 128 bytes no kernel OpenCL, a passphrase suporta até 99 caracteres ($8\text{ bytes de 'mnemonic'} + 99\text{ bytes} + 4\text{ bytes de índice} + 1\text{ byte de padding} = 112\text{ bytes} \le 112\text{ bytes do bloco SHA-512}$).

---

## Metas de Futuras Otimizações (Roadmap Técnico)

- [ ] **Derivação Secp256k1 Nativa na GPU**: Mover toda a derivação BIP-32 e geração de chave pública para dentro do kernel OpenCL (estilo *Keyhunt / vanitygen*), eliminando totalmente a necessidade de transferir as sementes de 64 bytes da VRAM para a CPU via barramento PCI-e.
- [ ] **Suporte a BIP-84 (Native SegWit Bech32) e BIP-86 (Taproot)**: Implementar decodificação e conferência rápida de endereços iniciados em `bc1q` e `bc1p`.
- [ ] **Filtro Cuckoo SIMD Multi-Alvo ($\mathcal{O}(1)$)**: Implementar uma estrutura de dados probabilística vetorial em memória para permitir que o usuário busque por centenas ou milhares de endereços simultaneamente sem perda de velocidade.
- [ ] **Backend de Computação via Vulkan / Metal**: Suporte a aceleração gráfica em plataformas sem drivers OpenCL robustos, como macOS (Apple Silicon via Metal) e Android (Termux via Vulkan Compute).
- [ ] **Bitslicing de SHA-512 em Software**: Implementar rota de bitslicing puro para arquiteturas sem vetores de 64 bits nativos, aumentando o paralelismo lógico em CPUs antigas.

---

## Licença

Distribuído sob licença MIT. Consulte o arquivo de licença correspondente para mais informações.
