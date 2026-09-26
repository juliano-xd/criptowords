# CriptoWords v2.0

> **Motor C++23 de Alta Performance para Recuperação, Poda Analítica e Derivação de Frases Mnemônicas BIP-39 / BIP-44 (Bitcoin & Ethereum).**

O **CriptoWords** é uma ferramenta de engenharia reversa e recuperação de chaves criptográficas projetada para restaurar frases sementes (*seed phrases*) BIP-39 com palavras perdidas, corrompidas ou desconhecidas (`?`).

Diferente de ferramentas de força bruta convencionais que testam combinações de forma cega, o CriptoWords adota uma abordagem fundamentada em **Teoria da Informação e Poda Analítica em $\mathbb{F}_2^C$**. O motor analisa a estrutura algébrica do checksum do BIP-39 antes de despachar qualquer combinação para o gargalo computacional pesado (**PBKDF2 com 2048 rodadas de HMAC-SHA512**), descartando antecipadamente até **99,6%** do espaço de busca em nanossegundos via instruções nativas de hardware (**SHA-NI**, **SIMD AVX2** e **AVX-512**), com suporte a aceleração massiva por **GPU OpenCL** e modo cooperativo **Híbrido (CPU + GPU)**.

---

## Sumário

- [Visão Geral e Filosofia de Projeto](#visão-geral-e-filosofia-de-projeto)
- [Funcionalidades Detalhadas](#funcionalidades-detalhadas)
  - [1. Recuperação de Incógnitas e Poda Matemática em $\mathbb{F}_2^C$](#1-recuperação-de-incógnitas-e-poda-matemática-em-mathbbf_2c)
  - [2. Restrições Combinatórias e Afunilamento](#2-restrições-combinatórias-e-afunilamento)
  - [3. Suporte Multi-Idioma BIP-39 Oficial com Unicode NFC/NFD](#3-suporte-multi-idioma-bip-39-oficial-com-unicode-nfcnfd)
  - [4. Suporte a Todos os Tamanhos de Frase (12 a 24 palavras)](#4-suporte-a-todos-os-tamanhos-de-frase-12-a-24-palavras)
  - [5. Derivação Criptográfica BIP-32 / BIP-44 (BTC e ETH)](#5-derivação-criptográfica-bip-32--bip-44-btc-e-eth)
  - [6. Filtro Precoce C1-64 (Rejeição em 64 bits em 1 ciclo)](#6-filtro-precoce-c1-64-rejeição-em-64-bits-em-1-ciclo)
  - [7. Aceleração de Hardware: CPU SIMD e GPU OpenCL](#7-aceleração-de-hardware-cpu-simd-e-gpu-opencl)
  - [8. Otimizações de Microarquitetura e Cache L1i / $\mu$OP](#8-otimizações-de-microarquitetura-e-cache-l1i--muop)
  - [9. Sondagem Profunda de Hardware e Auto-Tuning Adaptativo (`HostProbe`)](#9-sondagem-profunda-de-hardware-e-auto-tuning-adaptativo-hostprobe)
  - [10. Suíte de Benchmark de 8 Capítulos (`--benchmark`)](#10-suíte-de-benchmark-de-8-capítulos---benchmark)
- [Compilação e Instalação](#compilação-e-instalação)
- [Guia de Uso e Exemplos Práticos Reais](#guia-de-uso-e-exemplos-práticos-reais)
- [Métricas Reais de Desempenho e Comparativo de Hardware](#métricas-reais-de-desempenho-e-comparativo-de-hardware)
  - [1. Máquina Local (AMD Ryzen 5 7520U + Radeon 610M)](#1-máquina-local-amd-ryzen-5-7520u--radeon-610m)
  - [2. Servidor Cloud Vast.ai (Intel Xeon Platinum 8180M + NVIDIA RTX A4000)](#2-servidor-cloud-vastai-intel-xeon-platinum-8180m--nvidia-rtx-a4000)
  - [3. Comparativo de Throughput: Commit 68570d3 vs Versão Atual](#3-comparativo-de-throughput-commit-68570d3-vs-versão-atual)
  - [4. Teste de Busca Real em Lote Massivo (2 Incógnitas = 4.194.304 Chaves)](#4-teste-de-busca-real-em-lote-massivo-2-incógnitas--4194304-chaves)
- [Garantia de Qualidade e Suíte de Testes (QA Suite)](#garantia-de-qualidade-e-suíte-de-testes-qa-suite)
- [Fraquezas Conhecidas e Limitações Atuais](#fraquezas-conhecidas-e-limitações-atuais)
- [Metas de Futuras Otimizações (Roadmap Técnico)](#metas-de-futuras-otimizações-roadmap-técnico)
- [Licença](#licença)

---

## Visão Geral e Filosofia de Projeto

A especificação oficial BIP-39 define a derivação da semente mestre através de:
$$\text{Seed} = \text{PBKDF2}(\text{senha} = \text{frase mnemônica}, \text{salt} = \text{\"mnemonic\"} + \text{passphrase}, \text{rounds} = 2048, \text{prf} = \text{HMAC-SHA512})$$

Cada candidato requer **4.098 blocos de compressão SHA-512**. Em um espaço de busca com apenas 2 palavras desconhecidas ($2048^2 = 4.194.304$ combinações), uma busca cega convencional exigiria calcular mais de **17,1 bilhões de blocos SHA-512**, tornando o processo inviável em computadores comuns.

O CriptoWords inverte esse paradigma por meio de três pilares fundamentais:
1. **Poda Analítica em $\mathbb{F}_2^C$**: O checksum do BIP-39 consiste nos $C = N/3$ bits mais significativos de $\text{SHA256}(\text{entropia})$. Para qualquer topologia de incógnitas, o CriptoWords resolve o checksum antes de tocar no PBKDF2, reduzindo o volume de cálculo em **16x (12 palavras)** até **256x (24 palavras)**.
2. **Zero-Copy e Fatiamento em Memória (N-Slices)**: As partes conhecidas da frase mnemônica residem imutáveis no cache L1 da CPU. O odômetro sobrescreve apenas os deslocamentos dos bytes das palavras incógnitas (*in-place patching*), eliminando concatenações de strings e chamadas de alocação de memória no loop crítico.
3. **Paralelismo em Camadas e Microarquitetura Estrita**:
   - Vetorização SIMD na CPU (**AVX-512**, **AVX2**, **SSE4.1** e **SHA-NI**).
   - Dimensionamento de loops para caber **100% no $\mu$OP Cache** e no **Cache L1 de Instruções (32 KB)**.
   - Fixação estrita de afinidade a núcleos físicos reais (`HostProbe::get_physical_cpu_ids`), eliminando penalidades de SMT.
   - Suporte a aceleração assíncrona por GPU OpenCL com *double-buffering* e modo cooperativo **Híbrido**.

---

## Funcionalidades Detalhadas

### 1. Recuperação de Incógnitas e Poda Matemática em $\mathbb{F}_2^C$
- **Dedução Reversa da Última Palavra ($w_{N-1} = ?$)**: Quando a última palavra da semente é desconhecida, seus $C$ bits de checksum são determinados unicamente pela entropia das palavras anteriores. O algoritmo deduz o checksum diretamente via hardware SHA-NI e sintetiza a palavra correta em $\mathcal{O}(1)$, sem testar palavras inválidas.
- **Pruning Analítico de Pares em $\mathbb{F}_2^C$ ($K=2$)**: Para 2 palavras perdidas em qualquer posição, o motor pré-computa o bloco base e sintetiza uma tabela de pares válidos antes do início da busca. Em 12 palavras, das 4.194.304 combinações possíveis, apenas **262.144** pares matematicamente válidos são processados (redução exata de 16x).
- **Poda Streaming e Dedução Cascata ($K \ge 3$)**: Para 3 ou mais incógnitas, emprega geração sob demanda com descarte prévio de candidatos que não satisfazem o checksum, mantendo consumo de memória constante ($\mathcal{O}(1)$ em RAM) e saltos instantâneos de subárvores.

### 2. Restrições Combinatórias e Afunilamento
- **Restrição de Não-Repetição (`--distinct`)**: Baseia-se no princípio de que a maioria dos geradores de carteira e usuários não repetem palavras em sementes curtas. Remove todas as palavras conhecidas das rodas de busca das incógnitas, eliminando centenas de milhares de ramificações inúteis via poda de subárvores (*subtree skipping*).
- **Restrição Pontual (`--allow <pos>:<palavras>`)**: Permite restringir posições específicas a um subconjunto delimitado de palavras (ex: `--allow 10:desk|door|dog`). Inclui de-duplicação canônica e ordenação interna automática.
- **Busca em Modo Aberto (`--invalid_too`)**: Permite desativar a exigência de checksum válido caso a carteira de origem utilize regras customizadas ou caso o usuário queira auditar sementes com integridade corrompida.

### 3. Suporte Multi-Idioma BIP-39 Oficial com Unicode NFC/NFD
Suporte nativo e completo a todas as listas de palavras oficiais do padrão BIP-39, com detecção e normalização automática Unicode:
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

| Tamanho | Entropia | Checksum ($C$) | Fator de Poda Máximo ($\mathbb{F}_2^C$) | Espaço Bruto ($2048^K$) | Espaço Pós-Poda ($K=2$) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **12 palavras** | 128 bits | 4 bits | **16x** (93,75% de descarte) | 4.194.304 | 262.144 |
| **15 palavras** | 160 bits | 5 bits | **32x** (96,87% de descarte) | 4.194.304 | 131.072 |
| **18 palavras** | 192 bits | 6 bits | **64x** (98,43% de descarte) | 4.194.304 | 65.536 |
| **21 palavras** | 224 bits | 7 bits | **128x** (99,21% de descarte) | 4.194.304 | 32.768 |
| **24 palavras** | 256 bits | 8 bits | **256x** (99,61% de descarte) | 4.194.304 | **16.384** |

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

### 6. Filtro Precoce C1-64 (Rejeição em 64 bits em 1 ciclo)
Para evitar chamadas desnecessárias a `memcmp(20)` e reconstruções de string, o CriptoWords pré-computa um token de 64 bits correspondente aos primeiros 8 bytes do alvo decodificado:
```cpp
uint64_t ripemd_fast64;
std::memcpy(&ripemd_fast64, ripemd_buf.data(), 8);
if (__builtin_expect(ripemd_fast64 != target_fast64, 1)) return false; // Probabilidade de falso positivo: 2^-64
return std::memcmp(ripemd_buf.data() + 8, target_ripemd + 8, 12) == 0;
```

### 7. Aceleração de Hardware: CPU SIMD e GPU OpenCL
- **CPU SIMD Auto-Vectoring**:
  - **AVX-512**: Processamento de PBKDF2 em lote de 16 vias paralelas (vetores ZMM de 512 bits) com rotações em 1 ciclo (`vprorq`) e lógica ternária (`vpternlogq`).
  - **AVX2 + FMA**: Processamento em lote de 8 vias paralelas (vetores YMM de 256 bits).
  - **SSE4.1**: Processamento em lote de 4 vias paralelas (vetores XMM de 128 bits).
  - **SHA-NI Nativo**: Instruções `_mm_sha256rnds2_epu32` executando verificações de checksum a mais de **10,30 Mop/s**.
- **GPU OpenCL Pipelining**:
  - Kernel customizado de PBKDF2-HMAC-SHA512 compilado em runtime para a arquitetura alvo.
  - **Double-Buffering Assíncrono (Ping-Pong DMA)**: 2 slots de VRAM intercalados; enquanto um slot executa na GPU, a CPU transfere o próximo lote e colhe os resultados do anterior.
  - **Detecção de Memória Unificada (Zero-Copy)**: Otimizado para APUs e GPUs integradas (Intel UHD/Iris, AMD Radeon 600M/700M/Vega), com largura de banda de até **66,91 GB/s**.
- **Modo Híbrido Cooperativo (`--hybrid`)**: Combina CPU e GPU simultaneamente, atingindo **16.728 keys/s** na máquina local e **~405.000 keys/s** no servidor com GPU dedicada.

### 8. Otimizações de Microarquitetura e Cache L1i / $\mu$OP
- **Adequação Estrita ao $\mu$OP Cache**: Remoção do unrolling forçado (`#pragma GCC unroll 80/16`) nas rotinas de bloco do SHA-512, reduzindo a pegada de código de cada função de **22,8 KB** para **5,3 KB**. O loop do PBKDF2 de 2048 iterações passa a residir **100% dentro do Cache de Instruções L1i (32 KB)** e do $\mu$OP Cache, eliminando paradas de decodificação no pipeline.
- **Afinidade de Núcleos Físicos Reais (`HostProbe::get_physical_cpu_ids`)**: Identificação precisa dos núcleos físicos primários via `/sys/devices/system/cpu/cpu*/topology/core_id` e aplicação de `pthread_setaffinity_np`. A contenção de recursos do SMT (Hyper-Threading) é eliminada, derrubando o jitter multithread de **69,3%** para **14,7%**.
- **Curva Elíptica Secp256k1 via Tabela Comb de 8 bits Constexpr**: Geração em tempo de compilação da tabela de pontos da curva secp256k1 alinhada em cache L1D, substituindo o algoritmo clássico de 128 adições por apenas 32 adições mistas afins (redução de 17,19 µs para **12,97 µs por chave pública**).

### 9. Sondagem Profunda de Hardware e Auto-Tuning Adaptativo (`HostProbe`)
- Extração automática de fabricante, modelo, frequências e topologia de processador (`Zen 2/3/4/5`, `Intel Core/Xeon`).
- Medição exata da hierarquia de memórias cache L1d, L1i, L2 e L3.
- Detecção e classificação de todas as GPUs OpenCL disponíveis no sistema com pontuação de relevância.
- Relatório técnico estruturado via `--host-info` com recomendação automática da melhor orquestração de hardware.

### 10. Suíte de Benchmark de 8 Capítulos (`--benchmark`)
A suíte de benchmark integrada foi reestruturada em 8 capítulos com precisão de ciclos de clock TSC e latências em nanossegundos:
- **`[1/8] Hardware & Capacidades Detectadas do Host`**: Detecção de CPU, topologia, extensões SIMD e aceleradores OpenCL.
- **`[2/8] Criptografia BIP-39 & SHA-256 (SHA-NI vs Escalar)`**: Throughput de checksum, jitter e microbenchmark de blocos de 64 bytes com SHA-NI.
- **`[3/8] CPU PBKDF2-HMAC-SHA512 (SIMD Multi-Way, Ciclos TSC & Jitter)`**: Desempenho escalar vs vetorial, ciclos por chave e escalabilidade multithread.
- **`[4/8] GPU OpenCL Profiling (Largura de Banda, Saturação & Estabilidade)`**: Latências H2D/Kernel/D2H medidas via OpenCL Hardware Events para lotes de 1.024 a 16.384 chaves.
- **`[5/8] Arquitetura de Curva Elíptica SECP256K1 & F_p (SECP vs UInt<4>)`**: Microbenchmarks de adição escalar, multiplicação, quadratura, inversão modular $a^{p-2} \pmod p$ e criação de chave pública Comb 8-bit.
- **`[6/8] Encoding de Redes & Hashing (Bitcoin Hash160 vs Ethereum Keccak-256)`**: Comparativo de custo de derivação de endereço BTC vs ETH e throughput de BIP-32/44.
- **`[7/8] Benchmark: SHA-512 Streaming vs Template (Preset/Complete)`**: Eficiência e conformidade bit a bit entre rota streaming e pré-computada.
- **`[8/8] Motor Integrado & Modo Híbrido Cooperativo`**: Vazão física combinada CPU+GPU, projeções de tempo de busca e recomendações de hardware.

---

## Compilação e Instalação

### Pré-requisitos
- Compilador C++ com suporte a **C++23** (GCC 13+ ou Clang 16+).
- **CMake** versão 3.25 ou superior.
- **OpenCL** (Opcional, para aceleração por placa de vídeo): drivers proprietários NVIDIA, AMD ROCm/AMDGPU-PRO ou Mesa Rusticl/Clover.
- **pkg-config** (recomendado).

> **Compilação Otimizada por Padrão**:
> O sistema de build CMake habilita automaticamente **`-march=native -mtune=native`** e **Link-Time Optimization (`LTO / IPO`)** em compilações `Release`, garantindo que o compilador utilize todas as extensões do seu processador (AVX-512, AVX2, SHA-NI, BMI2) com inlining inter-procedural entre arquivos fonte.

> **Download Automático de Dependências**: Se `libsecp256k1` ou `CLI11` não estiverem presentes no sistema operacional, o CMake baixará, configurará e compilará as bibliotecas oficiais do Bitcoin Core automaticamente via `FetchContent`.

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

O binário executável otimizado será gerado em `build/criptowords`.

---

## Guia de Uso e Exemplos Práticos Reais

### 1. Derivação Direta (Conferência de Endereço)
Caso possua todas as palavras e queira conferir o endereço gerado sem efetuar busca:
```bash
./build/criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut desk annual" --coin btc
```
*Gera o endereço Bitcoin correspondente:* `1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS`.

### 2. Recuperação de 1 Palavra Perdida no Fim (Dedução Instantânea em $\mathcal{O}(1)$)
A última palavra contém o checksum. O CriptoWords utiliza SHA-NI para derivar a palavra em menos de 0,01 segundos:
```bash
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 3. Recuperação de 2 Palavras Perdidas com Poda Analítica (16x mais rápida)
```bash
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS \
  --threads 4
```

### 4. Recuperação com Restrição de Não-Repetição (`--distinct`)
Caso tenha certeza de que as palavras que faltam não se repetem na semente:
```bash
./build/criptowords \
  --distinct \
  --mnemonics "arena huge owner legend diet smart spread truth file ? ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 5. Recuperação com Restrição Pontual (`--allow`)
Se você lembra anotações parciais das palavras perdidas:
```bash
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? annual" \
  --allow "10:desk|door|dog|dark" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 6. Recuperação de Carteira Ethereum com Passphrase
```bash
./build/criptowords \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut desk ?" \
  --passphrase "MinhaSenhaSegura" \
  --coin eth \
  --target 0x71C8084A3B4380Dfc51F5FCE874b348EFeC0179F
```

### 7. Aceleração por GPU OpenCL e Seleção de Dispositivo
```bash
# Listar as placas de vídeo disponíveis no sistema
./build/criptowords --list-gpus

# Executar a busca acelerada por GPU
./build/criptowords \
  --gpu \
  --gpu-platform 0 --gpu-device 0 \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 8. Recuperação em Modo Híbrido Cooperativo (CPU + GPU)
Utiliza simultaneamente a CPU (via SIMD AVX2/AVX-512) e a GPU (via OpenCL) para vazão máxima de computação:
```bash
./build/criptowords \
  --hybrid \
  --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" \
  --coin btc \
  --target 1BZg39dxtDkvf7UQvWpzBHRTixBUvURmyS
```

### 9. Execução da Bateria de Benchmarks do Hardware
```bash
./build/criptowords --benchmark
```

### 10. Diagnóstico Arquitetural do Host e Auto-Tuning (`--host-info`)
```bash
./build/criptowords --host-info
```

---

## Métricas Reais de Desempenho e Comparativo de Hardware

As tabelas a seguir refletem medições diretas em tempo real registradas em ambiente de desenvolvimento local e em cluster dedicado na nuvem.

### 1. Máquina Local (AMD Ryzen 5 7520U + Radeon 610M)
- **CPU**: AMD Ryzen 5 7520U (4 Núcleos Físicos / 8 Threads Zen 2 @ 2.80 - 4.30 GHz, TDP de 15W, AVX2, SSE4.1, SHA-NI, BMI2).
- **GPU**: AMD Radeon 610M (2 Compute Units RDNA2 @ 1899 MHz / VRAM compartilhada).

#### A. Throughput PBKDF2-HMAC-SHA512 (2048 Rodadas - Medição com Core Pinning)
| Threads Ativas | Lote/Thread | Tempo (ms) | Throughput Efetivo | Jitter | Speedup | Eficiência por Núcleo |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1 Thread** | 128 | 64,05 ms | **1.998,35 keys/s** | 18,5% | 1.00x | 100,0% |
| **2 Threads** | 128 | 69,42 ms | **3.687,63 keys/s** | 6,7% | 1.85x | 92,3% |
| **4 Threads** | 128 | 67,29 ms | **7.608,42 keys/s** | 17,2% | **3.81x** | **95,2%** |
| **8 Threads (SMT)** | 128 | 137,00 ms | **7.474,37 keys/s** | 16,3% | 3.74x | 46,8% |

> **Nota de Arquitetura**: 4 núcleos físicos operando a **7.608 keys/s** equivalem a processar **2,49 bilhões de rodadas SHA-512 por segundo**. Como o Zen 2 possui 2 portas vetoriais de 256 bits (FP0 e FP1), a CPU está retirando **~2,05 instruções vetoriais por ciclo de clock**, atingindo 100% da sua capacidade máxima de silício em 15W.

#### B. Poda de Checksum BIP-39 e SHA-256 (SHA-NI Hardware)
| Operação | Iterações | Throughput | Latência Média | Ganho vs Escalar |
| :--- | :---: | :---: | :---: | :---: |
| **BIP-39 Checksum (12 palavras)** | 500.000 | **10,30 Mop/s** | **97,06 ns/op** (Melhor: 95,94 ns) | **2,89x mais rápido** |
| **SHA-256 Escalar Software (64B)** | 100.000 | 1,47 Mhash/s | 681,92 ns/bloco | 1.00x |
| **SHA-256 Hardware SHA-NI (64B)** | 100.000 | **17,31 Mhash/s** | **57,77 ns/bloco** (1056 MB/s) | **11,80x speedup** |

#### C. Microbenchmarks de Curva Elíptica Secp256k1 & BIP-32
| Operação | Custo / Latência | Throughput | Comparativo / Ganho |
| :--- | :---: | :---: | :---: |
| **Adição Escalar libsecp256k1** | 37,52 ns/op | 26,65 Mop/s | 1.00x |
| **Adição Escalar UInt<4> Nativa** | **13,10 ns/op** | **76,33 Mop/s** | **2,86x speedup** |
| **Multiplicação $F_p$ (`mul_mod_p`)** | 26,79 ns/op | 37,32 Mop/s | — |
| **Quadratura $F_p$ (`sqr_mod_p`)** | 23,58 ns/op | 42,40 Mop/s | 1.14x speedup vs mul |
| **Inversão Modular $F_p$ ($a^{p-2} \pmod p$)** | 6.788,56 ns/op | 0,15 Mop/s | — |
| **Pubkey Create libsecp256k1** | 17,19 µs/op | 58.173 ops/s | 1.00x |
| **Pubkey Create Comb 8-bit Nativa** | **12,97 µs/op** | **77.100 ops/s** | **1,33x speedup** |
| **Derivação Completa BIP-32/BIP-44** | **52,24 µs/chave** | **19.140,60 deriv/s** | **1,17x speedup** |

#### D. Modo Híbrido Cooperativo Local (CPU + GPU)
- **Vazão Física CPU (SIMD AVX2)**: 7.608,42 keys/s
- **Vazão Física GPU (OpenCL Radeon 610M)**: 9.119,47 keys/s
- **Throughput Combinado (CPU+GPU)**: **16.727,89 keys/s** (100% de uso de hardware)
- **Throughput Efetivo (com Poda 16x em 12w)**: **267,65 Kkeys/s**
- **Throughput Efetivo (com Poda 256x em 24w)**: **4,28 Mkeys/s**

---

### 2. Servidor Cloud Vast.ai (Intel Xeon Platinum 8180M + NVIDIA RTX A4000)
- **CPU**: Intel Xeon Platinum 8180M (28 Núcleos / 56 Threads @ 2.50 - 3.80 GHz, com extensões **AVX-512 F/CD/BW/DQ/VL**, 32 registradores ZMM de 512 bits).
- **GPU**: NVIDIA RTX A4000 (16 GB GDDR6, 6144 CUDA Cores, barramento PCIe Gen4).

| Métrica / Benchmark | Intel Xeon Platinum 8180M (AVX-512) | Comparativo vs Ryzen 5 7520U (AVX2) |
| :--- | :---: | :---: |
| **PBKDF2 1 Thread (AVX-512)** | **5.392,81 keys/s** | **2,69x mais rápido** por núcleo |
| **PBKDF2 4 Threads (AVX-512)** | **21.515,06 keys/s** (99,7% efic., 3,7% jitter) | **2,83x mais rápido** |
| **Vazão Híbrida Estimada (Xeon + RTX A4000)** | **~405.000 keys/s** | **~24x mais rápido** |

---

### 3. Comparativo de Throughput: Commit `68570d3` vs Versão Atual

| Componente / Métrica | Commit `68570d3` | Versão Atual | Ganho Registrado |
| :--- | :---: | :---: | :---: |
| **PBKDF2 1 Thread (CPU Local)** | 1.013,68 keys/s | **1.998,35 - 2.004,66 keys/s** | **+97,1% (1,97x speedup)** |
| **PBKDF2 4 Threads (CPU Local)** | 2.711,71 keys/s | **7.608,42 keys/s** | **+180,6% (2,81x speedup)** |
| **PBKDF2 4 Threads (Xeon AVX-512)** | — | **21.515,06 keys/s** | **7,93x vs commit anterior** |
| **Jitter Multithread (Estabilidade)** | 69,3% | **14,7% / 17,2%** | **4,7x mais estável** |
| **Poda de Checksum (SHA-NI)** | 3,56 Mop/s (280,8 ns) | **10,30 Mop/s (97,0 ns)** | **+189,3% (2,89x speedup)** |
| **Criação de Pubkey Secp256k1** | 17,19 µs/op | **12,97 µs/op** | **+32,5% (1,33x speedup)** |
| **Derivação BIP-32/BIP-44** | 16.403 deriv/s (60,96 µs) | **19.140 deriv/s (52,24 µs)** | **+16,7% mais rápida** |
| **Modo Híbrido CPU+GPU Local** | — | **16.727,89 keys/s** | **Novo Recurso Nativo** |
| **Filtro Precoce de Endereço** | C1 (32-bit) | **C1-64 (64-bit)** | **Dupla Precisão em 1 Ciclo** |

---

### 4. Teste de Busca Real em Lote Massivo (2 Incógnitas = 4.194.304 Chaves)
Executado em modo de busca real completa no servidor com processador Intel Xeon Platinum 8180M (AVX-512):

```bash
# Busca Real em Bitcoin (2 incógnitas no fim)
./build/criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" --coin btc --target 1...
```
- **Tempo Total Decorrido**: **18,65 segundos**
- **Throughput Efetivo de Varredura**: **224,89 Kkeys/s** (Espaço coberto: 4.194.304 chaves brutas)
- **Throughput Sustentado PBKDF2**: **15,24 Kkeys/s** de cálculo pesado contínuo

```bash
# Busca Real em Ethereum (2 incógnitas no fim)
./build/criptowords --mnemonics "arena huge owner legend diet smart spread truth file peanut ? ?" --coin eth --target 0x...
```
- **Tempo Total Decorrido**: **18,28 segundos**
- **Throughput Efetivo de Varredura**: **229,44 Kkeys/s** (Espaço coberto: 4.194.304 chaves brutas)
- **Throughput Sustentado PBKDF2**: **14,35 Kkeys/s** de cálculo pesado contínuo

---

## Garantia de Qualidade e Suíte de Testes (QA Suite)

O CriptoWords é acompanhado por uma suíte rigorosa de testes de regressão e conformidade criptográfica (`tests/qa_suite.py`):

```bash
python3 tests/qa_suite.py
```

### Resultados da Validação Automatizada:
```text
================================================================================
  RESULTADO FINAL DA SUÍTE DE QA
================================================================================
  Total de Testes Executados: 85
  Testes Aprovados          : 85 (100.0%)
  Testes com Falha          : 0 (0.0%)
  Tempo Total de Execução   : 83.21 segundos
  Status Geral              : [✓] TODOS OS TESTES PASSARAM COM SUCESSO!
================================================================================
```

### Categorias de Teste Validadas:
1. **Vetores Oficiais de Especificação BIP-39 (Trezor / Python bip-utils)**:
   - Derivação semente-para-chave bit a bit idêntica para 12, 15, 18, 21 e 24 palavras.
   - Suporte a passphrases complexas (ex: `'TREZOR'`, caracteres especiais, espaços).
2. **Cobertura de Todos os Idiomas**:
   - Validação dos dicionários e normalizações Unicode para Inglês, Português, Espanhol, Francês, Italiano, Tcheco, Japonês (`U+3000`), Coreano e Chinês.
3. **Conformidade de Endereços**:
   - Endereços Bitcoin Legacy P2PKH Base58Check (`1...`).
   - Endereços Ethereum 0x com Keccak-256 (`0x...`).
4. **Precisão da Poda Analítica em $\mathbb{F}_2^C$**:
   - Dedução reversa instantânea de 1 incógnita ($K=1$).
   - Pruning de pares exato para 2 incógnitas ($K=2$).
   - Poda streaming para $K \ge 3$ com integridade de checksum mantida.
5. **Conformidade Multi-Arquitetura**:
   - Verificação de equivalência matemática bit a bit entre rota Escalar, SIMD SSE4.1, AVX2, AVX-512 e GPU OpenCL (`[BIT-EXACT MATCH]`).

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
- [ ] **Vetorização do BIP-32 em CPU**: Executar o primeiro salto do BIP-32 ($m/44'$) em paralelo vetorial para as 8 (AVX2) ou 16 (AVX-512) sementes já produzidas pelo lote do PBKDF2.
- [ ] **Filtro Cuckoo / Bloom SIMD Multi-Alvo ($\mathcal{O}(1)$)**: Implementar estrutura de dados vetorial em memória para permitir que o usuário busque por centenas ou milhares de endereços simultaneamente sem perda de velocidade.
- [ ] **Backend de Computação via Vulkan / Metal**: Suporte a aceleração gráfica em plataformas sem drivers OpenCL robustos, como macOS (Apple Silicon via Metal) e Android (Termux via Vulkan Compute).

---

## Licença

Distribuído sob licença MIT. Consulte o arquivo de licença correspondente para mais informações.
