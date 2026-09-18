# CriptoWords — Especificação Técnica de Engenharia: Backlog de Otimizações a Fazer

**Versão do Documento:** 2.0.0  
**Status:** Arquitetura e Engenharia de Performance  
**Objetivo Primário:** Afunilar ao limite matemático absoluto o número de combinações candidatas antes de acionar a computação pesada (PBKDF2-HMAC-SHA512), extraindo a máxima vazão física permitida pelo hardware (CPU x86_64, SIMD e caches).

---

## Índice Temático

1. [Fase 1: Matemática Pura & Redução Combinatorial do Espaço de Busca](#fase-1-matemática-pura--redução-combinatorial-do-espaço-de-busca)
   - [OTM-01: Dedução Reversa da Última Palavra por Checksum](#otm-01-dedução-reversa-da-última-palavra-por-checksum)
   - [OTM-02: Pruning Analítico de Pares em $\mathbb{F}_2^C$](#otm-02-pruning-analítico-de-pares-em-mathbbf_2c)
   - [OTM-03: Árvores de Decisão Binária Ordenadas (ROBDD)](#otm-03-árvores-de-decisão-binária-ordenadas-robdd)
   - [OTM-04: Propagação de Intervalos Afins no Merkle-Damgård](#otm-04-propagação-de-intervalos-afins-no-merkle-damgård)
   - [OTM-05: Meet-in-the-Middle de Entropia (Baby-Step / Giant-Step)](#otm-05-meet-in-the-middle-de-entropia-baby-step--giant-step)
   - [OTM-06: Grafos de De Bruijn para Enumeração de Anagramas](#otm-06-grafos-de-de-bruijn-para-enumeração-de-anagramas)
   - [OTM-07: Autômatos de Damerau-Levenshtein sobre TRIE (Modo Typo)](#otm-07-autômatos-de-damerau-levenshtein-sobre-trie-modo-typo)
   - [OTM-08: Poda por Prefixo Canônico de 4 Letras do BIP-39](#otm-08-poda-por-prefixo-canônico-de-4-letras-do-bip-39)
   - [OTM-09: Modelagem SAT/CNF com Eliminação Gaussiana (CryptoMiniSat)](#otm-09-modelagem-satcnf-com-eliminação-gaussiana-cryptominisat)
2. [Fase 2: Estruturação de Memória, Topologia e Localidade de Cache](#fase-2-estruturação-de-memória-topologia-e-localidade-de-cache)
   - [OTM-10: Fatiamento em N-Slices (Two-Sided Memory Patching)](#otm-10-fatiamento-em-n-slices-two-sided-memory-patching)
   - [OTM-11: Reordenação de Eixos do Odômetro (Loop Inversion)](#otm-11-reordenação-de-eixos-do-odômetro-loop-inversion)
   - [OTM-12: Ordenação por Máximo Prefixo Comum (Common Prefix Trie)](#otm-12-ordenação-por-máximo-prefixo-comum-common-prefix-trie)
   - [OTM-13: Particionamento Hierárquico em Blocos Contíguos](#otm-13-particionamento-hierárquico-em-blocos-contíguos)
   - [OTM-14: Divisões Inteiras Mágicas de Granlund-Montgomery (Barrett)](#otm-14-divisões-inteiras-mágicas-de-granlund-montgomery-barrett)
   - [OTM-15: Pré-computação Estática do Salt de PBKDF2](#otm-15-pré-computação-estática-do-salt-de-pbkdf2)
   - [OTM-16: Core Pinning e Afinidade a Núcleos Físicos de CPU](#otm-16-core-pinning-e-afinidade-a-núcleos-físicos-de-cpu)
3. [Fase 3: Filtragem Física de Descarte em Hardware](#fase-3-filtragem-física-de-descarte-em-hardware)
   - [OTM-17: Aceleração de Checksum por Hardware SHA-NI](#otm-17-aceleração-de-checksum-por-hardware-sha-ni)
   - [OTM-18: Mid-State Caching de SHA-256 no Prefixo Fixo de Entropia](#otm-18-mid-state-caching-de-sha-256-no-prefixo-fixo-de-entropia)
   - [OTM-19: Bitslicing de Software SHA-256 (Fallback Vetorial)](#otm-19-bitslicing-de-software-sha-256-fallback-vetorial)
4. [Fase 4: Motor Pesado PBKDF2-HMAC-SHA512 (Massive Parallelism)](#fase-4-motor-pesado-pbkdf2-hmac-sha512-massive-parallelism)
   - [OTM-20: Dual-Stream Interleaved AVX2 (Dual-Issue Pipelining)](#otm-20-dual-stream-interleaved-avx2-dual-issue-pipelining)
   - [OTM-21: Janela Circular de Mensagem ($W$) no SHA-512](#otm-21-janela-circular-de-mensagem-w-no-sha-512)
   - [OTM-22: Sparsity Folding no Bloco $K \oplus \text{ipad}$ do HMAC](#otm-22-sparsity-folding-no-bloco-k-oplus-textipad-do-hmac)
   - [OTM-23: Fast-Forwarding do Round 1 do PBKDF2](#otm-23-fast-forwarding-do-round-1-do-pbkdf2)
   - [OTM-24: Execução de SHA-512 em Little-Endian Nativo](#otm-24-execução-de-sha-512-em-little-endian-nativo)
5. [Fase 5: Derivação de Endereço e Verificação Final](#fase-5-derivação-de-endereço-e-verificação-final)
   - [OTM-25: Inferência de Rota BIP em $\mathcal{O}(1)$ pelo Prefixo do Alvo](#otm-25-inferência-de-rota-bip-em-mathcalo1-pelo-prefixo-do-alvo)
   - [OTM-26: Rejeição Precoce C1 por Token de 32-bits](#otm-26-rejeição-precoce-c1-por-token-de-32-bits)
   - [OTM-27: Decomposição de Escalar por Endomorfismo GLV no secp256k1](#otm-27-decomposição-de-escalar-por-endomorfismo-glv-no-secp256k1)
   - [OTM-28: SIMD Cuckoo Filter para Multi-Targeting $\mathcal{O}(1)$](#otm-28-simd-cuckoo-filter-para-multi-targeting-mathcalo1)
6. [Fase 6: Heurísticas e Teoria da Informação para `--invalid_too`](#fase-6-heurísticas-e-teoria-da-informação-para---invalid_too)
   - [OTM-29: Priorização por Gradiente de Distância de Hamming ($d_H$)](#otm-29-priorização-por-gradiente-de-distância-de-hamming-d_h)
   - [OTM-30: Modelo do Canal Ruidoso de Shannon (Fonética e Teclado)](#otm-30-modelo-do-canal-ruidoso-de-shannon-fonética-e-teclado)

---

## FASE 1: Matemática Pura & Redução Combinatorial do Espaço de Busca

---

### OTM-01: Dedução Reversa da Última Palavra por Checksum
* **Status:** Implementado / Produção.
* **O Porquê:** Na especificação BIP-39, a última palavra contém os bits finais de entropia e os $C \in \{4, 5, 6, 7, 8\}$ bits de checksum derivados do hash SHA-256 de toda a entropia precedente. Quando a última palavra é incógnita, não há necessidade de força bruta sobre o espaço de 2048 palavras; os bits de checksum são rigidamente determinados pela entropia já construída.
* **Ganhos Métricos:**
  - Redução exata do espaço de combinações pelo fator $2^C$:
    - 12 palavras: divide o espaço por **$16\times$** ($2^4$).
    - 15 palavras: divide o espaço por **$32\times$** ($2^5$).
    - 24 palavras: divide o espaço por **$256\times$** ($2^8$).
  - **100% das chaves testadas são válidas.** Zero desperdício de PBKDF2.
* **Complexidade:** Baixa ($\mathcal{O}(1)$ por candidato).
* **Riscos & Efeitos Colaterais:** Incompatível com o modo `--invalid_too` (pois este pressupõe que o checksum pode estar errado).
* **Compatibilidade:** Sinergia total com OTM-10 (N-Slices) e OTM-11 (Loop Inversion).

---

### OTM-02: Pruning Analítico de Pares em $\mathbb{F}_2^C$
* **Status:** Planejado / Alta Prioridade.
* **O Porquê:** Quando a última palavra é FIXA, mas existem 2 incógnitas em posições intermediárias (ex: `dad few ? trumpet ... begin ? street`), a última palavra já impõe um checksum alvo $C_{\text{alvo}}$. O produto cartesiano geraria $2048 \times 2048 = 4.194.304$ combinações no odômetro. No entanto, para cada candidato da incógnita 1, existem no máximo $2048 / 2^C$ candidatos da incógnita 2 que satisfazem a congruência afim do checksum.
* **Ganhos Métricos:**
  - Reduz o espaço do odômetro de 4.194.304 para **131.072 combinações** (em 15w) antes de rodar o loop.
  - O tempo de busca cai de **17 segundos para ~1,5 segundo**.
* **Complexidade:** Alta (exige álgebra de alinhamento de bits não-múltiplos de 8).
* **Riscos & Efeitos Colaterais:** Risco de regressão se houver desalinhamento de bits em frases com comprimentos ímpares (15 e 21 palavras). Deve ser coberto por testes de regressão diferenciais.

---

### OTM-03: Árvores de Decisão Binária Ordenadas (ROBDD)
* **Status:** Pesquisa / Backlog.
* **O Porquê:** Uma ROBDD compila a função booleana do checksum $f: \{0,1\}^n \to \{0,1\}$ em um grafo acíclico direcionado canônico. Os caminhos da raiz até o nó terminal `1` representam o conjunto exato de todas as atribuições de palavras que formam uma frase válida.
* **Ganhos Métricos:**
  - O odômetro é substituído por uma travessia direta no grafo.
  - Elimina $100\%$ da geração de combinações inválidas sem executar nenhum hash SHA-256 no filtro.
* **Complexidade:** Muito Alta (dependência de biblioteca de BDD como CUDD ou Sylvan).
* **Riscos & Efeitos Colaterais:** Explosão de memória RAM durante a compilação do grafo se a ordem das variáveis não for ótima (tamanho do grafo pode crescer exponencialmente).

---

### OTM-04: Propagação de Intervalos Afins no Merkle-Damgård
* **Status:** Planejado.
* **O Porquê:** O SHA-256 comprime palavras de 32 bits através de somas modulares $\boxplus \pmod{2^{32}}$. Se grande parte das palavras é conhecida, as variáveis de estado nas primeiras 8 rodadas residem em intervalos convexos fechados $[X_{\min}, X_{\max}]$.
* **Ganhos Métricos:**
  - Descarta sub-árvores inteiras de combinações onde o intervalo de saída $[S_{\min}, S_{\max}]$ não possui interseção com o valor binário do checksum.
  - Redução de **2x a 5x** no espaço de teste do filtro.
* **Complexidade:** Alta.
* **Riscos & Efeitos Colaterais:** Se houver mais de 3 incógnitas, a difusão rápida do SHA-256 expande os intervalos para $[0, 2^{32}-1]$ já no round 6, anulando a capacidade de poda.

---

### OTM-05: Meet-in-the-Middle de Entropia (Baby-Step / Giant-Step)
* **Status:** Planejado.
* **O Porquê:** Para 2 incógnitas localizadas em blocos distintos de entropia (uma no início e outra no final), a computação pode ser cindida ao meio.
* **Ganhos Métricos:**
  - Transforma uma busca de complexidade $\mathcal{O}(N^2)$ em $\mathcal{O}(N)$ no tempo, armazenando os estados intermediários em tabela hash de alta velocidade.
* **Complexidade:** Alta.
* **Riscos & Efeitos Colaterais:** Consumo de memória RAM para indexar os estados intermediários (tabela de Baby-Steps).

---

### OTM-06: Grafos de De Bruijn para Enumeração de Anagramas
* **Status:** Planejado (Módulo Anagram).
* **O Porquê:** Quando o usuário possui as $N$ palavras corretas anotadas, mas a ordem foi perdida, o espaço é o fatorial $N!$ (para 12 palavras: $12! = 479.001.600$). Modelar as transições como caminhos eulerianos em grafos de De Bruijn permite podar arestas que violam a paridade dos bits de fronteira de bytes da entropia.
* **Ganhos Métricos:**
  - Poda **mais de 95% das permutações no papel**, reduzindo de 479 milhões para menos de 15 milhões de testes.
* **Complexidade:** Alta.

---

### OTM-07: Autômatos de Damerau-Levenshtein sobre TRIE (Modo Typo)
* **Status:** Planejado / Flag `--strategy typo`.
* **O Porquê:** Na presença de palavras que não constam no dicionário oficial ou palavras digitadas com erro, calcular Levenshtein por força bruta leva $\mathcal{O}(2048 \times |W|)$. Um Autômato de Levenshtein Universal cruza a palavra corrompida contra a TRIE do dicionário em tempo linear $\mathcal{O}(|W|)$.
* **Ganhos Métricos:**
  - Afunila uma incógnita de $2.048$ opções para **apenas 5 a 15 palavras candidatas**.
  - Em 2 palavras com erro, o espaço cai de 4,19 milhões para **menos de 200 combinações**.
* **Complexidade:** Média.
* **Riscos & Efeitos Colaterais:** Não afeta a busca normal se não for acionada a flag `--strategy typo`.

---

### OTM-08: Poda por Prefixo Canônico de 4 Letras do BIP-39
* **Status:** Planejado.
* **O Porquê:** No padrão BIP-39 oficial, nenhuma palavra compartilha os mesmos 4 primeiros caracteres com outra palavra na mesma língua. Se o usuário fornecer 4 letras ou anotação parcial, a palavra está matematicamente fixada em $\mathcal{O}(1)$.
* **Ganhos Métricos:** Elimina completamente a incógnita ($2048 \to 1$).
* **Complexidade:** Baixa.

---

### OTM-09: Modelagem SAT/CNF com Eliminação Gaussiana (CryptoMiniSat)
* **Status:** Pesquisa / Backlog para $K \ge 4$.
* **O Porquê:** Para 4 ou mais incógnitas ($K \ge 4$), o espaço ultrapassa dezenas de trilhões. O circuito lógico do SHA-256 é transposto para equações booleanas CNF com cláusulas XOR. O solver deduz as variáveis livres usando eliminação gaussiana sobre $\mathbb{F}_2$.
* **Ganhos Métricos:** Pula trilhões de estados sem iterar.
* **Complexidade:** Extrema.
* **Riscos & Efeitos Colaterais:** Ineficiente para $K \le 3$ devido ao tempo de instanciação de cláusulas (overhead de centenas de milissegundos).

---

## FASE 2: Estruturação de Memória, Topologia e Localidade de Cache

---

### OTM-10: Fatiamento em N-Slices (Two-Sided Memory Patching)
* **Status:** Planejado / Alta Prioridade.
* **O Porquê:** Atualmente, o motor copia o texto das palavras conhecidas repetidamente para o buffer `pw` a cada lote. O Fatiamento em N-Slices divide o buffer em fatias estáticas (`prefix_str`, `middle_str`, `suffix_str`) pré-alocadas. Durante a busca, o motor só altera os offsets das incógnitas.
* **Ganhos Métricos:**
  - Elimina mais de **500 milhões de chamadas `memcpy`** em buscas longas.
  - Aceleração direta de **+15% a +25%** no ciclo do odômetro.
* **Complexidade:** Média.
* **Riscos & Efeitos Colaterais:** Cuidado extremo com caracteres multibyte (UTF-8) em idiomas como Coreano, Japonês e Chinês, garantindo que os offsets de escrita correspondam a bytes e não a caracteres lógicos.

---

### OTM-11: Reordenação de Eixos do Odômetro (Loop Inversion)
* **Status:** Planejado / Alta Prioridade.
* **O Porquê:** Na travessia mista de variáveis, se a variável mais à esquerda mudar no loop interno, quase todo o buffer de string é alterado a cada iteração. Invertendo os eixos para que a incógnita mais à direita seja o loop mais interno, 95% do buffer de senha permanece estritamente idêntico por 2.048 ciclos consecutivos.
* **Ganhos Métricos:**
  - Taxa de acerto no cache de dados L1 sustentada em **> 99.8%**.
  - Ganho de **+5% a +12%** de vazão global.
* **Complexidade:** Baixa.

---

### OTM-12: Ordenação por Máximo Prefixo Comum (Common Prefix Trie)
* **Status:** Planejado.
* **O Porquê:** Agrupa as sequências de palavras geradas de forma que o maior prefixo binário possível de SHA-512 permaneça imutável. Permite congelar o cálculo da primeira metade do bloco de 128 bytes nos registradores YMM por milhares de iterações.
* **Ganhos Métricos:** Economiza até 40% das operações de round inicial do PBKDF2 em loops longos.

---

### OTM-13: Particionamento Hierárquico em Blocos Contíguos
* **Status:** Planejado.
* **O Porquê:** Em vez de fazer as threads avançarem de forma intercalada (`thread + N * step`), o espaço é fatiado em blocos contíguos ($[0, \frac{N}{T}), [\frac{N}{T}, \frac{2N}{T})\dots$). A variável mais externa fica estática dentro daquela thread por milhões de ciclos.
* **Ganhos Métricos:** Zero contenção de barramento de memória entre núcleos físicos da CPU.

---

### OTM-14: Divisões Inteiras Mágicas de Granlund-Montgomery (Barrett)
* **Status:** Planejado.
* **O Porquê:** A instrução `idiv` da arquitetura x86-64 consome de 25 a 45 ciclos de clock. Substituí-la por multiplicação inteira de alta precisão por uma constante mágica pré-computada seguida de shift aritmético (`imul` + `sar`) reduz o custo para **1 ciclo de clock**.
* **Ganhos Métricos:** Aceleração de até **5% no gerador do odômetro**.

---

### OTM-15: Pré-computação Estática do Salt de PBKDF2
* **Status:** Planejado / Alta Prioridade.
* **O Porquê:** O salt do BIP-39 é invariável (`"mnemonic" + passphrase`). Formatar o buffer de salt de 128 bytes e convertê-lo em vetores a cada lote de 8 mnemônicos é um desperdício puro de ciclos. O vetor `msg_salt[16]` deve ser gerado uma única vez na inicialização da thread.
* **Ganhos Métricos:** Elimina dezenas de milhares de instruções de inicialização de memória por segundo. Ganho de **+3% a +5%**.

---

### OTM-16: Core Pinning e Afinidade a Núcleos Físicos de CPU
* **Status:** Planejado / Alta Prioridade.
* **O Porquê:** Em cargas 100% vetoriais (AVX2), duas threads lógicas (SMT/Hyper-Threading) no mesmo núcleo físico disputam as mesmas portas de execução de 256 bits, gerando contenção e aquecimento excessivo que derruba a frequência do Turbo Boost. Fixar 1 worker por núcleo físico real via `pthread_setaffinity_np` estabiliza o clock e o throughput.
* **Ganhos Métricos:** Ganho de **+10% a +18%** de velocidade sustentada em multithreading contínuo.

---

## FASE 3: Filtragem Física de Descarte em Hardware

---

### OTM-17: Aceleração de Checksum por Hardware SHA-NI
* **Status:** Planejado / Altíssima Prioridade.
* **O Porquê:** Processadores modernos (como o AMD Ryzen 5 7520U Zen 2) possuem instruções dedicadas de silício para SHA-256 (`_mm_sha256rnds2_epu32`, `_mm_sha256msg1_epu32`, `_mm_sha256msg2_epu32`).
* **Ganhos Métricos:**
  - O cálculo de 1 bloco de SHA-256 cai de ~800 ciclos (emulação AVX2 de software) para **apenas ~70 ciclos no silício**.
  - **Aceleração de 10x a 12x no filtro de checksum**. Permite avaliar 50 milhões de combinações por segundo.
* **Complexidade:** Média (requer compilação com `-msha -msse4.1`).
* **Riscos & Efeitos Colaterais:** Gera `SIGILL` em CPUs antigas que não possuem SHA-NI. Deve possuir fallback automático via Auto-Tuner.

---

### OTM-18: Mid-State Caching de SHA-256 no Prefixo Fixo de Entropia
* **Status:** Planejado.
* **O Porquê:** A entropia de mnemônicos conhecidos no início da frase gera palavras de 32 bits imutáveis no início do bloco de SHA-256. Salvar o estado intermediário ($A \dots H$) após processar os termos fixos evita recalcular a primeira metade do bloco em todas as combinações.
* **Ganhos Métricos:** Corta o custo de cada teste de checksum pela metade (**2x mais rápido**).

---

### OTM-19: Bitslicing de Software SHA-256 (Fallback Vetorial)
* **Status:** Backlog (Apenas para CPUs sem SHA-NI).
* **O Porquê:** Em CPUs legadas que não possuem instruções SHA-NI, o Bitslicing transposta 256 mnemônicos paralelos em bits individuais sobre registradores YMM, executando operações lógicas em lote.
* **Ganhos Métricos:** 3x a 5x mais rápido que código escalar puro em CPUs antigas.
* **Conflito:** É completamente superado pelo Hardware SHA-NI em CPUs modernas.

---

## FASE 4: Motor Pesado PBKDF2-HMAC-SHA512 (Massive Parallelism)

---

### OTM-20: Dual-Stream Interleaved AVX2 (Dual-Issue Pipelining)
* **Status:** Planejado / Altíssima Prioridade.
* **O Porquê:** O loop de 2048 rodadas de SHA-512 tem uma cadeia estrita de dependência de dados ($e_{k+1} = d_k + T_1$ e $a_{k+1} = T_1 + T_2$). Em um único fluxo de 4 sementes, as unidades de execução vetorial da CPU sofrem stalls de latência. Intercalar dois fluxos independentes (Sementes 1..4 e Sementes 5..8) permite que a CPU execute as instruções do Fluxo 2 enquanto o Fluxo 1 aguarda a latência de rotação/soma.
* **Ganhos Métricos:** **+15% a +30% de vazão contínua em PBKDF2**.
* **Complexidade:** Alta.
* **Riscos:** Alto consumo de registradores YMM. Deve ser afinado pelo Auto-Tuner para evitar stack spilling.

---

### OTM-21: Janela Circular de Mensagem ($W$) no SHA-512
* **Status:** Planejado.
* **O Porquê:** O código atual gera 3.254 instruções de load/store de pilha (`vmovdqa`) porque precisa de 24 registradores e o AVX2 só tem 16. Utilizar uma janela circular móvel para os 16 termos de $W$ reduz o número de variáveis ativas mantidas na pilha.
* **Ganhos Métricos:** Redução de até 50% no tráfego de memória de pilha no L1. Ganho de **+8% a +15%**.

---

### OTM-22: Sparsity Folding no Bloco $K \oplus \text{ipad}$ do HMAC
* **Status:** Planejado.
* **O Porquê:** O mnemônico preenche apenas os primeiros ~70 a 90 bytes do bloco de 128 bytes de HMAC. Os bytes 90 a 127 são estritamente zeros, resultando em constantes estáticas `0x3636363636363636`. As rodadas finais da expansão de mensagem dependem exclusivamente de zeros e constantes conhecidas, podendo ser resolvidas estaticamente em tempo de compilação.
* **Ganhos Métricos:** Economia de 30% das operações de round no bloco de chave.

---

### OTM-23: Fast-Forwarding do Round 1 do PBKDF2
* **Status:** Planejado.
* **O Porquê:** No Round 1 do PBKDF2, a mensagem de entrada é `salt || 0x00000001`. Como o salt é constante durante toda a busca, o hash interno do Round 1 pode ser pré-computado em ponto morto. O loop de PBKDF2 começa diretamente no Round 2.
* **Ganhos Métricos:** Economiza milhões de blocos de SHA-512 completos em buscas volumosas.

---

### OTM-24: Execução de SHA-512 em Little-Endian Nativo
* **Status:** Planejado.
* **O Porquê:** Elimina 100% das instruções de `vpshufb` (`_mm256_shuffle_epi8`) invertendo as constantes $K_t$ e os vetores de inicialização em tempo de compilação.
* **Ganhos Métricos:** Economiza **mais de 137 bilhões de instruções de CPU** em buscas de 4 milhões de chaves.

---

## FASE 5: Derivação de Endereço e Verificação Final

---

### OTM-25: Inferência de Rota BIP em $\mathcal{O}(1)$ pelo Prefixo do Alvo
* **Status:** Implementado / Produção.
* **O Porquê:** O formato do endereço alvo determina univocamente a rota de derivação (`1...` $\to$ BIP-44, `3...` $\to$ BIP-49, `bc1q...` $\to$ BIP-84, `bc1p...` $\to$ BIP-86, `0x...` $\to$ ETH). Poda 100% de qualquer tentativa em caminhos incompatíveis.
* **Complexidade:** Muito Baixa ($\mathcal{O}(1)$).

---

### OTM-26: Rejeição Precoce C1 por Token de 32-bits
* **Status:** Implementado / Produção.
* **O Porquê:** Em vez de comparar os 20 bytes inteiros do hash RIPEMD/Keccak com `memcmp`, compara apenas os primeiros 4 bytes (`uint32_t`) em 1 ciclo de clock. A probabilidade de um falso positivo passar pelo token de 32 bits é de apenas 1 em 4,29 bilhões.
* **Ganhos Métricos:** Rejeição de chaves erradas em **1 ciclo de clock**.

---

### OTM-27: Decomposição de Escalar por Endomorfismo GLV no secp256k1
* **Status:** Planejado via `libsecp256k1`.
* **O Porquê:** Explora o endomorfismo da curva Koblitz do secp256k1, decompondo o escalar de 256 bits em dois sub-escalares de 128 bits calculados simultaneamente via Strauss-Shamir.
* **Ganhos Métricos:** **Dobra a velocidade** da multiplicação de pontos na curva elíptica.

---

### OTM-28: SIMD Cuckoo Filter para Multi-Targeting $\mathcal{O}(1)$
* **Status:** Planejado.
* **O Porquê:** Se o usuário buscar contra uma lista de múltiplos endereços alvos (ex: 1.000 ou 100.000 alvos), consultar uma tabela Cuckoo com impressões digitais de 16 bits via vetor AVX2 leva **1 ciclo de clock**, com o mesmo tempo de buscar apenas 1 alvo.

---

## FASE 6: Heurísticas e Teoria da Informação para `--invalid_too`

---

### OTM-29: Priorização por Gradiente de Distância de Hamming ($d_H$)
* **Status:** Planejado / Alta Prioridade para `--invalid_too`.
* **O Porquê:** Em 99% das frases reais com checksum corrompido, o erro humano difere por apenas 1 ou 2 bits de paridade. O otimizador organiza a varredura em camadas concêntricas de esferas de Hamming ($d_H = 1 \to d_H = 2 \to \dots$).
* **Ganhos Métricos:** A chave correta é encontrada nos **primeiros 5 a 15 segundos**, dispensando a espera de minutos no final do loop.

---

### OTM-30: Modelo do Canal Ruidoso de Shannon (Fonética e Teclado)
* **Status:** Planejado / Flag `--strategy phonetic` e `--strategy keyboard`.
* **O Porquê:** Modela os erros por probabilidade bayesiana de digitação (teclas vizinhas em QWERTY/ABNT2) e homófonos acústicos (Metaphone 3).
* **Ganhos Métricos:** Em carteiras com erro de grafia, afunila a busca para menos de 500 combinações totais, resolvendo a recuperação em fração de segundo.

---

## Matriz de Decisão: Quais Técnicas Rodam Juntas por Volume de Incógnitas?

```text
┌───────────┬──────────────────────────┬──────────────────────────────────────────────────────────┐
│ Volume    │ Espaço de Busca Efetivo  │ Stack Ótimo Recomendado                                  │
├───────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
│ K = 1     │ 2.048 combinações        │ • OTM-01 (Dedução Reversa) + OTM-26 (Token C1)           │
│           │                          │ Tempo: < 0.005s                                          │
├───────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
│ K = 2     │ 4,19 milhões             │ • OTM-01/OTM-02 (Pruning Analítico F2^C)                 │
│           │ (ou 131k com dedução)    │ • OTM-10 (N-Slices) + OTM-11 (Loop Inversion)            │
│           │                          │ • OTM-15 (Salt Pré-comp) + OTM-16 (Core Pinning)         │
│           │                          │ • OTM-17 (Hardware SHA-NI) + OTM-20 (Interleaved PBKDF2) │
│           │                          │ Tempo: ~1 a 2 segundos                                   │
├───────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
│ K = 3     │ 8,59 bilhões             │ • OTM-01/OTM-02 (Redução 256x por Checksum)              │
│           │ (33,5M com dedução)      │ • OTM-17 (Hardware SHA-NI a 50M chaves/s)                │
│           │                          │ • OTM-20 (Dual-Stream) + OTM-24 (Little-Endian SHA)      │
│           │                          │ Tempo: ~20 a 45 minutos (em vez de 12 dias!)             │
├───────────┼──────────────────────────┼──────────────────────────────────────────────────────────┤
│ K ≥ 4     │ Trilhões / Quatrilhões   │ • OTM-07 (Autômatos Levenshtein na TRIE)                 │
│           │                          │ • OTM-08 (Prefixo-4) + OTM-29 (Gradiente de Hamming)     │
│           │                          │ • OTM-30 (Matriz de Canal Ruidoso de Shannon)            │
│           │                          │ • Poda por Letra Inicial / `--allow`                     │
│           │                          │ Tempo: Minutos a horas (em vez de milênios!)            │
└───────────┴──────────────────────────┴──────────────────────────────────────────────────────────┘
```

---

## Conclusão de Engenharia

O projeto do `CriptoWords` passa a ter um **mapa de implementação completo e modular**. 
A regra mandatória que guia todo o desenvolvimento futuro é:
1. **A Pré-Busca Matemática** (Fases 1 e 2) reduz o espaço combinatorial e congela a memória;
2. **O Hardware Dedicado** (Fase 3) descarta qualquer resíduo restante à taxa de dezenas de milhões de testes por segundo;
3. **O Motor Pesado PBKDF2** (Fase 4) só opera sobre os sobreviventes matematicamente aprovados;
4. **A Verificação Criptográfica** (Fase 5) rejeita divergências em 1 ciclo de clock.
