# Plano de Refatoração CriptoWords

## Objetivo
Reestruturar o CriptoWords com arquitetura limpa: CLI profissional, separação de responsabilidades, e otimizações.

## Arquitetura Proposta

```
CLI → SearchOptimizer → SearchConfig → BruteForceEngine → ProducerChannel → ResultProcessor
```

### Componentes

| Componente | Arquivo | Responsabilidade |
|------------|---------|-----------------|
| `SearchConfig` | `include/search_config.hpp` | Estrutura centralizada |
| `SearchOptimizer` | `include/search_optimizer.hpp` | Analisa + relatório |
| `ProducerChannel<T>` | `include/producer_channel.hpp` | Fila thread-safe |
| `ResultProcessor` | `include/result_processor.hpp` | Deriva + verifica |
| `BruteForceEngine` | `include/brute_force_engine.hpp` | ONLY gera seeds |

## Símbolos CLI

| Símbolo | Significado | Exemplo |
|----------|-------------|---------|
| `[+]` | Habilitado/Adicionado | `[+] GPU habilitado` |
| `[-]` | Desabilitado/Removido | `[-] ETH desabilitado` |
| `[!]` | Alerta/Warning | `[!] Busca iniciada` |
| `[=]` | Informação | `[=] Tempo: 00:05:23` |
| `[✓]` | Sucesso | `[✓] Match encontrado!` |
| `[✗]` | Erro | `[✗] Target inválido` |
| `[→]` | Direcionamento | `[→] Enviando para GPU` |
| `[*]` | Em progresso | `[*] Processando...` |
| `[·]` | Bullet | `[·] Opção 1 |

---

## SKILL 1: SearchConfig

### Arquivo
`include/search_config.hpp`

### Estrutura
```cpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "bip39.hpp"  // TargetBytes

struct SearchConfig {
    // INPUT DO USUÁRIO
    std::string passphrase = "";
    std::string target = "";
    TargetBytes target_bytes;
    int pbkdf2_rounds = 2048;
    int num_threads = 0;  // 0 = auto
    bool use_gpu = false;

    // WORDLIST
    std::vector<std::string> wordlist;
    std::string wordlist_path = "../wordlist/english.txt";

    // MNEMONIC
    std::vector<std::string> base_words;
    std::vector<size_t> unknown_positions;
    std::vector<std::vector<std::string>> candidates;

    // COMPUTADO
    uint64_t total_combinations = 0;
    bool is_trivial = false;
    std::string search_summary;
};
```

### Checklist
- [ ] Criar header com pragma once
- [ ] Incluir bip39.hpp para TargetBytes
- [ ] Definir todos os campos com defaults seguros
- [ ] passphrase default = "" (vazio BIP39)
- [ ] rounds default = 2048 (BIP39)

---

## SKILL 2: SearchOptimizer

### Arquivo
`include/search_optimizer.hpp` + `src/search_optimizer.cpp`

### Responsabilidade
1. Analisa constraints
2. Calcula espaço de busca
3. Aplica otimizações
4. Gera relatório para usuário

### Interface
```cpp
class SearchOptimizer {
public:
    static SearchConfig analyze(
        const std::vector<std::string>& wordlist,
        const std::vector<std::string>& base_words,
        const std::map<size_t, std::vector<std::string>>& fix_map,
        const std::map<size_t, std::vector<std::string>>& allow_map,
        const std::string& passphrase,
        const std::string& target,
        int pbkdf2_rounds,
        int num_threads,
        bool use_gpu
    );

    static void print_report(const SearchConfig& config);
    static bool confirm_start();
};
```

### Relatório a Gerar
```
╔══════════════════════════════════════════════════════════════════════╗
║                   SEARCH OPTIMIZATION REPORT                         ║
╚══════════════════════════════════════════════════════════════════════╝

[=] ENTRADA DO USUÁRIO
    [+--mnemonic] "abandon ? ? ? ... abandon" (11 posições desconhecidas)
    [+--passphrase] "" (vazio)
    [+--hash] 1MrkVrDviJqqFFxF1BUqs1xib3w2pQuR6j
    [+--wordlist] english.txt (2048 palavras)
    [+--rounds] 2048 (BIP39 padrão)

[=] ESPAÇO DE BUSCA
    [+] Posições desconhecidas: 11
    [+] Combinações totais: 2^128 (≈ 10^38)

[!] Tempo estimado: >1000 anos @ 1000 buscas/s

[=] OTIMIZAÇÕES APLICADAS
    [+] Batch size otimizado para cache CPU
    [+] Pipeline GPU habilitado (OpenCL)
    [+] Early-exit ao encontrar match

[=] PLANO DE EXECUÇÃO
    [+] Modo: HÍBRIDO (GPU producer + CPU verifier)

╔══════════════════════════════════════════════════════════════════════╗
║  [!] ATENÇÃO: Busca iniciada. Pressione Ctrl+C para interromper.   ║
╚══════════════════════════════════════════════════════════════════════╝

[?] Prosseguir com a busca? [Y/n]:
```

### Checklist
- [ ] Calcular total_combinations
- [ ] Detectar caso trivial (mnemonic completo)
- [ ] Formatar saída com símbolos corretos
- [ ] Aguardar confirmação do usuário

---

## SKILL 3: ProducerChannel<T>

### Arquivo
`include/producer_channel.hpp`

### Responsabilidade
Fila thread-safe com batching para comunicação entre BruteForceEngine e ResultProcessor.

### Interface
```cpp
template<typename T>
class ProducerChannel {
public:
    ProducerChannel(size_t capacity = 1024);

    // Produtor: empurra batch de itens
    void push_batch(const T* items, size_t count);

    // Produtor: sinaliza que terminou
    void close();

    // Consumidor: bloqueia até ter count itens ou canal fechado
    size_t pop_batch(T* items, size_t count, std::chrono::milliseconds timeout);

    // true se canal fechou e está vazio
    bool done() const;

private:
    // implementação com mutex + condition_variable
};
```

### Estrutura de Dados para Seed
```cpp
struct SeedResult {
    uint8_t seed[64];                    // PBKDF2 output
    std::vector<std::string> mnemonic;   // Para reportar match
    size_t batch_index;                  // Para debugging
};
```

### Checklist
- [ ] Template thread-safe
- [ ] Suporte múltiplos produtores (GPU + CPU threads)
- [ ] Batch push/pop
- [ ] Timeout no pop
- [ ] close() para sinalizar fim

---

## SKILL 4: ResultProcessor

### Arquivo
`include/result_processor.hpp` + `src/result_processor.cpp`

### Responsabilidade
- Recebe seed do channel
- Deriva master_node via HMAC-SHA512("Bitcoin seed")
- Deriva chave pública via secp256k1
- Deriva endereço BTC (Base58Check) ou ETH (Keccak-256)
- Verifica match com target
- Reporta resultado

### Interface
```cpp
class ResultProcessor {
public:
    ResultProcessor(const SearchConfig& config);

    // Consome do channel, verifica, reporta
    void run(ProducerChannel<SeedResult>& input);

private:
    std::string derive_btc(const uint8_t* seed);
    std::string derive_eth(const uint8_t* seed);
    bool check_match(const std::string& addr);

    // thread_local contexts para performance
    thread_local secp256k1_context* ctx_;
};
```

### Fluxo de Derivação (copiar de bip39.hpp)
```
seed (64 bytes) → HMAC-SHA512("Bitcoin seed") → master_node (64 bytes)
                                                         ↓
                                          secp256k1_ec_pubkey_create
                                                         ↓
                                          public_key (33 bytes compressa)
                                                         ↓
                                          SHA256 → RIPEMD160 → payload (21 bytes)
                                                         ↓
                                          Double SHA256 → checksum (4 bytes)
                                                         ↓
                                          Base58Check → BTC address
```

### Checklist
- [ ] HMAC-SHA512 com "Bitcoin seed" fixo
- [ ] secp256k1 com thread_local context
- [ ] Derivation BTC completa
- [ ] Derivation ETH (Keccak-256)
- [ ] Verificação de match
- [ ] Output formatado com símbolos

---

## SKILL 5: BruteForceEngine

### Arquivo
`include/brute_force_engine.hpp` + `src/brute_force_engine.cpp`

### Responsabilidade
**APENAS gera seeds** - não verifica, não deriva endereços.

### Interface Nova
```cpp
class BruteForceEngine {
public:
    static void run(
        const SearchConfig& config,
        ProducerChannel<SeedResult>& output
    );
};
```

### Alterações do Código Atual
**REMOVER** do BruteForceEngine:
- [ ] Match detection logic (linhas 104-139, 184-206)
- [ ] BTC address derivation (linhas 130, 193)
- [ ] Result display
- [ ] Statistics output

**MANTER** no BruteForceEngine:
- [ ] Thread spawning
- [ ] GPU/CPU path
- [ ] Batch generation
- [ ] advance_odometer()
- [ ] build_mnemonic_fast()

### Checklist
- [ ] Separar GPU path
- [ ] Separar CPU path
- [ ] Usar ProducerChannel para output
- [ ] thread_local para contextos

---

## SKILL 6: CLI Profissional

### Arquivo
`src/cli.cpp`

### Símbolos a Usar

```
[+] = Habilitado/Adicionado
[-] = Desabilitado/Removido
[!] = Alerta/Warning
[=] = Informação/Dados
[✓] = Sucesso/Completo
[✗] = Erro/Falha
[→] = Direcionamento
[*] = Em progresso
[·] = Bullets
```

### Telas a Implementar

1. **Ajuda** (`--help`)
2. **Relatório de Otimização** (antes de iniciar)
3. **Progresso** (durante execução)
4. **Match Encontrado**
5. **Nenhum Match**
6. **Erros**

### Exemplo: Tela de Erro
```
╔══════════════════════════════════════════════════════════════════════╗
║  [✗] ERRO                                                          ║
╚══════════════════════════════════════════════════════════════════════╝

[✗] Código: ERR_INVALID_TARGET
[✗] Mensagem: Endereço BTC inválido: "1MrkVr..."

[!] Solução:
    [+] Verifique se o endereço está correto
    [+] BTC addresses começam com 1 (mainnet) ou 3 (script)
```

### Checklist
- [ ] Usar símbolos corretos em todas as saídas
- [ ] Relatório antes de iniciar
- [ ] Confirmação Y/n
- [ ] Progresso durante execução
- [ ] Tela de match
- [ ] Tela de sem match
- [ ] Tela de erros

---

## SKILL 7: Integração e Testes

### Testes a Criar

1. **test_search_config.cpp** - Validar SearchConfig
2. **test_bip39_vectors.cpp** - Usar vetores de teste BIP39 conhecidos
3. **test_derivations.cpp** - Verificar que BTC/ETH derivation estão corretas

### Vetores de Teste BIP39

```
Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
Seed: 006unda4d1ca8a5e4e84c7d85f1a6e9d9b8e8f4e4c7a5e4e84c7d85f1a6e9d9
BTC Address: 1MrkVrDviJqqFFxF1BUqs1xib3w2pQuR6j
```

### Checklist
- [ ] Compilar sem erros
- [ ] Testar derivação BTC com vetor conhecido
- [ ] Testar derivação ETH com vetor conhecido
- [ ] Testar CLI com símbolos
- [ ] Testar SearchOptimizer relatório

---

## Ordem de Implementação

1. **SearchConfig** (base, outros components dependem)
2. **ProducerChannel** (abstração de comunicação)
3. **ResultProcessor** (lógica de verificação)
4. **BruteForceEngine** (refatorado, usa channel)
5. **SearchOptimizer** (análise + relatório)
6. **CLI atualizada** (junta tudo)
7. **Testes**

---

## Checklist Final

- [ ] Código compila sem erros
- [ ] CLI usa símbolos corretos
- [ ] Relatório é exibido antes de iniciar
- [ ] Usuário confirma antes de buscar
- [ ] BruteForceEngine apenas gera seeds
- [ ] ResultProcessor verifica matches
- [ ] Passphrase configurável
- [ ] ETH derivation funciona (Keccak-256)
- [ ] thread_local contexts para performance
