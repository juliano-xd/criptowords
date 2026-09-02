# criptowords

Programa de brute force para recuperação de mnemônicos BIP39.

## Compilação

```bash
cd src
g++ -O3 -mavx2 -std=c++26 -march=native \
    main.cpp cli.cpp brute_force_engine.cpp cli_parser.cpp \
    result_processor.cpp search_optimizer.cpp \
    -o runner -lsecp256k1 -lcrypto -lOpenCL -lpthread
```

O executável será gerado em `src/runner`.

## Uso

```bash
# Mostrar ajuda
./runner --help

# Gerar endereços de mnemonic conhecido
./runner --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Buscar mnemonic com posições desconhecidas
./runner --mnemonic "? ? abandon ... about" --hash 1MrkVrDviJqqFFxF1BUqs1xib3w2pQuR6j

# Com passphrase BIP39
./runner --mnemonic "? ? ... about" --passphrase "mysecret" --hash 1MrkVr...

# Usar GPU (se disponível)
./runner --mnemonic "? ? ... about" --gpu --hash 1MrkVr...
```

## Opções

| Opção | Descrição |
|-------|-----------|
| `--mnemonic` | Mnemonic com `?` para posições desconhecidas |
| `--hash` | Endereço BTC/ETH alvo |
| `--passphrase` | BIP39 passphrase (padrão: vazio) |
| `--wordlist` | Arquivo de wordlist customizado |
| `--fix` | Fixa palavra em posição específica |
| `--allow` | Palavras permitidas por posição |
| `--threads` | Número de threads (padrão: automático) |
| `--rounds` | Iterações PBKDF2 (padrão: 2048) |
| `--gpu` | Habilita GPU via OpenCL |

## Arquitetura

```
CLI → SearchOptimizer → SearchConfig → BruteForceEngine → ProducerChannel → ResultProcessor
```

- **BruteForceEngine**: Gera seeds PBKDF2 (APENAS isso)
- **ResultProcessor**: Deriva endereços e verifica matches
- **SearchOptimizer**: Analisa espaço de busca e gera relatório

## Status

Em desenvolvimento. Bugs e issues: https://github.com/seu-repo/criptowords/issues
