# CriptoWords v2.0 - Motor de Busca BIP39

CriptoWords é um motor de força bruta e recuperação mnemônica BIP39 construído em **C++23** focado em altíssimo desempenho e eficiência criptográfica. Ele foi desenhado para contornar gargalos matemáticos durante a recuperação de frases semente perdidas (Bitcoin e Ethereum) utilizando vetorização de CPU (SIMD AVX2/AVX512), otimização de pipeline JIT (Just-in-Time) e *Early Rejection*.

## 🚀 Funcionalidades e Inovações

- **Vetorização SIMD (AVX2/AVX512)**: Implementação brutal e *lock-free* do PBKDF2-HMAC-SHA512. Em vez de rodar o hash de 1 em 1, o núcleo matemático empacota múltiplos *hashes* na mesma instrução de CPU. 
  - **Resultados Típicos (Por Core):** AVX2 entrega ganhos reais em torno de **5.4x** em processadores modernos de desktop em relação à execução unilinear, e AVX512 expande esse teto em **+11%**.
- **Target Early Rejection (Corte O(1))**: Em vez de fazer uma lenta comparação em array byte a byte do alvo final (`memcmp`), o programa *faz engenharia reversa visual* do Endereço Target (Base58/Hex) antes do motor inicializar. Um *token* de 32-bits é extraído para realizar saltos condicionais nos registradores do processador.
- **Auto-Dedução de Checksum Reverso**: Se as posições da frase fornecidas tiverem vazios, a palavra que carrega o *checksum* é inteiramente deduzida validando sub-blocos reversos de SHA256 sem invocar processamentos desnecessários em PBKDF2.

## 🛠️ Limitações Matemáticas (O Efeito Exponencial)
Este projeto é projetado para **Mnemônicos (BIP39)**, onde a geração do `Seed` obrigatoriamente força o processador a executar 2.048 iterações de `SHA512` sob *PBKDF2*. Como esse passo não pode ser burlado criptograficamente, a busca linear tem um teto físico. 
Usando um processador multi-core otimizado em AVX2:
- 1 ou 2 palavras desconhecidas (Até 4 Milhões de permutações): **Resolvido em menos de 1 minuto.**
- 3 palavras desconhecidas (8,5 Bilhões): **Leva algumas horas.**
- 4 palavras desconhecidas (17 Trilhões): **Demoraria anos em uma CPU caseira.**

*Nota: Se o seu caso de uso não for recuperar palavras BIP39, mas sim fazer força bruta cega direto na Secp256k1 por um range de Chaves Privadas Raw (ex: Bitcoin Puzzle), você deve usar ferramentas de Point-Addition (Baby-Step Giant-Step / Kangaroo) em placa de vídeo (GPU).*

## 🛠️ Requisitos de Instalação

Para compilar, o ambiente precisa possuir os pacotes de cabeçalho da *libsecp256k1*. O suporte nativo foi focado puramente em vetores de CPU.

No Ubuntu/Debian Linux:
```bash
sudo apt-get update
sudo apt-get install build-essential g++ libsecp256k1-dev
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
| `--lang` | Idioma oficial do BIP39 (`en`, `pt`, `es`, `fr`, etc). | Padrão: `en` |
| `--passphrase`| Aplica a 25ª palavra extra estipulada pelo usuário (salt extra no PBKDF2). (Max 100 chars). | Padrão: (Vazio) |
| `--threads` | Quantidade de threads de CPU alocadas. Recomenda-se no máximo o Nº de núcleos físicos. | Padrão: Metade da CPU |
| `--rounds` | Rodadas do PBKDF2 (Customizável para brute-force em forks com parâmetros diferentes). | Padrão: `2048` |
| `--invalid_too` | Habilita a busca por chaves com checksum inválido. | (Flag booleana) |

