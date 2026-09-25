#pragma once

#include <array>
#include <string>
#include <span>
#include <vector>
#include <cstdint>
#include <secp256k1.h>

namespace cryptowords {

    static constexpr size_t MAX_MNEMONIC_LEN = 1024;
    static constexpr size_t BIP39_WORDLIST_SIZE = 2048;

    class Bip39Deriver {
        public:
            // Constrói a string mnemônica juntando as palavras do dicionário.
            static size_t build_mnemonic_str(std::span<const uint16_t> ids_vec,
                                             const std::vector<std::string>& wl,
                                             const std::string& separator,
                                             char* out_buf) noexcept;

            // Derivação BIP32 Estendida (Chave Criança - Child Key)
            static bool derive_child_key(const secp256k1_context &ctx,
                                         std::array<uint8_t, 32> &priv_key,
                                         std::array<uint8_t, 32> &chain_code,
                                         uint32_t index) noexcept;

            // Derivação BIP32 Hardened otimizada
            static bool derive_child_key_hardened(const secp256k1_context &ctx,
                                                  std::array<uint8_t, 32> &priv_key,
                                                  std::array<uint8_t, 32> &chain_code,
                                                  uint32_t index) noexcept;

            // Deriva o endereço BTC final de uma semente bruta
            static std::string derive_btc_address_from_seed(const secp256k1_context &ctx,
                                                            const std::array<uint8_t, 64> &seed,
                                                            const char* passphrase = nullptr,
                                                            size_t passphrase_len = 0) noexcept;

            // Deriva o endereço ETH final de uma semente bruta
            static std::string derive_eth_address_from_seed(const secp256k1_context &ctx,
                                                            const uint8_t* seed,
                                                            const char* passphrase = nullptr,
                                                            size_t passphrase_len = 0) noexcept;

            // Deriva o endereço BTC a partir de ids de mnemônicos (Gera a string e roda PBKDF2)
            static std::string derive_btc_address(const secp256k1_context* ctx,
                                                  std::span<const uint16_t> mnemonic_ids,
                                                  const std::vector<std::string>& wl,
                                                  const char* passphrase = nullptr,
                                                  size_t passphrase_len = 0,
                                                  uint32_t rounds = 2048,
                                                  const std::string& separator = " ") noexcept;

            // Deriva o endereço ETH a partir de ids de mnemônicos (Gera a string e roda PBKDF2)
            static std::string derive_eth_address(const secp256k1_context &ctx,
                                                  std::span<const uint16_t> mnemonic_ids,
                                                  const std::vector<std::string> &wl,
                                                  const char* passphrase = nullptr,
                                                  size_t passphrase_len = 0,
                                                  uint32_t rounds = 2048,
                                                  const std::string& separator = " ");

            // Converte e verifica integridade de endereço Base58 do BTC
            static bool decode_base58_btc_address(const std::string& address, uint8_t out_ripemd[20]) noexcept;

            // Analisa endereço Hexadecimal do ETH
            static bool decode_hex_eth_address(const std::string& hex_addr, uint8_t out_target[20]) noexcept;

            // Faz a derivação completa e compara diretamente com um alvo RIPEMD160 (BTC) na memória
            static bool check_btc_target_from_seed(const secp256k1_context* ctx,
                                                   const uint8_t* seed,
                                                   const uint8_t* target_ripemd,
                                                   uint32_t target_fast) noexcept;
            static bool check_btc_target_from_seed(const secp256k1_context* ctx,
                                                   const uint8_t* seed,
                                                   const uint8_t* target_ripemd,
                                                   uint64_t target_fast64) noexcept;

            // Faz a derivação completa e compara diretamente com um alvo Hex 20-bytes (ETH) na memória
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                   const uint8_t* seed,
                                                   const uint8_t* target_eth,
                                                   uint64_t target_fast64) noexcept;
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                   const uint8_t* seed,
                                                   const uint8_t* target_eth,
                                                   uint32_t target_fast) noexcept;
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                   const std::array<uint8_t, 64> &seed,
                                                   const uint8_t* target_eth,
                                                   uint32_t target_fast) noexcept {
                return check_eth_target_from_seed(ctx, seed.data(), target_eth, target_fast);
            }
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                   const std::array<uint8_t, 64> &seed,
                                                   const uint8_t* target_eth,
                                                   uint64_t target_fast64) noexcept {
                return check_eth_target_from_seed(ctx, seed.data(), target_eth, target_fast64);
            }

            // Validador de integridade do Mnemônico (Checksum BIP39)
            static bool verify_checksum(std::span<const uint16_t> mnemonic_ids) noexcept;
    };
} // namespace cryptowords
