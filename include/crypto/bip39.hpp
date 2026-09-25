#pragma once

#include <array>
#include <string>
#include <span>
#include <vector>
#include <cstdint>
#include <secp256k1.h>

using namespace std;
using u8 = uint8_t;

namespace cryptowords {

    static constexpr size_t MAX_MNEMONIC_LEN = 1024;
    static constexpr size_t BIP39_WORDLIST_SIZE = 2048;

    class Bip39Deriver {
        public:
            // Constrói a string mnemônica juntando as palavras do dicionário.
            static size_t build_mnemonic_str(span<const uint16_t> ids_vec,
                                                const vector<string>& wl,
                                                const string& separator,
                                                char* out_buf) noexcept;

            // Derivação BIP32 Estendida (Chave Criança - Child Key)
            static bool derive_child_key([[maybe_unused]] const secp256k1_context &ctx,
                                            array<u8, 32> &priv_key,
                                            array<u8, 32> &chain_code,
                                            uint32_t index) noexcept;

            // Derivação BIP32 Hardened otimizada (sem branches e sem pubkey)
            static bool derive_child_key_hardened(const secp256k1_context &ctx,
                                                    array<u8, 32> &priv_key,
                                                    array<u8, 32> &chain_code,
                                                    uint32_t index) noexcept;

            // Deriva o endereço BTC final de uma semente bruta
            static string derive_btc_address_from_seed(const secp256k1_context &ctx,
                                                            const array<u8, 64> &seed,
                                                            const char* passphrase,
                                                            size_t passphrase_len) noexcept;

            // Deriva o endereço ETH final de uma semente bruta
            static string derive_eth_address_from_seed(const secp256k1_context &ctx,
                                                            const u8* seed,
                                                            const char* passphrase,
                                                            size_t passphrase_len) noexcept;

            // Deriva o endereço BTC a partir de ids de mnemônicos (Gera a string e roda PBKDF2)
            static string derive_btc_address(const secp256k1_context* ctx,
                                                span<const uint16_t> mnemonic_ids,
                                                const vector<string>& wl,
                                                const char* passphrase = nullptr,
                                                size_t passphrase_len = 0,
                                                uint32_t rounds = 2048,
                                                const string& separator = " ") noexcept;

            // Deriva o endereço ETH a partir de ids de mnemônicos (Gera a string e roda PBKDF2)
            static string derive_eth_address(const secp256k1_context &ctx,
                                                span<const uint16_t> &mnemonic_ids,
                                                const vector<string> &wl,
                                                const char* passphrase = nullptr,
                                                size_t passphrase_len = 0,
                                                uint32_t rounds = 2048,
                                                const string& separator = " ");

            // Converte e verifica integridade de endereço Base58 do BTC
            static bool decode_base58_btc_address(const string& address, u8 out_ripemd[20]) noexcept;

            // Analisa endereço Hexadecimal do ETH
            static bool decode_hex_eth_address(const string& hex_addr, u8 out_target[20]) noexcept;

            // Faz a derivação completa e compara diretamente com um alvo RIPEMD160 (BTC) na memória
            static bool check_btc_target_from_seed(const secp256k1_context* ctx,
                                                const u8* seed,
                                                const u8* target_ripemd,
                                                uint32_t target_fast) noexcept;
            static bool check_btc_target_from_seed(const secp256k1_context* ctx,
                                                const u8* seed,
                                                const u8* target_ripemd,
                                                uint64_t target_fast64) noexcept;

            // Faz a derivação completa e compara diretamente com um alvo Hex 20-bytes (ETH) na memória
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                const u8* seed,
                                                const u8* target_eth,
                                                uint64_t target_fast64) noexcept;
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                const u8* seed,
                                                const u8* target_eth,
                                                uint32_t target_fast) noexcept;
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                const array<u8, 64> &seed,
                                                const u8* target_eth,
                                                uint32_t target_fast) noexcept {
                return check_eth_target_from_seed(ctx, seed.data(), target_eth, target_fast);
            }
            static bool check_eth_target_from_seed(const secp256k1_context &ctx,
                                                const array<u8, 64> &seed,
                                                const u8* target_eth,
                                                uint64_t target_fast64) noexcept {
                return check_eth_target_from_seed(ctx, seed.data(), target_eth, target_fast64);
            }

            // Validador de integridade do Mnemônico (Checksum BIP39)
            static bool verify_checksum(span<const uint16_t> mnemonic_ids) noexcept;
    };
} // namespace cryptowords
