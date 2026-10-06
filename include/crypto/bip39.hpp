#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace cryptowords {

static constexpr size_t MAX_MNEMONIC_LEN    = 1024;
static constexpr size_t BIP39_WORDLIST_SIZE = 2048;

class Bip39Deriver {
   public:
    // Junta ids no buffer e devolve o comprimento escrito.
    static size_t build_mnemonic_str(std::span<const uint16_t> ids_vec,
                                     const std::vector<std::string>& wl,
                                     const std::string& separator, char* out_buf) noexcept;

    // Derivação BIP-32 (chave-filha hardened ou normal).
    static bool derive_child_key(std::array<uint8_t, 32>& priv_key,
                                 std::array<uint8_t, 32>& chain_code, uint32_t index) noexcept;

    // --- Endereços a partir de seed BIP-39 crua ---
    static std::string derive_btc_address_from_seed(const std::array<uint8_t, 64>& seed,
                                                    const char* passphrase = nullptr,
                                                    size_t passphrase_len = 0,
                                                    std::array<uint8_t, 32>* out_priv_key = nullptr) noexcept;
    static std::string derive_eth_address_from_seed(const uint8_t* seed,
                                                    const char* passphrase = nullptr,
                                                    size_t passphrase_len = 0,
                                                    std::array<uint8_t, 32>* out_priv_key = nullptr) noexcept;

    // --- Endereços a partir de ids do mnemônico (string + PBKDF2 + BIP-32/44) ---
    static std::string derive_btc_address(std::span<const uint16_t> mnemonic_ids,
                                          const std::vector<std::string>& wl,
                                          const char* passphrase = nullptr,
                                          size_t passphrase_len = 0, uint32_t rounds = 2048,
                                          const std::string& separator = " ",
                                          std::array<uint8_t, 32>* out_priv_key = nullptr) noexcept;
    static std::string derive_eth_address(std::span<const uint16_t> mnemonic_ids,
                                          const std::vector<std::string>& wl,
                                          const char* passphrase = nullptr,
                                          size_t passphrase_len = 0, uint32_t rounds = 2048,
                                          const std::string& separator = " ",
                                          std::array<uint8_t, 32>* out_priv_key = nullptr);

    // --- Somente os 20 bytes do endereço (sem formatação/checagem) ---
    // Usado no caminho multi-target: deriva uma vez, compara com N alvos.
    static bool derive_btc_address_bytes(const uint8_t* seed, uint8_t out_ripemd[20]) noexcept;
    static bool derive_eth_address_bytes(const uint8_t* seed, uint8_t out_eth[20]) noexcept;

    // --- Decodificação de endereço ---
    static bool decode_base58_btc_address(const std::string& address, uint8_t out_ripemd[20]) noexcept;
    static bool decode_hex_eth_address(const std::string& hex_addr, uint8_t out_target[20]) noexcept;

    // --- Comparação rápida (single-target) ---
    static bool check_btc_target_from_seed(const uint8_t* seed,
                                           const uint8_t* target_ripemd,
                                           uint64_t target_fast64) noexcept;
    static bool check_eth_target_from_seed(const uint8_t* seed,
                                           const uint8_t* target_eth,
                                           uint64_t target_fast64) noexcept;
    static bool check_eth_target_from_seed(const std::array<uint8_t, 64>& seed,
                                           const uint8_t* target_eth,
                                           uint64_t target_fast64) noexcept {
        return check_eth_target_from_seed(seed.data(), target_eth, target_fast64);
    }

    // --- Checksum BIP-39 ---
    static bool verify_checksum(std::span<const uint16_t> mnemonic_ids) noexcept;
    static bool extract_checksum(std::span<const uint16_t> mnemonic_ids,
                                 uint8_t& out_checksum) noexcept;
};

}  // namespace cryptowords
