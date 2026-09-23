#pragma once

#include <array>
#include <string>
#include <cstdint>

namespace cryptowords {
    namespace base58 {
    // Alfabeto Padrão do Bitcoin
    constexpr const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Decodifica um endereço Base58 (BTC) validando o checksum (SHA256d)
    // Retorna true se for válido e salva o hash160 (RIPEMD160) em out_ripemd.
    bool decode_btc_address(const std::string& address, uint8_t out_ripemd[20]);

    // Codifica um payload binário bruto (ex: versão + pubkeyhash + checksum) em Base58.
    // Retorna o tamanho final da string inserida em out_buf.
    // Nota: O buffer de saída deve ter espaço suficiente.
    size_t encode_raw(const uint8_t* payload, size_t len, char* out_buf);

    } // namespace base58
} // namespace cryptowords
