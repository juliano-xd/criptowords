#include "../../include/crypto/base58.hpp"
#include "../../include/crypto/sha256.hpp"
#include <gmp.h>
#include <gmpxx.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <array>
#include <string_view>

namespace cryptowords {
namespace base58 {

// Assumindo que BASE58_ALPHABET está definido no seu base58.hpp
// Exemplo clássico do Bitcoin: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
constexpr const std::string_view BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Tabela estática de lookup O(1) para caracteres Base58 (256 bytes)
constexpr auto make_b58_table() {
    std::array<int8_t, 256> tbl{};
    tbl.fill(-1);
    for (int i = 0; i < 58; ++i) {
        tbl[static_cast<uint8_t>(BASE58_ALPHABET[i])] = static_cast<int8_t>(i);
    }
    return tbl;
}

constexpr auto B58_LOOKUP = make_b58_table();

bool decode_btc_address(const std::string& address, uint8_t out_ripemd[20]) {
    if (address.size() < 26 || address.size() > 35) return false;

    // 1 inicial no alfabeto BTC representa o byte 0x00 à esquerda.
    size_t leading = 0;
    while (leading < address.size() && address[leading] == BASE58_ALPHABET[0]) {
        ++leading;
    }
    if (leading >= 25) return false;

    mpz_class val = 0;
    for (char c : address) {
        int8_t digit = B58_LOOKUP[static_cast<uint8_t>(c)];
        if (digit < 0) [[unlikely]] return false;

        val = val * 58 + digit;
    }

    // Exporta o valor do mpz_class diretamente para um buffer de bytes em Big-Endian
    alignas(8) uint8_t raw[32];
    std::memset(raw, 0, sizeof(raw));

    size_t count = 0;
    // mpz_export preenche o buffer de trás para frente se o número for menor que 32 bytes,
    // mantendo o alinhamento Big-Endian correto.
    if (val > 0) {
        mpz_export(raw, &count, 1, 1, 1, 0, val.get_mpz_t());
    }

    // Ajusta o ponteiro baseado em quantos bytes reais o GMP exportou
    // Um endereço BTC decodificado válido (incluindo a versão e checksum) tem sempre 25 bytes.
    if (count > 25) return false;

    // Alinha o buffer decodificado para o final para simular o comportamento de preenchimento por zeros à esquerda
    uint8_t decoded[25];
    std::memset(decoded, 0, 25 - count);
    std::memcpy(decoded + (25 - count), raw, count);

    // Valida a versão (0x00 para Mainnet P2PKH)
    if (decoded[0] != 0x00) return false;

    // Validação de Checksum (Double SHA256 do payload de 21 bytes)
    uint8_t checksum[32];
    crypto::SHA256::hash(decoded, 21, checksum);
    crypto::SHA256::hash(checksum, 32, checksum);

    if (std::memcmp(decoded + 21, checksum, 4) != 0) return false;

    // Copia os 20 bytes do hash RIPEMD160 (pulando o byte de versão)
    std::memcpy(out_ripemd, decoded + 1, 20);
    return true;
}

size_t encode_raw(const uint8_t* payload, size_t len, char* out_buf) {
    if (len == 0) {
        out_buf[0] = '\0';
        return 0;
    }

    size_t leading_zeros = 0;
    while (leading_zeros < len && payload[leading_zeros] == 0x00) {
        leading_zeros++;
    }

    // Importa os bytes para o GMP (Big-Endian)
    mpz_class val;
    if (len - leading_zeros > 0) {
        mpz_import(val.get_mpz_t(), len - leading_zeros, 1, 1, 1, 0, payload + leading_zeros);
    } else {
        val = 0;
    }

    char tmp[64];
    size_t tmp_len = 0;

    // Divisão sucessiva por 58 usando as operações eficientes do GMP
    if (val == 0) {
        tmp[tmp_len++] = BASE58_ALPHABET[0];
    } else {
        mpz_class rem;
        while (val > 0) {
            mpz_class q = val / 58;
            rem = val % 58;
            val = q;
            tmp[tmp_len++] = BASE58_ALPHABET[rem.get_ui()];
        }
    }

    size_t out_len = 0;
    // Adiciona os zeros à esquerda codificados como o primeiro caractere do alfabeto (geralmente '1')
    for (size_t i = 0; i < leading_zeros; ++i) {
        out_buf[out_len++] = BASE58_ALPHABET[0];
    }

    // Inverte a string temporária para colocar na ordem correta (Big-Endian)
    for (size_t i = 0; i < tmp_len; ++i) {
        out_buf[out_len++] = tmp[tmp_len - 1 - i];
    }

    out_buf[out_len] = '\0';
    return out_len;
}

} // namespace base58
} // namespace cryptowords
