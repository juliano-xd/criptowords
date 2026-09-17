#include "../../include/crypto/hmac_sha512.hpp"
#include <cstring>
#include <algorithm>
#include <bit>

namespace crypto {

namespace {

[[gnu::always_inline]] inline uint64_t Ch64  (uint64_t x, uint64_t y, uint64_t z) { return z ^ (x & (y ^ z)); }
[[gnu::always_inline]] inline uint64_t Maj64 (uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (z & (x | y)); }
[[gnu::always_inline]] inline uint64_t BSig0 (uint64_t x) { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); }
[[gnu::always_inline]] inline uint64_t BSig1 (uint64_t x) { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); }
[[gnu::always_inline]] inline uint64_t SSig0 (uint64_t x) { return std::rotr(x, 1)  ^ std::rotr(x, 8)  ^ (x >> 7); }
[[gnu::always_inline]] inline uint64_t SSig1 (uint64_t x) { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }
[[gnu::always_inline]] inline uint64_t load_be64(const uint8_t* p) {
    uint64_t v; std::memcpy(&v, p, 8); return __builtin_bswap64(v);
}

static constexpr uint64_t K512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static constexpr uint64_t SHA512_IV[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

#define RND_S(K, WV)                                                     \
    do {                                                                 \
        const uint64_t _t1 = h + BSig1(e) + Ch64(e, f, g) + (K) + (WV); \
        const uint64_t _t2 = BSig0(a) + Maj64(a, b, c);                 \
        h = g; g = f; f = e; e = d + _t1;                                \
        d = c; c = b; b = a; a = _t1 + _t2;                              \
    } while (0)

[[gnu::always_inline]]
static inline void sha512_compress_block(uint64_t state[8], uint64_t W[16]) {
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) RND_S(K512[i], W[i]);

    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i)
            W[i] += SSig0(W[(i + 1) & 15]) + W[(i + 9) & 15] + SSig1(W[(i + 14) & 15]);
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) RND_S(K512[r * 16 + i], W[i]);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

[[gnu::always_inline]]
static inline void sha512_compress_64_fast(const uint64_t state_in[8], const uint64_t data[8], uint64_t state_out[8]) {
    uint64_t W[16];
    for (int i = 0; i < 8; ++i) W[i] = data[i];
    W[8] = 0x8000000000000000ULL;
    W[9] = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 1536;

    uint64_t a = state_in[0], b = state_in[1], c = state_in[2], d = state_in[3];
    uint64_t e = state_in[4], f = state_in[5], g = state_in[6], h = state_in[7];

    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) RND_S(K512[i], W[i]);

    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            W[i] += SSig0(W[(i + 1) & 15]) + W[(i + 9) & 15] + SSig1(W[(i + 14) & 15]);
            RND_S(K512[r * 16 + i], W[i]);
        }
    }

    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
    state_out[5] = state_in[5] + f;
    state_out[6] = state_in[6] + g;
    state_out[7] = state_in[7] + h;
}

#undef RND_S

} // namespace

HMAC_SHA512::HMAC_SHA512(const void* key, size_t key_len) {
    init(static_cast<const uint8_t*>(key), key_len);
}

void HMAC_SHA512::init(const uint8_t* key, size_t key_len) {
    uint8_t k_use[128] = {0};
    size_t k_use_len;
    if (key_len > 128) {
        SHA512::hash(key, key_len, k_use);
        k_use_len = 64;
    } else {
        std::memcpy(k_use, key, key_len);
        k_use_len = key_len;
    }

    uint8_t ipad[128], opad[128];
    std::memset(ipad, 0x36, 128);
    std::memset(opad, 0x5c, 128);

    for (size_t i = 0; i < k_use_len; i++) {
        ipad[i] ^= k_use[i];
        opad[i] ^= k_use[i];
    }

    inner_.reset();
    inner_.update(ipad, 128);
    inner_base_ = inner_;

    // Configura outer_base_ com preset permanente para mensagens de 64 bytes (inner_hash)
    outer_base_.preset(opad, 128, 64);
    is_preset_ = false;
    expected_len_ = 0;
}

void HMAC_SHA512::update(const uint8_t* data, size_t len) {
    inner_.update(data, len);
}

void HMAC_SHA512::finalize(uint8_t* out) {
    uint8_t inner_hash[64];
    inner_.finalize(inner_hash);
    // complete() não destrói o outer_base_, mantendo-o reutilizável
    outer_base_.complete(inner_hash, 64, out);
}

void HMAC_SHA512::reset_inner() {
    inner_ = inner_base_;
}

void HMAC_SHA512::preset(const void* key, size_t key_len, size_t expected_data_len) {
    uint8_t k_use[128] = {0};
    size_t k_use_len;
    if (key_len > 128) {
        SHA512::hash(key, key_len, k_use);
        k_use_len = 64;
    } else {
        std::memcpy(k_use, key, key_len);
        k_use_len = key_len;
    }

    uint8_t ipad[128], opad[128];
    std::memset(ipad, 0x36, 128);
    std::memset(opad, 0x5c, 128);

    for (size_t i = 0; i < k_use_len; i++) {
        ipad[i] ^= k_use[i];
        opad[i] ^= k_use[i];
    }

    inner_base_.preset(ipad, 128, expected_data_len);
    inner_ = inner_base_;
    outer_base_.preset(opad, 128, 64);
    is_preset_ = true;
    expected_len_ = expected_data_len;
}

void HMAC_SHA512::complete(const void* data, size_t len, uint8_t out[64]) const {
    uint8_t inner_hash[64];
    inner_base_.complete(data, len, inner_hash);
    outer_base_.complete(inner_hash, 64, out);
}

void HMAC_SHA512::complete(const void* data, uint8_t out[64]) const {
    complete(data, expected_len_, out);
}

void HMAC_SHA512::bip32_hash(const uint8_t chain_code[32],
                             const uint8_t data[37],
                             uint8_t out[64]) {
    // 1. Bloco 0 do Inner: Processa o ipad diretamente em registradores
    uint64_t state_inner[8];
    std::memcpy(state_inner, SHA512_IV, sizeof(state_inner));

    uint64_t W[16];
    constexpr uint64_t IPAD_CONST = 0x3636363636363636ULL;
    for (int i = 0; i < 4; ++i) W[i] = load_be64(chain_code + i * 8) ^ IPAD_CONST;
    for (int i = 4; i < 16; ++i) W[i] = IPAD_CONST;
    sha512_compress_block(state_inner, W);

    // 2. Bloco 0 do Outer: Processa o opad diretamente em registradores
    uint64_t state_outer[8];
    std::memcpy(state_outer, SHA512_IV, sizeof(state_outer));
    constexpr uint64_t OPAD_CONST = 0x5c5c5c5c5c5c5c5cULL;
    for (int i = 0; i < 4; ++i) W[i] = load_be64(chain_code + i * 8) ^ OPAD_CONST;
    for (int i = 4; i < 16; ++i) W[i] = OPAD_CONST;
    sha512_compress_block(state_outer, W);

    // 3. Bloco 1 do Inner: data (37 bytes) com padding e bitlength
    for (int i = 0; i < 4; ++i) W[i] = load_be64(data + i * 8);
    W[4] = (uint64_t(data[32]) << 56) |
           (uint64_t(data[33]) << 48) |
           (uint64_t(data[34]) << 40) |
           (uint64_t(data[35]) << 32) |
           (uint64_t(data[36]) << 24) |
           0x0000000000800000ULL;
    for (int i = 5; i < 15; ++i) W[i] = 0;
    // Comprimento total = 128 (ipad) + 37 (data) = 165 bytes = 1320 bits
    W[15] = 1320;
    sha512_compress_block(state_inner, W);

    // 4. Bloco 1 do Outer: state_inner (64 bytes) com padding e bitlength (1536 bits)
    for (int i = 0; i < 8; ++i) W[i] = state_inner[i];
    W[8] = 0x8000000000000000ULL;
    for (int i = 9; i < 15; ++i) W[i] = 0;
    W[15] = 1536;
    sha512_compress_block(state_outer, W);

    // 5. Serialização final do resultado (64 bytes)
    for (int i = 0; i < 8; ++i) {
        uint64_t v = __builtin_bswap64(state_outer[i]);
        std::memcpy(out + i * 8, &v, 8);
    }
}

void HMAC_SHA512::hash_single_block(const void* key, size_t key_len,
                                    const void* data, size_t data_len,
                                    uint8_t out[64]) {
    uint8_t k_use[128] = {0};
    size_t k_use_len;
    if (key_len > 128) {
        SHA512::hash(key, key_len, k_use);
        k_use_len = 64;
    } else {
        std::memcpy(k_use, key, key_len);
        k_use_len = key_len;
    }

    uint8_t ipad[128], opad[128];
    std::memset(ipad, 0x36, 128);
    std::memset(opad, 0x5c, 128);
    for (size_t i = 0; i < k_use_len; ++i) {
        ipad[i] ^= k_use[i];
        opad[i] ^= k_use[i];
    }

    uint64_t state_inner[8];
    std::memcpy(state_inner, SHA512_IV, sizeof(state_inner));
    uint64_t W[16];
    for (int i = 0; i < 16; ++i) W[i] = load_be64(ipad + i * 8);
    sha512_compress_block(state_inner, W);

    uint64_t state_outer[8];
    std::memcpy(state_outer, SHA512_IV, sizeof(state_outer));
    for (int i = 0; i < 16; ++i) W[i] = load_be64(opad + i * 8);
    sha512_compress_block(state_outer, W);

    // Prepara bloco formatado do dado
    uint8_t buf[128] = {0};
    if (data_len > 0) std::memcpy(buf, data, data_len);
    buf[data_len] = 0x80;
    const uint64_t total_bits = (128 + data_len) * 8;
    const uint64_t bit_len_be = __builtin_bswap64(total_bits);
    std::memcpy(buf + 120, &bit_len_be, 8);

    for (int i = 0; i < 16; ++i) W[i] = load_be64(buf + i * 8);
    sha512_compress_block(state_inner, W);

    for (int i = 0; i < 8; ++i) W[i] = state_inner[i];
    W[8] = 0x8000000000000000ULL;
    for (int i = 9; i < 15; ++i) W[i] = 0;
    W[15] = 1536;
    sha512_compress_block(state_outer, W);

    for (int i = 0; i < 8; ++i) {
        uint64_t v = __builtin_bswap64(state_outer[i]);
        std::memcpy(out + i * 8, &v, 8);
    }
}

void HMAC_SHA512::hash(const void* key, size_t key_len,
                       const void* data, size_t data_len,
                       uint8_t out[64]) {
    if (data_len <= 111) {
        hash_single_block(key, key_len, data, data_len, out);
    } else {
        HMAC_SHA512 hmac;
        hmac.init(static_cast<const uint8_t*>(key), key_len);
        hmac.update(static_cast<const uint8_t*>(data), data_len);
        hmac.finalize(out);
    }
}

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len) {
    HMAC_SHA512 hmac_base;
    const size_t u1_msg_len = salt_len + 4;
    hmac_base.preset(password, password_len, u1_msg_len);

    uint8_t salt_and_be4[256];
    std::memcpy(salt_and_be4, salt, salt_len);
    salt_and_be4[salt_len + 0] = 0;
    salt_and_be4[salt_len + 1] = 0;
    salt_and_be4[salt_len + 2] = 0;
    salt_and_be4[salt_len + 3] = 1;

    uint8_t U[64], T[64];
    hmac_base.complete(salt_and_be4, u1_msg_len, U);
    std::memcpy(T, U, 64);

    uint64_t inner_state[8];
    uint64_t outer_state[8];
    for (int i = 0; i < 8; ++i) {
        inner_state[i] = hmac_base.inner_base_.h_[i];
        outer_state[i] = hmac_base.outer_base_.h_[i];
    }

    uint64_t U64[8];
    for (int i = 0; i < 8; ++i) {
        U64[i] = (uint64_t(U[i*8]) << 56) | (uint64_t(U[i*8+1]) << 48) |
                 (uint64_t(U[i*8+2]) << 40) | (uint64_t(U[i*8+3]) << 32) |
                 (uint64_t(U[i*8+4]) << 24) | (uint64_t(U[i*8+5]) << 16) |
                 (uint64_t(U[i*8+6]) << 8)  | uint64_t(U[i*8+7]);
    }
    uint64_t T64[8];
    for (int i = 0; i < 8; ++i) T64[i] = U64[i];

    for (int i = 1; i < iterations; ++i) {
        uint64_t temp[8];
        sha512_compress_64_fast(inner_state, U64, temp);
        sha512_compress_64_fast(outer_state, temp, U64);
        for (int j = 0; j < 8; ++j) {
            T64[j] ^= U64[j];
        }
    }

    for (int i = 0; i < 8; ++i) {
        T[i*8]   = T64[i] >> 56;
        T[i*8+1] = T64[i] >> 48;
        T[i*8+2] = T64[i] >> 40;
        T[i*8+3] = T64[i] >> 32;
        T[i*8+4] = T64[i] >> 24;
        T[i*8+5] = T64[i] >> 16;
        T[i*8+6] = T64[i] >> 8;
        T[i*8+7] = T64[i];
    }
    std::memcpy(out, T, std::min(static_cast<size_t>(64), out_len));
}

} // namespace crypto
