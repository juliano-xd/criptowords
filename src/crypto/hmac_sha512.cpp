#include <cstring>
#include <algorithm>
#include "../../include/crypto/hmac_sha512.hpp"

namespace crypto {

static constexpr uint64_t K512_SCALAR_FAST[80] = {
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

static inline uint64_t rotr64_f(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static inline uint64_t Ch64_f(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static inline uint64_t Maj64_f(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint64_t Sigma0_64_f(uint64_t x) { return rotr64_f(x, 28) ^ rotr64_f(x, 34) ^ rotr64_f(x, 39); }
static inline uint64_t Sigma1_64_f(uint64_t x) { return rotr64_f(x, 14) ^ rotr64_f(x, 18) ^ rotr64_f(x, 41); }
static inline uint64_t sigma0_64_f(uint64_t x) { return rotr64_f(x, 1) ^ rotr64_f(x, 8) ^ (x >> 7); }
static inline uint64_t sigma1_64_f(uint64_t x) { return rotr64_f(x, 19) ^ rotr64_f(x, 61) ^ (x >> 6); }

static inline void sha512_compress_64_fast(const uint64_t state_in[8], const uint64_t data[8], uint64_t state_out[8]) {
    uint64_t W[80];
    for (int i = 0; i < 8; ++i) {
        W[i] = data[i];
    }
    W[8] = 0x8000000000000000ULL;
    W[9] = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 1536;

    for (int i = 16; i < 80; ++i) {
        W[i] = sigma1_64_f(W[i - 2]) + W[i - 7] + sigma0_64_f(W[i - 15]) + W[i - 16];
    }

    uint64_t a = state_in[0], b = state_in[1], c = state_in[2], d = state_in[3];
    uint64_t e = state_in[4], f = state_in[5], g = state_in[6], h = state_in[7];

#define SHA512_ROUND_UNROLLED(A, B, C, D, E, F, G, H, i) \
    do { \
        uint64_t T1 = H + Sigma1_64_f(E) + Ch64_f(E, F, G) + K512_SCALAR_FAST[i] + W[i]; \
        uint64_t T2 = Sigma0_64_f(A) + Maj64_f(A, B, C); \
        D += T1; \
        H = T1 + T2; \
    } while(0)

    for (int i = 0; i < 80; i += 8) {
        SHA512_ROUND_UNROLLED(a, b, c, d, e, f, g, h, i + 0);
        SHA512_ROUND_UNROLLED(h, a, b, c, d, e, f, g, i + 1);
        SHA512_ROUND_UNROLLED(g, h, a, b, c, d, e, f, i + 2);
        SHA512_ROUND_UNROLLED(f, g, h, a, b, c, d, e, i + 3);
        SHA512_ROUND_UNROLLED(e, f, g, h, a, b, c, d, i + 4);
        SHA512_ROUND_UNROLLED(d, e, f, g, h, a, b, c, i + 5);
        SHA512_ROUND_UNROLLED(c, d, e, f, g, h, a, b, i + 6);
        SHA512_ROUND_UNROLLED(b, c, d, e, f, g, h, a, i + 7);
    }
#undef SHA512_ROUND_UNROLLED

    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
    state_out[5] = state_in[5] + f;
    state_out[6] = state_in[6] + g;
    state_out[7] = state_in[7] + h;
}

void HMAC_SHA512::init(const uint8_t* key, size_t key_len) {
    uint8_t k_hash[64];
    const uint8_t* k_use;
    size_t k_use_len;
    if (key_len > 128) {
        SHA512::hash(key, key_len, k_hash);
        k_use = k_hash;
        k_use_len = 64;
    } else {
        k_use = key;
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

    outer_base_.reset();
    outer_base_.update(opad, 128);
}

void HMAC_SHA512::update(const uint8_t* data, size_t len) {
    inner_.update(data, len);
}

void HMAC_SHA512::finalize(uint8_t* out) {
    uint8_t inner_hash[64];
    inner_.finalize(inner_hash);


    outer_base_.update(inner_hash, 64);
    outer_base_.finalize(out);
}

void HMAC_SHA512::reset_inner() {
    inner_ = HMAC_SHA512::inner_base_;
}

void pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len,
                        int iterations, uint8_t* out, size_t out_len) {
    HMAC_SHA512 hmac_base;
    hmac_base.init((const uint8_t*)password, password_len);

    HMAC_SHA512 hmac = hmac_base;
    uint8_t U[64], T[64];
    uint8_t be4[4] = {0, 0, 0, 1};

    hmac.update(salt, salt_len);
    hmac.update(be4, 4);
    hmac.finalize(U);

    // Reset inner to start the next HMAC message with the same key
    hmac.reset_inner();

    std::memcpy(T, U, 64);


    uint64_t inner_state[8];
    uint64_t outer_state[8];
    for(int i=0; i<8; i++) inner_state[i] = hmac_base.inner_base_.h_[i];
    for(int i=0; i<8; i++) outer_state[i] = hmac_base.outer_base_.h_[i];

    uint64_t U64[8];
    for(int i=0; i<8; i++) {
        U64[i] = (uint64_t(U[i*8]) << 56) | (uint64_t(U[i*8+1]) << 48) |
                 (uint64_t(U[i*8+2]) << 40) | (uint64_t(U[i*8+3]) << 32) |
                 (uint64_t(U[i*8+4]) << 24) | (uint64_t(U[i*8+5]) << 16) |
                 (uint64_t(U[i*8+6]) << 8)  | uint64_t(U[i*8+7]);
    }
    uint64_t T64[8];
    for(int i=0; i<8; i++) T64[i] = U64[i];

    for (int i = 1; i < iterations; i++) {
        uint64_t temp[8];
        sha512_compress_64_fast(inner_state, U64, temp);
        sha512_compress_64_fast(outer_state, temp, U64);
        for (int j = 0; j < 8; j++) {
            T64[j] ^= U64[j];
        }
    }

    for(int i=0; i<8; i++) {
        T[i*8]   = T64[i] >> 56;
        T[i*8+1] = T64[i] >> 48;
        T[i*8+2] = T64[i] >> 40;
        T[i*8+3] = T64[i] >> 32;
        T[i*8+4] = T64[i] >> 24;
        T[i*8+5] = T64[i] >> 16;
        T[i*8+6] = T64[i] >> 8;
        T[i*8+7] = T64[i];
    }
    std::memcpy(out, T, std::min((size_t)64, out_len));
}

} // namespace crypto
