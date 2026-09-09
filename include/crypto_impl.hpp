#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include "sha512_simd.hpp"

// SHA-NI intrinsics (Intel SHA Extensions)
#include <immintrin.h>

namespace crypto {

// ============================================================
// SHA-256 — SHA-NI quando disponível, fallback genérico
// ============================================================
class SHA256 {
  public:
    SHA256() {
        reset();
    }

    void reset() {
        h_[0] = 0x6a09e667;
        h_[1] = 0xbb67ae85;
        h_[2] = 0x3c6ef372;
        h_[3] = 0xa54ff53a;
        h_[4] = 0x510e527f;
        h_[5] = 0x9b05688c;
        h_[6] = 0x1f83d9ab;
        h_[7] = 0x5be0cd19;
        total_len_ = 0;
        buf_len_ = 0;
    }

    void update(const void* data, size_t len) {
        auto p = static_cast<const uint8_t*>(data);
        total_len_ += len;

        if (buf_len_ > 0) {
            size_t to_copy = std::min(len, 64 - buf_len_);
            std::memcpy(buf_ + buf_len_, p, to_copy);
            buf_len_ += to_copy;
            p += to_copy;
            len -= to_copy;
            if (buf_len_ == 64) {
                process_block(buf_);
                buf_len_ = 0;
            }
        }

        while (len >= 64) {
            process_block(p);
            p += 64;
            len -= 64;
        }

        if (len > 0) {
            std::memcpy(buf_, p, len);
            buf_len_ = len;
        }
    }

    void finalize(uint8_t out[32]) {
        uint64_t bit_len = total_len_ * 8;
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 56) {
            std::memset(buf_ + buf_len_, 0, 64 - buf_len_);
            process_block(buf_);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, 56 - buf_len_);
        for (int i = 7; i >= 0; --i) {
            buf_[56 + (7 - i)] = static_cast<uint8_t>(bit_len >> (i * 8));
        }
        process_block(buf_);

        for (int i = 0; i < 8; ++i) {
            out[i * 4] = static_cast<uint8_t>(h_[i] >> 24);
            out[i * 4 + 1] = static_cast<uint8_t>(h_[i] >> 16);
            out[i * 4 + 2] = static_cast<uint8_t>(h_[i] >> 8);
            out[i * 4 + 3] = static_cast<uint8_t>(h_[i]);
        }
    }

    static void hash(const void* data, size_t len, uint8_t out[32]) {
        SHA256 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

  private:
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buf_len_;
    uint64_t total_len_;

    static inline uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }
    static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint32_t Sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    static inline uint32_t Sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    static inline uint32_t sigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    static inline uint32_t sigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};

     void process_block(const uint8_t block[64]) {
        uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) | block[i * 4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += h;
    }
};

// ============================================================
// SHA-512 — reference implementation (FIPS 180-4)
// ============================================================
class SHA512 {
  public:
    SHA512() {
        reset();
    }

    void reset() {
        h_[0] = 0x6a09e667f3bcc908ULL;
        h_[1] = 0xbb67ae8584caa73bULL;
        h_[2] = 0x3c6ef372fe94f82bULL;
        h_[3] = 0xa54ff53a5f1d36f1ULL;
        h_[4] = 0x510e527fade682d1ULL;
        h_[5] = 0x9b05688c2b3e6c1fULL;
        h_[6] = 0x1f83d9abfb41bd6bULL;
        h_[7] = 0x5be0cd19137e2179ULL;
        total_len_ = 0;
        buf_len_ = 0;
    }

    void update(const void* data, size_t len) {
        auto p = static_cast<const uint8_t*>(data);
        total_len_ += len;
        if (buf_len_ > 0) {
            size_t to_copy = std::min(len, (size_t) 128 - buf_len_);
            std::memcpy(buf_ + buf_len_, p, to_copy);
            buf_len_ += to_copy;
            p += to_copy;
            len -= to_copy;
            if (buf_len_ == 128) {
                process_block(buf_);
                buf_len_ = 0;
            }
        }
        while (len >= 128) {
            process_block(p);
            p += 128;
            len -= 128;
        }
        if (len > 0) {
            std::memcpy(buf_, p, len);
            buf_len_ = len;
        }
    }

    void finalize(uint8_t out[64]) {
        uint64_t bit_len = total_len_ * 8;
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 112) {
            std::memset(buf_ + buf_len_, 0, (size_t) 128 - buf_len_);
            process_block(buf_);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, (size_t) 112 - buf_len_);
        // 128-bit big-endian length at bytes 112-127
        // High 64 bits (bytes 112-119) = 0 for messages < 2^64 bits
        std::memset(buf_ + 112, 0, 8);
        // Low 64 bits (bytes 120-127) = bit_len big-endian
        buf_[120] = (uint8_t) (bit_len >> 56);
        buf_[121] = (uint8_t) (bit_len >> 48);
        buf_[122] = (uint8_t) (bit_len >> 40);
        buf_[123] = (uint8_t) (bit_len >> 32);
        buf_[124] = (uint8_t) (bit_len >> 24);
        buf_[125] = (uint8_t) (bit_len >> 16);
        buf_[126] = (uint8_t) (bit_len >> 8);
        buf_[127] = (uint8_t) (bit_len);
        process_block(buf_);
        for (int i = 0; i < 8; ++i) {
            out[i * 8] = (uint8_t) (h_[i] >> 56);
            out[i * 8 + 1] = (uint8_t) (h_[i] >> 48);
            out[i * 8 + 2] = (uint8_t) (h_[i] >> 40);
            out[i * 8 + 3] = (uint8_t) (h_[i] >> 32);
            out[i * 8 + 4] = (uint8_t) (h_[i] >> 24);
            out[i * 8 + 5] = (uint8_t) (h_[i] >> 16);
            out[i * 8 + 6] = (uint8_t) (h_[i] >> 8);
            out[i * 8 + 7] = (uint8_t) (h_[i]);
        }
    }

    static void hash(const void* data, size_t len, uint8_t out[64]) {
        SHA512 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

    // Clone for HMAC pre-computation
    void clone_from(const SHA512& src) {
        std::memcpy(h_, src.h_, sizeof(h_));
        std::memcpy(buf_, src.buf_, sizeof(buf_));
        buf_len_ = src.buf_len_;
        total_len_ = src.total_len_;
    }

  private:
    uint64_t h_[8];
    uint8_t buf_[128];
    size_t buf_len_;
    uint64_t total_len_;

    static constexpr uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    static inline uint64_t rotr(uint64_t x, int n) {
        return (x >> n) | (x << (64 - n));
    }
    static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint64_t Sigma0(uint64_t x) {
        return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
    }
    static inline uint64_t Sigma1(uint64_t x) {
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
    }
    static inline uint64_t sigma0(uint64_t x) {
        return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
    }
    static inline uint64_t sigma1(uint64_t x) {
        return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
    }

    __attribute__((hot, optimize("O3"))) void process_block(const uint8_t block[128]) {
        uint64_t W[80];
        for (int i = 0; i < 16; ++i) {
            int o = i * 8;
            W[i] = ((uint64_t) block[o] << 56) | ((uint64_t) block[o + 1] << 48) |
                   ((uint64_t) block[o + 2] << 40) | ((uint64_t) block[o + 3] << 32) |
                   ((uint64_t) block[o + 4] << 24) | ((uint64_t) block[o + 5] << 16) |
                   ((uint64_t) block[o + 6] << 8) | (uint64_t) block[o + 7];
        }
        for (int i = 16; i < 80; ++i)
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6],
                 hh = h_[7];
        for (int i = 0; i < 80; ++i) {
            uint64_t T1 = hh + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
            uint64_t T2 = Sigma0(a) + Maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += hh;
    }
};

// ============================================================
// HMAC-SHA512
// ============================================================
class HMAC_SHA512 {
  public:
    void init(const uint8_t* key, size_t key_len) {
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

        outer_base_.reset();
        outer_base_.update(opad, 128);
    }

    void update(const uint8_t* data, size_t len) {
        inner_.update(data, len);
    }

    void finalize(uint8_t* out) {
        uint8_t inner_hash[64];
        inner_.finalize(inner_hash);

        SHA512 outer = outer_base_; // Copy state
        outer.update(inner_hash, 64);
        outer.finalize(out);
    }

    // Fast copy for reuse
    void reset_inner() {
        // Not easily doable without copying inner_base_
    }

  private:
    SHA512 inner_;
    SHA512 outer_base_;
};

// ============================================================
// PBKDF2-HMAC-SHA512 — optimized with pre-computed HMAC states
// ============================================================
__attribute__((hot, optimize("O3"))) inline void
pbkdf2_hmac_sha512(const char* password, size_t password_len, const uint8_t* salt, size_t salt_len,
                   int iterations, uint8_t* out, size_t out_len) {
    HMAC_SHA512 hmac_base;
    hmac_base.init((const uint8_t*)password, password_len);
    
    HMAC_SHA512 hmac = hmac_base;
    uint8_t U[64], T[64];
    uint8_t be4[4] = {0, 0, 0, 1};
    
    hmac.update(salt, salt_len);
    hmac.update(be4, 4);
    hmac.finalize(U);
    
    std::memcpy(T, U, 64);
    
    for (int i = 1; i < iterations; i++) {
        hmac = hmac_base; // Reuse pre-computed ipad/opad states!
        hmac.update(U, 64);
        hmac.finalize(U);
        for (int j = 0; j < 64; j++) {
            T[j] ^= U[j];
        }
    }
    std::memcpy(out, T, std::min((size_t)64, out_len));
}




// ============================================================
// RIPEMD-160
// ============================================================
class RIPEMD160 {
  public:
    RIPEMD160() {
        reset();
    }

    void reset() {
        h_[0] = 0x67452301;
        h_[1] = 0xefcdab89;
        h_[2] = 0x98badcfe;
        h_[3] = 0x10325476;
        h_[4] = 0xc3d2e1f0;
        total_len_ = 0;
        buf_len_ = 0;
    }

    void update(const void* data, size_t len) {
        auto p = static_cast<const uint8_t*>(data);
        total_len_ += len;

        if (buf_len_ > 0) {
            size_t to_copy = std::min(len, 64 - buf_len_);
            std::memcpy(buf_ + buf_len_, p, to_copy);
            buf_len_ += to_copy;
            p += to_copy;
            len -= to_copy;
            if (buf_len_ == 64) {
                process_block(buf_);
                buf_len_ = 0;
            }
        }

        while (len >= 64) {
            process_block(p);
            p += 64;
            len -= 64;
        }

        if (len > 0) {
            std::memcpy(buf_, p, len);
            buf_len_ = len;
        }
    }

    void finalize(uint8_t out[20]) {
        uint64_t bit_len = total_len_ * 8;
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 56) {
            std::memset(buf_ + buf_len_, 0, 64 - buf_len_);
            process_block(buf_);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, 56 - buf_len_);
        for (int i = 0; i < 8; ++i) {
            buf_[56 + i] = static_cast<uint8_t>(bit_len >> (i * 8));
        }
        process_block(buf_);

        for (int i = 0; i < 5; ++i) {
            out[i * 4] = static_cast<uint8_t>(h_[i]);
            out[i * 4 + 1] = static_cast<uint8_t>(h_[i] >> 8);
            out[i * 4 + 2] = static_cast<uint8_t>(h_[i] >> 16);
            out[i * 4 + 3] = static_cast<uint8_t>(h_[i] >> 24);
        }
    }

    static void hash(const void* data, size_t len, uint8_t out[20]) {
        RIPEMD160 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

  private:
    uint32_t h_[5];
    uint8_t buf_[64];
    size_t buf_len_;
    uint64_t total_len_;

    static inline uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr uint32_t KL[5] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
    static constexpr uint32_t KR[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};

    static constexpr int RL[80] = {0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
                                   7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
                                   3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
                                   1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
                                   4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13};
    static constexpr int RR_[80] = {5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
                                    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
                                    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
                                    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
                                    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};

    static constexpr int SL[80] = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
                                   7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
                                   11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
                                   11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
                                   9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
    static constexpr int SR_[80] = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
                                    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
                                    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
                                    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
                                    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};

    static inline uint32_t F1(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }
    static inline uint32_t F2(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }
    static inline uint32_t F3(uint32_t x, uint32_t y, uint32_t z) {
        return (x | ~y) ^ z;
    }
    static inline uint32_t F4(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }
    static inline uint32_t F5(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ (y | ~z);
    }

    using RoundFn = uint32_t (*)(uint32_t, uint32_t, uint32_t);
    static constexpr RoundFn FL[5] = {F1, F2, F3, F4, F5};
    static constexpr RoundFn FR[5] = {F5, F4, F3, F2, F1};

    void process_block(const uint8_t block[64]) {
        uint32_t X[16];
        for (int i = 0; i < 16; ++i) {
            X[i] = (uint32_t(block[i * 4])) | (uint32_t(block[i * 4 + 1]) << 8) |
                   (uint32_t(block[i * 4 + 2]) << 16) | (uint32_t(block[i * 4 + 3]) << 24);
        }

        uint32_t al = h_[0], bl = h_[1], cl = h_[2], dl = h_[3], el = h_[4];
        uint32_t ar = h_[0], br = h_[1], cr = h_[2], dr = h_[3], er = h_[4];

        for (int j = 0; j < 80; ++j) {
            int round = j / 16;
            uint32_t t = al + FL[round](bl, cl, dl) + X[RL[j]] + KL[round];
            t = rotl(t, SL[j]) + el;
            al = el;
            el = dl;
            dl = rotl(cl, 10);
            cl = bl;
            bl = t;

            t = ar + FR[round](br, cr, dr) + X[RR_[j]] + KR[round];
            t = rotl(t, SR_[j]) + er;
            ar = er;
            er = dr;
            dr = rotl(cr, 10);
            cr = br;
            br = t;
        }

        uint32_t t = h_[1] + cl + dr;
        h_[1] = h_[2] + dl + er;
        h_[2] = h_[3] + el + ar;
        h_[3] = h_[4] + al + br;
        h_[4] = h_[0] + bl + cr;
        h_[0] = t;
    }
};

// ============================================================
// Keccak-256 — Usado para derivação de endereços Ethereum
// ============================================================
class Keccak256 {
  public:
    Keccak256() {
        reset();
    }

    void reset() {
        for (int i = 0; i < 25; ++i)
            A_[i] = 0;
        rate_bytes_ = 136;
        nb_ = 8 * rate_bytes_;
    }

    void update(const void* data, size_t len) {
        auto p = static_cast<const uint8_t*>(data);
        size_t left_bytes = nb_ / 8;
        size_t left_bits = nb_ % 8;

        if (left_bytes > 0 || left_bits > 0) {
            size_t copy = std::min(len, 8 - left_bytes);
            if (left_bits > 0) {
                uint64_t T = 0;
                for (size_t i = 0; i < copy; ++i)
                    T |= static_cast<uint64_t>(p[i]) << (8 * (left_bytes + i));
                A_[rate_bytes_ / 8 - 1] ^= T << (8 * (8 - left_bits - copy));
            } else {
                for (size_t i = 0; i < copy; ++i)
                    A_[rate_bytes_ / 8 - 1] ^= static_cast<uint64_t>(p[i])
                                               << (8 * (7 - left_bytes - i));
            }
            nb_ += copy * 8;
            p += copy;
            len -= copy;
            if (nb_ == 8 * rate_bytes_) {
                keccakf1600(A_);
                nb_ = 0;
            }
            if (len == 0)
                return;
        }

        while (len >= rate_bytes_) {
            for (size_t iw = 0; iw < rate_bytes_ / 8; ++iw)
                A_[iw] ^= le64dec(p + 8 * iw);
            keccakf1600(A_);
            p += rate_bytes_;
            len -= rate_bytes_;
        }

        if (len > 0) {
            nb_ = 0;
            for (size_t i = 0; i < len; ++i) {
                nb_ += 8;
                A_[rate_bytes_ / 8 - 1] ^= static_cast<uint64_t>(p[i]) << (8 * (7 - i));
            }
        }
    }

    void finalize(uint8_t out[32]) {
        if (nb_ > 0) {
            A_[rate_bytes_ / 8 - 1] ^= 0x8000000000000000ULL;
        }
        keccakf1600(A_);

        for (int iw = 0; iw < 4; ++iw)
            le64enc(out + 8 * iw, A_[iw]);
    }

    static void hash(const void* data, size_t len, uint8_t out[32]) {
        Keccak256 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

  private:
    uint64_t A_[25];
    size_t rate_bytes_;
    size_t nb_;

    static inline uint64_t le64dec(const void* buf) {
        auto p = static_cast<const uint8_t*>(buf);
        return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
               (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
               (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
               (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
    }

    static inline void le64enc(void* buf, uint64_t v) {
        auto p = static_cast<uint8_t*>(buf);
        p[0] = static_cast<uint8_t>(v);
        p[1] = static_cast<uint8_t>(v >> 8);
        p[2] = static_cast<uint8_t>(v >> 16);
        p[3] = static_cast<uint8_t>(v >> 24);
        p[4] = static_cast<uint8_t>(v >> 32);
        p[5] = static_cast<uint8_t>(v >> 40);
        p[6] = static_cast<uint8_t>(v >> 48);
        p[7] = static_cast<uint8_t>(v >> 56);
    }

    static inline uint64_t rotl64(uint64_t x, int n) {
        return (x << n) | (x >> (64 - n));
    }

    static void keccakf1600(uint64_t A[25]) {
        static const uint64_t RC[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

        for (int i = 0; i < 24; ++i) {
            uint64_t C[5];
            for (int y = 0; y < 5; ++y)
                C[y] = A[y] ^ A[5 + y] ^ A[10 + y] ^ A[15 + y] ^ A[20 + y];

            for (int y = 0; y < 5; ++y) {
                uint64_t D = C[(y + 4) % 5] ^ rotl64(C[(y + 1) % 5], 1);
                for (int x = 0; x < 5; ++x)
                    A[x * 5 + y] ^= D;
            }

            uint64_t B[25];
            for (int x = 0; x < 5; ++x)
                for (int y = 0; y < 5; ++y)
                    B[y * 5 + ((2 * x + 3 * y) % 5)] =
                        rotl64(A[x * 5 + y], static_cast<int>((x + 5 - y) % 5 * (y + 1)));

            for (int x = 0; x < 5; ++x)
                for (int y = 0; y < 5; ++y)
                    A[x * 5 + y] =
                        B[x * 5 + y] ^ (~B[((x + 1) % 5) * 5 + y] & B[((x + 2) % 5) * 5 + y]);

            A[0] ^= RC[i];
        }
    }
};

} // namespace crypto
