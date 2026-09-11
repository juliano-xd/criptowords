#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include "sha256.hpp"
#include "sha512.hpp"
#include "pbkdf2_simd.hpp"

// SHA-NI intrinsics (Intel SHA Extensions)
#include <immintrin.h>

namespace crypto {





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
    Keccak256() { reset(); }
    void reset() {
        for (int i = 0; i < 25; ++i) A_[i] = 0;
        buf_len_ = 0;
    }

    void update(const void* data, size_t len) {
        auto p = static_cast<const uint8_t*>(data);
        size_t rate = 136;
        while (len > 0) {
            size_t copy = std::min(len, rate - buf_len_);
            for (size_t i = 0; i < copy; ++i) {
                buf_[buf_len_ + i] = p[i];
            }
            buf_len_ += copy;
            p += copy;
            len -= copy;
            if (buf_len_ == rate) {
                for (size_t i = 0; i < rate / 8; ++i) {
                    A_[i] ^= le64dec(buf_ + i * 8);
                }
                keccakf1600(A_);
                buf_len_ = 0;
            }
        }
    }

    void finalize(uint8_t out[32]) {
        size_t rate = 136;
        buf_[buf_len_] = 0x01; // Keccak padding (Ethereum)
        for (size_t i = buf_len_ + 1; i < rate; ++i) {
            buf_[i] = 0;
        }
        buf_[rate - 1] |= 0x80;

        for (size_t i = 0; i < rate / 8; ++i) {
            A_[i] ^= le64dec(buf_ + i * 8);
        }
        keccakf1600(A_);

        for (int i = 0; i < 4; ++i) {
            le64enc(out + i * 8, A_[i]);
        }
    }

    static void hash(const void* data, size_t len, uint8_t out[32]) {
        Keccak256 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

  private:
    uint64_t A_[25];
    uint8_t buf_[136];
    size_t buf_len_;

    static inline uint64_t le64dec(const void* buf) {
        auto p = static_cast<const uint8_t*>(buf);
        return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
               (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
               (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
               (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
    }

    static inline void le64enc(void* buf, uint64_t v) {
        auto p = static_cast<uint8_t*>(buf);
        p[0] = static_cast<uint8_t>(v); p[1] = static_cast<uint8_t>(v >> 8);
        p[2] = static_cast<uint8_t>(v >> 16); p[3] = static_cast<uint8_t>(v >> 24);
        p[4] = static_cast<uint8_t>(v >> 32); p[5] = static_cast<uint8_t>(v >> 40);
        p[6] = static_cast<uint8_t>(v >> 48); p[7] = static_cast<uint8_t>(v >> 56);
    }

    static inline uint64_t rotl64(uint64_t x, int n) {
        return (x << (n % 64)) | (x >> (64 - (n % 64)));
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

        static const int R[25] = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

        for (int i = 0; i < 24; ++i) {
            uint64_t C[5], D[5];
            for (int x = 0; x < 5; ++x) {
                C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            }
            for (int x = 0; x < 5; ++x) {
                D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            }
            for (int x = 0; x < 5; ++x) {
                for (int y = 0; y < 5; ++y) {
                    A[x + y * 5] ^= D[x];
                }
            }
            
            uint64_t B[25];
            for (int x = 0; x < 5; ++x) {
                for (int y = 0; y < 5; ++y) {
                    B[y + ((2 * x + 3 * y) % 5) * 5] = rotl64(A[x + y * 5], R[x + y * 5]);
                }
            }
            
            for (int x = 0; x < 5; ++x) {
                for (int y = 0; y < 5; ++y) {
                    A[x + y * 5] = B[x + y * 5] ^ (~B[((x + 1) % 5) + y * 5] & B[((x + 2) % 5) + y * 5]);
                }
            }
            A[0] ^= RC[i];
        }
    }
};

} // namespace crypto
