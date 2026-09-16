#include "../../include/crypto/ripemd160.hpp"
#include <cstring>
#include <algorithm>

namespace crypto {

inline uint32_t rotl(uint32_t x, int n) {
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

inline uint32_t F1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t F2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t F3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
inline uint32_t F4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t F5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

using RoundFn = uint32_t (*)(uint32_t, uint32_t, uint32_t);
static constexpr RoundFn FL[5] = {F1, F2, F3, F4, F5};
static constexpr RoundFn FR[5] = {F5, F4, F3, F2, F1};

RIPEMD160::RIPEMD160() {
    reset();
}

void RIPEMD160::reset() {
    h_[0] = 0x67452301;
    h_[1] = 0xefcdab89;
    h_[2] = 0x98badcfe;
    h_[3] = 0x10325476;
    h_[4] = 0xc3d2e1f0;
    total_len_ = 0;
    buf_len_ = 0;
}

void RIPEMD160::update(const void* data, size_t len) {
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

void RIPEMD160::finalize(uint8_t out[20]) {
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

void RIPEMD160::hash(const void* data, size_t len, uint8_t out[20]) {
    RIPEMD160 ctx;
    ctx.update(data, len);
    ctx.finalize(out);
}

void RIPEMD160::process_block(const uint8_t block[64]) {
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

} // namespace crypto
