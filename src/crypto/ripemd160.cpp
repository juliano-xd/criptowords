#include "../../include/crypto/ripemd160.hpp"
#include <cstring>
#include <algorithm>

namespace crypto {

inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static constexpr std::array<uint32_t, 5> KL = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
static constexpr std::array<uint32_t, 5> KR = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};

static constexpr std::array<int, 80> RL = {0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
                                7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
                                3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
                                1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
                                4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13};
static constexpr std::array<int, 80> RR_ = {5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
                                 6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
                                 15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
                                 8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
                                 12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};

static constexpr std::array<int, 80> SL = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
                                7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
                                11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
                                11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
                                9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
static constexpr std::array<int, 80> SR_ = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
                                 9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
                                 9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
                                 15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
                                 8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};

inline uint32_t F1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t F2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t F3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
inline uint32_t F4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t F5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

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
        std::memcpy(buf_.data() + buf_len_, p, to_copy);
        buf_len_ += to_copy;
        p += to_copy;
        len -= to_copy;
        if (buf_len_ == 64) {
            process_block(buf_.data());
            buf_len_ = 0;
        }
    }

    while (len >= 64) {
        process_block(p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        std::memcpy(buf_.data(), p, len);
        buf_len_ = len;
    }
}

void RIPEMD160::finalize(uint8_t out[20]) {
    uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 56) {
        std::memset(buf_.data() + buf_len_, 0, 64 - buf_len_);
        process_block(buf_.data());
        buf_len_ = 0;
    }
    std::memset(buf_.data() + buf_len_, 0, 56 - buf_len_);
    for (int i = 0; i < 8; ++i) {
        buf_[56 + i] = static_cast<uint8_t>(bit_len >> (i * 8));
    }
    process_block(buf_.data());

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

[[gnu::always_inline]] static inline void ripemd160_transform_inlined(std::array<uint32_t, 5>& h, const std::array<uint32_t, 16>& X) {
    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];

    // Rodada 1 (j = 0..15): FL = F1, FR = F5
    #pragma GCC unroll 16
    for (int j = 0; j < 16; ++j) {
        uint32_t t = al + F1(bl, cl, dl) + X[RL[j]] + KL[0];
        t = rotl(t, SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = ar + F5(br, cr, dr) + X[RR_[j]] + KR[0];
        t = rotl(t, SR_[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }

    // Rodada 2 (j = 16..31): FL = F2, FR = F4
    #pragma GCC unroll 16
    for (int j = 16; j < 32; ++j) {
        uint32_t t = al + F2(bl, cl, dl) + X[RL[j]] + KL[1];
        t = rotl(t, SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = ar + F4(br, cr, dr) + X[RR_[j]] + KR[1];
        t = rotl(t, SR_[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }

    // Rodada 3 (j = 32..47): FL = F3, FR = F3
    #pragma GCC unroll 16
    for (int j = 32; j < 48; ++j) {
        uint32_t t = al + F3(bl, cl, dl) + X[RL[j]] + KL[2];
        t = rotl(t, SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = ar + F3(br, cr, dr) + X[RR_[j]] + KR[2];
        t = rotl(t, SR_[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }

    // Rodada 4 (j = 48..63): FL = F4, FR = F2
    #pragma GCC unroll 16
    for (int j = 48; j < 64; ++j) {
        uint32_t t = al + F4(bl, cl, dl) + X[RL[j]] + KL[3];
        t = rotl(t, SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = ar + F2(br, cr, dr) + X[RR_[j]] + KR[3];
        t = rotl(t, SR_[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }

    // Rodada 5 (j = 64..79): FL = F5, FR = F1
    #pragma GCC unroll 16
    for (int j = 64; j < 80; ++j) {
        uint32_t t = al + F5(bl, cl, dl) + X[RL[j]] + KL[4];
        t = rotl(t, SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = ar + F1(br, cr, dr) + X[RR_[j]] + KR[4];
        t = rotl(t, SR_[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }

    uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

void RIPEMD160::process_block(const uint8_t block[64]) {
    std::array<uint32_t, 16> X;
    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) {
        X[i] = (uint32_t(block[i * 4])) | (uint32_t(block[i * 4 + 1]) << 8) |
               (uint32_t(block[i * 4 + 2]) << 16) | (uint32_t(block[i * 4 + 3]) << 24);
    }
    ripemd160_transform_inlined(h_, X);
}

void RIPEMD160::hash32(const std::array<uint8_t, 32> &in, std::array<uint8_t, 20> &out) noexcept {
    std::array<uint32_t, 16> X;
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        X[i] = (uint32_t(in[i * 4])) | (uint32_t(in[i * 4 + 1]) << 8) |
               (uint32_t(in[i * 4 + 2]) << 16) | (uint32_t(in[i * 4 + 3]) << 24);
    }
    X[8] = 0x00000080;
    X[9] = 0; X[10] = 0; X[11] = 0; X[12] = 0; X[13] = 0;
    X[14] = 256; // 32 * 8 = 256 bits
    X[15] = 0;

    std::array<uint32_t, 5> h = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    ripemd160_transform_inlined(h, X);

    #pragma GCC unroll 5
    for (int i = 0; i < 5; ++i) {
        out[i * 4]     = static_cast<uint8_t>(h[i]);
        out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 8);
        out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 16);
        out[i * 4 + 3] = static_cast<uint8_t>(h[i] >> 24);
    }
}

} // namespace crypto
