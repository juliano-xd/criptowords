#include "../../include/crypto/keccak256.hpp"

namespace crypto {

inline uint64_t Keccak256::le64dec(const void* buf) {
    auto p = static_cast<const uint8_t*>(buf);
    return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
}

inline void Keccak256::le64enc(void* buf, uint64_t v) {
    auto p = static_cast<uint8_t*>(buf);
    p[0] = static_cast<uint8_t>(v); p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16); p[3] = static_cast<uint8_t>(v >> 24);
    p[4] = static_cast<uint8_t>(v >> 32); p[5] = static_cast<uint8_t>(v >> 40);
    p[6] = static_cast<uint8_t>(v >> 48); p[7] = static_cast<uint8_t>(v >> 56);
}

inline uint64_t Keccak256::rotl64(uint64_t x, int n) {
    int mod = n % 64;
    if (mod == 0) return x;
    return (x << mod) | (x >> (64 - mod));
}

void Keccak256::keccakf1600(uint64_t A[25]) {
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

Keccak256::Keccak256() { reset(); }

void Keccak256::reset() {
    for (int i = 0; i < 25; ++i) A_[i] = 0;
    buf_len_ = 0;
}

void Keccak256::update(const void* data, size_t len) {
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

void Keccak256::finalize(uint8_t out[32]) {
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

void Keccak256::hash(const void* data, size_t len, uint8_t out[32]) {
    Keccak256 ctx;
    ctx.update(data, len);
    ctx.finalize(out);
}

} // namespace crypto
