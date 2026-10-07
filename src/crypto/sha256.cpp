#include "../../include/crypto/sha256.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "../../include/crypto/sha256_shani.hpp"
#include "../../include/simd/cpu_features.hpp"

// Nota de portabilidade: as rotinas abaixo (sha256_transform_sse/avx2/avx512)
// operam sobre o estado INTERLEAVED (state[palavra][lane]). São usadas apenas
// pelo filtro de checksum em lote. Em plataformas sem SIMD, ou quando as
// versões vetorizadas nativas não estão disponíveis no binário, caem no
// mesmo caminho escalar lane-a-lane — comportamento correto, só mais lento.

alignas(64) static constexpr std::array<uint32_t, 64> K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static constexpr std::array<uint32_t, 8> SHA256_IV = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

template <size_t LANES>
constexpr inline void sha256_init_simd(std::array<std::array<uint32_t, LANES>, 8>& arr) noexcept {
    for (size_t i = 0; i < 8; ++i)
        for (size_t l = 0; l < LANES; ++l)
            arr[i][l] = SHA256_IV[i];
}

void sha256_init_sse(SHA256_SSE_State* ctx)         { sha256_init_simd<4>(ctx->state); }
void sha256_init_avx2(SHA256_AVX2_State* ctx)       { sha256_init_simd<8>(ctx->state); }
void sha256_init_avx512(SHA256_AVX512_State* ctx)   { sha256_init_simd<16>(ctx->state); }

// =========================================================================
// Fallback escalar para as versões SIMD do transform. Aceita tanto
// std::array<std::array<...>> (usado por SSE) quanto uint32_t[16][N] cru
// (usado por AVX2/AVX512) via template genérico.
// =========================================================================
namespace sha256_scalar_fallback {

[[gnu::always_inline]] inline uint32_t ror(uint32_t x, int n) noexcept { return std::rotr(x, n); }
[[gnu::always_inline]] inline uint32_t bsig0(uint32_t x) noexcept { return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22); }
[[gnu::always_inline]] inline uint32_t bsig1(uint32_t x) noexcept { return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25); }
[[gnu::always_inline]] inline uint32_t ssig0(uint32_t x) noexcept { return ror(x, 7) ^ ror(x, 18) ^ (x >> 3); }
[[gnu::always_inline]] inline uint32_t ssig1(uint32_t x) noexcept { return ror(x, 17) ^ ror(x, 19) ^ (x >> 10); }
[[gnu::always_inline]] inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (~x & z); }
[[gnu::always_inline]] inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }

// W_in pode ser std::array<std::array<uint32_t,Lanes>,16> ou uint32_t[16][Lanes].
// Em ambos os casos, W_in[t][lane] é uint32_t.
template <unsigned Lanes, typename WArray>
inline void transform_lanes(std::array<std::array<uint32_t, Lanes>, 8>& state,
                            const WArray& W_in) noexcept {
    for (unsigned lane = 0; lane < Lanes; ++lane) {
        std::array<uint32_t, 64> W;
#pragma GCC unroll 16
        for (int t = 0; t < 16; ++t) W[t] = W_in[t][lane];
#pragma GCC unroll 48
        for (int t = 16; t < 64; ++t)
            W[t] = ssig1(W[t - 2]) + W[t - 7] + ssig0(W[t - 15]) + W[t - 16];

        uint32_t a = state[0][lane], b = state[1][lane], c = state[2][lane], d = state[3][lane];
        uint32_t e = state[4][lane], f = state[5][lane], g = state[6][lane], h = state[7][lane];

#pragma GCC unroll 64
        for (int t = 0; t < 64; ++t) {
            const uint32_t T1 = h + bsig1(e) + ch(e, f, g) + K256[t] + W[t];
            const uint32_t T2 = bsig0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
        state[0][lane] += a; state[1][lane] += b; state[2][lane] += c; state[3][lane] += d;
        state[4][lane] += e; state[5][lane] += f; state[6][lane] += g; state[7][lane] += h;
    }
}

}  // namespace sha256_scalar_fallback

void sha256_transform_sse(SHA256_SSE_State* ctx,
                          const std::array<std::array<uint32_t, 4>, 16>& W_in) {
    sha256_scalar_fallback::transform_lanes<4>(ctx->state, W_in);
}
void sha256_transform_avx2(SHA256_AVX2_State* ctx, const uint32_t W_in[16][8]) {
    sha256_scalar_fallback::transform_lanes<8>(ctx->state, W_in);
}
void sha256_transform_avx512(SHA256_AVX512_State* ctx, const uint32_t W_in[16][16]) {
    sha256_scalar_fallback::transform_lanes<16>(ctx->state, W_in);
}

// =========================================================================
// Implementação escalar principal (sempre compilada).
// =========================================================================
namespace crypto {

[[gnu::always_inline]] static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
[[gnu::always_inline]] static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
[[gnu::always_inline]] static inline uint32_t Sigma0(uint32_t x) { return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22); }
[[gnu::always_inline]] static inline uint32_t Sigma1(uint32_t x) { return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25); }
[[gnu::always_inline]] static inline uint32_t sigma0(uint32_t x) { return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3); }
[[gnu::always_inline]] static inline uint32_t sigma1(uint32_t x) { return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10); }

SHA256::SHA256() { reset(); }

void SHA256::reset() {
#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) h_[i] = SHA256_IV[i];
    total_len_ = 0;
    buf_len_ = 0;
}

void SHA256::update(const void* data, size_t len) {
    auto p = static_cast<const uint8_t*>(data);
    total_len_ += len;

    if (buf_len_ > 0) {
        size_t to_copy = std::min(len, static_cast<size_t>(64) - buf_len_);
        std::memcpy(buf_ + buf_len_, p, to_copy);
        buf_len_ += to_copy;
        p += to_copy;
        len -= to_copy;
        if (buf_len_ == 64) { process_block(buf_); buf_len_ = 0; }
    }

    while (len >= 64) { process_block(p); p += 64; len -= 64; }

    if (len > 0) { std::memcpy(buf_, p, len); buf_len_ = len; }
}

void SHA256::finalize(uint8_t out[32]) {
    uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 56) {
        std::memset(buf_ + buf_len_, 0, 64 - buf_len_);
        process_block(buf_);
        buf_len_ = 0;
    }
    std::memset(buf_ + buf_len_, 0, 56 - buf_len_);

    uint64_t bit_len_be = std::byteswap(bit_len);
    std::memcpy(buf_ + 56, &bit_len_be, 8);
    process_block(buf_);

#pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) {
        uint32_t out_be = std::byteswap(h_[i]);
        std::memcpy(&out[i * 4], &out_be, 4);
    }
}

void SHA256::hash(const void* data, size_t len, uint8_t out[32]) {
    if (len <= 55) {
        alignas(16) uint8_t block[64] = {0};
        if (len != 0) std::memcpy(block, data, len);
        block[len] = 0x80;
        uint64_t bit_len_be = __builtin_bswap64(static_cast<uint64_t>(len) * 8);
        std::memcpy(block + 56, &bit_len_be, 8);

#if defined(CRYPTOWORDS_HAS_SHANI_INTRINSICS)
        if (cryptowords::cpu::has_sha_ni()) {
            std::array<uint32_t, 8> state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
            cryptowords::detail::sha256_process_x86(state.data(), block, 64);
#pragma GCC unroll 8
            for (int i = 0; i < 8; ++i) {
                uint32_t out_be = __builtin_bswap32(state[i]);
                std::memcpy(out + i * 4, &out_be, 4);
            }
            return;
        }
#endif
        SHA256 ctx;
        ctx.process_block(block);
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            uint32_t out_be = __builtin_bswap32(ctx.h_[i]);
            std::memcpy(out + i * 4, &out_be, 4);
        }
        return;
    }
    SHA256 ctx;
    ctx.update(data, len);
    ctx.finalize(out);
}

void SHA256::hash33(const std::array<uint8_t, 33>& in, std::array<uint8_t, 32>& out) noexcept {
    hash(in.data(), 33, out.data());
}

void SHA256::process_block(const uint8_t block[64]) {
    uint32_t W[64];
#pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) {
        std::memcpy(&W[i], &block[i * 4], 4);
        W[i] = std::byteswap(W[i]);
    }
#pragma GCC unroll 48
    for (int i = 16; i < 64; ++i)
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

#pragma GCC unroll 64
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K256[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

}  // namespace crypto

// =========================================================================
// Fallback não-x86 (Termux/ARM) para as rotinas "shani".
// =========================================================================
#if !defined(CRYPTOWORDS_HAS_SHANI_INTRINSICS)
namespace cryptowords::detail {

uint8_t sha256_bip39_first_byte_shani(const uint8_t block64[64]) {
    uint8_t hash[32];
    crypto::SHA256::hash(block64, 64, hash);
    return hash[0];
}

void sha256_process_x86(uint32_t state[8], const uint8_t data[], uint32_t length) {
    while (length >= 64) {
        uint32_t W[64];
#pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            W[i] = (uint32_t(data[i * 4]) << 24) | (uint32_t(data[i * 4 + 1]) << 16) |
                   (uint32_t(data[i * 4 + 2]) << 8)  | uint32_t(data[i * 4 + 3]);
        }
#pragma GCC unroll 48
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = std::rotr(W[i - 15], 7) ^ std::rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
            const uint32_t s1 = std::rotr(W[i - 2], 17) ^ std::rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

#pragma GCC unroll 64
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t T1 = h + S1 + ch + K256[i] + W[i];
            const uint32_t S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t T2 = S0 + maj;
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;

        data += 64;
        length -= 64;
    }
}

}  // namespace cryptowords::detail
#endif  // !CRYPTOWORDS_HAS_SHANI_INTRINSICS
