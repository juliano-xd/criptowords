#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#endif

namespace crypto {

class HMAC_SHA512;

class SHA512 {
    friend class HMAC_SHA512;

   public:
    using byte = std::uint8_t;
    using word = std::uint64_t;

    static constexpr std::size_t digest_size = 64;
    static constexpr std::size_t block_size  = 128;

   private:
#if defined(__GNUC__) || defined(__clang__)
#define SHA512_FORCE_INLINE inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define SHA512_FORCE_INLINE __forceinline
#else
#define SHA512_FORCE_INLINE inline
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define SHA512_UNROLL16 _Pragma("GCC unroll 16")
#elif defined(__clang__)
#define SHA512_UNROLL16 _Pragma("clang loop unroll_count(16)")
#else
#define SHA512_UNROLL16
#endif

    static constexpr std::array<word, 8> IV_{
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    static constexpr std::array<word, 80> K_{
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

    alignas(64) std::array<word, 8> h_{};
    alignas(64) std::array<byte, block_size> buffer_{};
    std::uint64_t total_lo_ = 0;
    std::uint64_t total_hi_ = 0;
    std::size_t   buffer_size_ = 0;

    // Cache para hash de um único bloco com sufixo fixo (usado por HMAC).
    bool template_single_block_ = false;
    std::size_t template_suffix_len_ = 0;
    std::uint32_t template_skip_ = 16;
    alignas(64) std::array<word, 16> template_w_{};
    alignas(64) std::array<word, 8>  template_mid_{};

    static constexpr word bswap64(word x) noexcept {
#if defined(__cpp_lib_byteswap) && __cpp_lib_byteswap >= 202110L
        return std::byteswap(x);
#else
        return ((x & 0x00000000000000FFULL) << 56) | ((x & 0x000000000000FF00ULL) << 40) |
               ((x & 0x0000000000FF0000ULL) << 24) | ((x & 0x00000000FF000000ULL) << 8) |
               ((x & 0x000000FF00000000ULL) >> 8)  | ((x & 0x0000FF0000000000ULL) >> 24) |
               ((x & 0x00FF000000000000ULL) >> 40) | ((x & 0xFF00000000000000ULL) >> 56);
#endif
    }

   public:
    SHA512_FORCE_INLINE static word load_be64(const void* p) noexcept {
        word v;
        std::memcpy(&v, p, sizeof(v));
        if constexpr (std::endian::native == std::endian::little) v = bswap64(v);
        return v;
    }

    SHA512_FORCE_INLINE static void store_be64(void* p, word v) noexcept {
        if constexpr (std::endian::native == std::endian::little) v = bswap64(v);
        std::memcpy(p, &v, sizeof(v));
    }

    SHA512_FORCE_INLINE static word ch(word x, word y, word z) noexcept { return z ^ (x & (y ^ z)); }
    SHA512_FORCE_INLINE static word maj(word x, word y, word z) noexcept { return (x & y) | (z & (x | y)); }
    SHA512_FORCE_INLINE static word big0(word x) noexcept { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); }
    SHA512_FORCE_INLINE static word big1(word x) noexcept { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); }
    SHA512_FORCE_INLINE static word small0(word x) noexcept { return std::rotr(x, 1) ^ std::rotr(x, 8) ^ (x >> 7); }
    SHA512_FORCE_INLINE static word small1(word x) noexcept { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }

    SHA512_FORCE_INLINE static void round(word& a, word& b, word& c, word& d, word& e, word& f, word& g, word& h,
                                          word k, word w) noexcept {
        const word kw = k + w;
        const word h_kw = h + kw;
        const word e_terms = big1(e) + ch(e, f, g);
        const word t1 = h_kw + e_terms;
        const word t2 = big0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    static void compress(std::array<word, 8>& state, const byte* block) noexcept {
        alignas(64) word w[16];
        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i) w[i] = load_be64(block + (i << 3));

        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];

        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i) round(a, b, c, d, e, f, g, h, K_[i], w[i]);

        SHA512_UNROLL16
        for (unsigned t = 16; t < 80; ++t) {
            const unsigned i = t & 15;
            w[i] += small0(w[(i + 1) & 15]) + w[(i + 9) & 15] + small1(w[(i + 14) & 15]);
            round(a, b, c, d, e, f, g, h, K_[t], w[i]);
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    static void compress_words(std::array<word, 8>& state, const word w_in[16]) noexcept {
        alignas(64) word w[16];
        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i) w[i] = w_in[i];

        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];

        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i) round(a, b, c, d, e, f, g, h, K_[i], w[i]);

        SHA512_UNROLL16
        for (unsigned t = 16; t < 80; ++t) {
            const unsigned i = t & 15;
            w[i] += small0(w[(i + 1) & 15]) + w[(i + 9) & 15] + small1(w[(i + 14) & 15]);
            round(a, b, c, d, e, f, g, h, K_[t], w[i]);
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    static void compress_from(std::array<word, 8>& state, std::array<word, 16>& w,
                              std::uint32_t first_round) noexcept {
        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];

        for (std::uint32_t t = first_round; t < 16; ++t)
            round(a, b, c, d, e, f, g, h, K_[t], w[t]);

        SHA512_UNROLL16
        for (std::uint32_t t = 16; t < 80; ++t) {
            const unsigned i = t & 15;
            w[i] += small0(w[(i + 1) & 15]) + w[(i + 9) & 15] + small1(w[(i + 14) & 15]);
            round(a, b, c, d, e, f, g, h, K_[t], w[i]);
        }

        state[0] = a; state[1] = b; state[2] = c; state[3] = d;
        state[4] = e; state[5] = f; state[6] = g; state[7] = h;
    }

#define SHA512_STEP_SCALAR(k_term, w_val)                                                                              \
    do {                                                                                                               \
        word T1 = (h) + (k_term) + (w_val) + big1(e) + ch(e, f, g);                                                    \
        word T2 = big0(a) + maj(a, b, c);                                                                              \
        h = g; g = f; f = e; e = d + T1;                                                                               \
        d = c; c = b; b = a; a = T1 + T2;                                                                              \
    } while (0)

#define SHA512_STEP_FUSED_SCALAR(k_fused)                                                                              \
    do {                                                                                                               \
        word T1 = (h) + (k_fused) + big1(e) + ch(e, f, g);                                                             \
        word T2 = big0(a) + maj(a, b, c);                                                                              \
        h = g; g = f; f = e; e = d + T1;                                                                               \
        d = c; c = b; b = a; a = T1 + T2;                                                                              \
    } while (0)

    // Compress de um único bloco já "pad-ado": 8 primeiras words preenchidas,
    // padding 0x80||...||bit_len já embutido nos índices 8..15.
    SHA512_FORCE_INLINE static void compress_padded_block64(const word iv[8], word W[16], word out[8]) noexcept {
        word a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];

        SHA512_STEP_SCALAR(K_[0], W[0]); W[0] += small0(W[1]);
        SHA512_STEP_SCALAR(K_[1], W[1]); W[1] += small0(W[2]) + 0xc0000000003018;
        SHA512_STEP_SCALAR(K_[2], W[2]); W[2] += small0(W[3]) + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]); W[3] += small0(W[4]) + small1(W[1]);
        SHA512_STEP_SCALAR(K_[4], W[4]); W[4] += small0(W[5]) + small1(W[2]);
        SHA512_STEP_SCALAR(K_[5], W[5]); W[5] += small0(W[6]) + small1(W[3]);
        SHA512_STEP_SCALAR(K_[6], W[6]); W[6] += small0(W[7]) + 0x600 + small1(W[4]);
        SHA512_STEP_SCALAR(K_[7], W[7]); W[7] += 0x4180000000000000ULL + W[0] + small1(W[5]);

        SHA512_STEP_FUSED_SCALAR(0x5807aa98a3030242);          // K_[8] + 0x8000... (padding W[8])
        W[8]  = 0x8000000000000000ULL + W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9]);  W[9]  = W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10]); W[10] = W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11]); W[11] = W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12]); W[12] = W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13]); W[13] = W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14]); W[14] = 0x30a + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(0xc19bf174cf692c94);          // K_[15] + 0x600 (bit_len 1024)
        W[15] = 0x600 + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g; g = f; f = e; e = d + T1;
                d = c; c = b; b = a; a = T1 + T2;
                if (r < 4) {
                    W[i] = W[i] + W[(i + 9) & 15] + small0(W[(i + 1) & 15]) + small1(W[(i + 14) & 15]);
                }
            }
        }

        out[0] = iv[0] + a; out[1] = iv[1] + b;
        out[2] = iv[2] + c; out[3] = iv[3] + d;
        out[4] = iv[4] + e; out[5] = iv[5] + f;
        out[6] = iv[6] + g; out[7] = iv[7] + h;
    }

    // Compress de um bloco de 37 bytes (usado por HMAC-SHA512 bip32).
    SHA512_FORCE_INLINE static void compress_padded_block37(const word iv[8], word W[16], word out[8]) noexcept {
        constexpr word C_W15_37      = 1320ULL;
        constexpr word C_S0_1320     = (std::rotr(1320ULL, 1) ^ std::rotr(1320ULL, 8) ^ (1320ULL >> 7));
        constexpr word C_S1_1320     = (std::rotr(1320ULL, 19) ^ std::rotr(1320ULL, 61) ^ (1320ULL >> 6));
        constexpr word K_FUSED_15_37 = 0xc19bf174cf692694ULL + 1320ULL;

        word a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];

        SHA512_STEP_SCALAR(K_[0], W[0]); W[0] += small0(W[1]);
        SHA512_STEP_SCALAR(K_[1], W[1]); W[1] += small0(W[2]) + C_S1_1320;
        SHA512_STEP_SCALAR(K_[2], W[2]); W[2] += small0(W[3]) + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]); W[3] += small0(W[4]) + small1(W[1]);
        SHA512_STEP_SCALAR(K_[4], W[4]); W[4] += small1(W[2]);

        SHA512_STEP_FUSED_SCALAR(K_[5]);  W[5]  = small1(W[3]);
        SHA512_STEP_FUSED_SCALAR(K_[6]);  W[6]  = C_W15_37 + small1(W[4]);
        SHA512_STEP_FUSED_SCALAR(K_[7]);  W[7]  = W[0] + small1(W[5]);
        SHA512_STEP_FUSED_SCALAR(K_[8]);  W[8]  = W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9]);  W[9]  = W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10]); W[10] = W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11]); W[11] = W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12]); W[12] = W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13]); W[13] = W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14]); W[14] = C_S0_1320 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_FUSED_15_37);
        W[15] = C_W15_37 + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g; g = f; f = e; e = d + T1;
                d = c; c = b; b = a; a = T1 + T2;
                if (r < 4) W[i] += small0(W[(i + 1) & 15]) + W[(i + 9) & 15] + small1(W[(i + 14) & 15]);
            }
        }

        out[0] = iv[0] + a; out[1] = iv[1] + b;
        out[2] = iv[2] + c; out[3] = iv[3] + d;
        out[4] = iv[4] + e; out[5] = iv[5] + f;
        out[6] = iv[6] + g; out[7] = iv[7] + h;
    }

    // HMAC ipad/opad com chave de 32 B.
    template <word PAD>
    SHA512_FORCE_INLINE static void compress_pad128_32bytekey(const word key_words[4], word out[8]) noexcept {
        constexpr word C_S0_PAD       = (std::rotr(PAD, 1) ^ std::rotr(PAD, 8) ^ (PAD >> 7));
        constexpr word C_S1_PAD       = (std::rotr(PAD, 19) ^ std::rotr(PAD, 61) ^ (PAD >> 6));
        constexpr word C_PAD_PLUS_S1  = PAD + C_S1_PAD;
        constexpr word C_PAD_PLUS_S0  = PAD + C_S0_PAD;
        constexpr word C_2PAD_PLUS_S0 = PAD + PAD + C_S0_PAD;

        word W[16];
        W[0] = key_words[0] ^ PAD;
        W[1] = key_words[1] ^ PAD;
        W[2] = key_words[2] ^ PAD;
        W[3] = key_words[3] ^ PAD;

        word a = IV_[0], b = IV_[1], c = IV_[2], d = IV_[3];
        word e = IV_[4], f = IV_[5], g = IV_[6], h = IV_[7];

        SHA512_STEP_SCALAR(K_[0], W[0]); W[0] += small0(W[1]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[1], W[1]); W[1] += small0(W[2]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[2], W[2]); W[2] += small0(W[3]) + PAD + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]); W[3] += C_PAD_PLUS_S0 + small1(W[1]);

        SHA512_STEP_FUSED_SCALAR(K_[4]  + PAD); W[4]  = C_2PAD_PLUS_S0 + small1(W[2]);
        SHA512_STEP_FUSED_SCALAR(K_[5]  + PAD); W[5]  = C_2PAD_PLUS_S0 + small1(W[3]);
        SHA512_STEP_FUSED_SCALAR(K_[6]  + PAD); W[6]  = C_2PAD_PLUS_S0 + small1(W[4]);
        SHA512_STEP_FUSED_SCALAR(K_[7]  + PAD); W[7]  = C_PAD_PLUS_S0 + W[0] + small1(W[5]);
        SHA512_STEP_FUSED_SCALAR(K_[8]  + PAD); W[8]  = C_PAD_PLUS_S0 + W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9]  + PAD); W[9]  = C_PAD_PLUS_S0 + W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10] + PAD); W[10] = C_PAD_PLUS_S0 + W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11] + PAD); W[11] = C_PAD_PLUS_S0 + W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12] + PAD); W[12] = C_PAD_PLUS_S0 + W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13] + PAD); W[13] = C_PAD_PLUS_S0 + W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14] + PAD); W[14] = C_PAD_PLUS_S0 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_[15] + PAD); W[15] = PAD + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g; g = f; f = e; e = d + T1;
                d = c; c = b; b = a; a = T1 + T2;
                if (r < 4) W[i] += small0(W[(i + 1) & 15]) + W[(i + 9) & 15] + small1(W[(i + 14) & 15]);
            }
        }

        out[0] = IV_[0] + a; out[1] = IV_[1] + b;
        out[2] = IV_[2] + c; out[3] = IV_[3] + d;
        out[4] = IV_[4] + e; out[5] = IV_[5] + f;
        out[6] = IV_[6] + g; out[7] = IV_[7] + h;
    }

    // HMAC ipad/opad com chave de 64 B.
    template <word PAD>
    SHA512_FORCE_INLINE static void compress_pad128_64bytekey(const word key_words[8], word out[8]) noexcept {
        constexpr word C_S0_PAD      = (std::rotr(PAD, 1) ^ std::rotr(PAD, 8) ^ (PAD >> 7));
        constexpr word C_S1_PAD      = (std::rotr(PAD, 19) ^ std::rotr(PAD, 61) ^ (PAD >> 6));
        constexpr word C_PAD_PLUS_S0 = PAD + C_S0_PAD;
        constexpr word C_PAD_PLUS_S1 = PAD + C_S1_PAD;

        word W[16];
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) W[i] = key_words[i] ^ PAD;

        word a = IV_[0], b = IV_[1], c = IV_[2], d = IV_[3];
        word e = IV_[4], f = IV_[5], g = IV_[6], h = IV_[7];

        SHA512_STEP_SCALAR(K_[0], W[0]); W[0] += small0(W[1]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[1], W[1]); W[1] += small0(W[2]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[2], W[2]); W[2] += small0(W[3]) + PAD + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]); W[3] += small0(W[4]) + PAD + small1(W[1]);
        SHA512_STEP_SCALAR(K_[4], W[4]); W[4] += small0(W[5]) + PAD + small1(W[2]);
        SHA512_STEP_SCALAR(K_[5], W[5]); W[5] += small0(W[6]) + PAD + small1(W[3]);
        SHA512_STEP_SCALAR(K_[6], W[6]); W[6] += small0(W[7]) + PAD + small1(W[4]);
        SHA512_STEP_SCALAR(K_[7], W[7]); W[7] += C_S0_PAD + W[0] + small1(W[5]);

        SHA512_STEP_FUSED_SCALAR(K_[8]  + PAD); W[8]  = C_PAD_PLUS_S0 + W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9]  + PAD); W[9]  = C_PAD_PLUS_S0 + W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10] + PAD); W[10] = C_PAD_PLUS_S0 + W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11] + PAD); W[11] = C_PAD_PLUS_S0 + W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12] + PAD); W[12] = C_PAD_PLUS_S0 + W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13] + PAD); W[13] = C_PAD_PLUS_S0 + W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14] + PAD); W[14] = C_PAD_PLUS_S0 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_[15] + PAD); W[15] = PAD + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g; g = f; f = e; e = d + T1;
                d = c; c = b; b = a; a = T1 + T2;
                if (r < 4) W[i] += small0(W[(i + 1) & 15]) + W[(i + 9) & 15] + small1(W[(i + 14) & 15]);
            }
        }

        out[0] = IV_[0] + a; out[1] = IV_[1] + b;
        out[2] = IV_[2] + c; out[3] = IV_[3] + d;
        out[4] = IV_[4] + e; out[5] = IV_[5] + f;
        out[6] = IV_[6] + g; out[7] = IV_[7] + h;
    }

#undef SHA512_STEP_SCALAR
#undef SHA512_STEP_FUSED_SCALAR

   private:
    void build_template_tables(const byte* block) noexcept {
        for (unsigned i = 0; i < 16; ++i)
            template_w_[i] = load_be64(block + (i << 3));

        template_skip_ = template_suffix_len_ ? static_cast<std::uint32_t>(buffer_size_ >> 3) : 16;

        auto mid = h_;
        for (std::uint32_t t = 0; t < template_skip_; ++t)
            round(mid[0], mid[1], mid[2], mid[3], mid[4], mid[5], mid[6], mid[7], K_[t], template_w_[t]);

        template_mid_ = mid;
    }

    static void write_digest(const std::array<word, 8>& state, byte out[digest_size]) noexcept {
        for (unsigned i = 0; i < 8; ++i) store_be64(out + (i << 3), state[i]);
    }

    void process_block() noexcept { compress(h_, buffer_.data()); }

   public:
    SHA512() noexcept { reset(); }

    void reset() noexcept {
        h_ = IV_;
        total_lo_ = 0;
        total_hi_ = 0;
        buffer_size_ = 0;
        template_single_block_ = false;
        template_suffix_len_ = 0;
        template_skip_ = 16;
    }

    void update(const void* data, std::size_t len) noexcept {
        if (len == 0) return;
        const auto* p = static_cast<const byte*>(data);

        const std::uint64_t old = total_lo_;
        total_lo_ += static_cast<std::uint64_t>(len);
        total_hi_ += (total_lo_ < old) ? 1u : 0u;

        if (buffer_size_ != 0) {
            const std::size_t take =
                (block_size - buffer_size_ < len) ? (block_size - buffer_size_) : len;
            std::memcpy(buffer_.data() + buffer_size_, p, take);
            buffer_size_ += take;
            p += take;
            len -= take;
            if (buffer_size_ == block_size) {
                process_block();
                buffer_size_ = 0;
            }
        }

        while (len >= block_size) {
            compress(h_, p);
            p += block_size;
            len -= block_size;
        }

        if (len != 0) {
            std::memcpy(buffer_.data(), p, len);
            buffer_size_ = len;
        }
    }

    void finalize(byte out[digest_size]) noexcept {
        const std::uint64_t bit_lo = total_lo_ << 3;
        const std::uint64_t bit_hi = (total_hi_ << 3) | (total_lo_ >> 61);

        buffer_[buffer_size_++] = 0x80;
        if (buffer_size_ > 112) {
            std::memset(buffer_.data() + buffer_size_, 0, block_size - buffer_size_);
            process_block();
            buffer_size_ = 0;
        }
        std::memset(buffer_.data() + buffer_size_, 0, 112 - buffer_size_);
        store_be64(buffer_.data() + 112, bit_hi);
        store_be64(buffer_.data() + 120, bit_lo);
        process_block();

        write_digest(h_, out);
    }

    static void hash(const void* data, std::size_t len, byte out[digest_size]) noexcept {
        if (len <= 111) {
            alignas(64) std::array<byte, block_size> block{};
            if (len != 0) std::memcpy(block.data(), data, len);
            block[len] = 0x80;
            store_be64(block.data() + 112, 0);
            store_be64(block.data() + 120, static_cast<std::uint64_t>(len) << 3);

            auto state = IV_;
            compress(state, block.data());
            write_digest(state, out);
            return;
        }

        SHA512 ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

    // Pré-computa o estado pós-prefixo para um hash de bloco único com
    // sufixo de tamanho fixo. Habilita reuso do prefixo em N sufixos.
    void preset(const void* prefix, std::size_t prefix_len, std::size_t suffix_len) noexcept {
        reset();
        update(prefix, prefix_len);
        template_suffix_len_ = suffix_len;

        if (buffer_size_ <= 111 && suffix_len <= (111 - buffer_size_)) {
            template_single_block_ = true;

            alignas(64) std::array<byte, block_size> block{};
            if (buffer_size_ != 0) std::memcpy(block.data(), buffer_.data(), buffer_size_);

            const std::size_t pad = buffer_size_ + suffix_len;
            block[pad] = 0x80;

            const std::uint64_t bytes = total_lo_ + static_cast<std::uint64_t>(suffix_len);
            const std::uint64_t high_bytes = total_hi_ + (bytes < total_lo_ ? 1u : 0u);
            const std::uint64_t bit_lo = bytes << 3;
            const std::uint64_t bit_hi = (high_bytes << 3) | (bytes >> 61);

            store_be64(block.data() + 112, bit_hi);
            store_be64(block.data() + 120, bit_lo);

            build_template_tables(block.data());
        } else {
            template_single_block_ = false;
            template_skip_ = 0;
        }
    }

    void complete(const void* suffix, byte out[digest_size]) const noexcept {
        complete(suffix, template_suffix_len_, out);
    }

    void complete(const void* suffix, std::size_t suffix_len, byte out[digest_size]) const noexcept {
        if (!template_single_block_ || suffix_len != template_suffix_len_) {
            SHA512 temp = *this;
            temp.update(suffix, suffix_len);
            temp.finalize(out);
            return;
        }

        alignas(64) std::array<word, 16> w = template_w_;

        if (suffix_len != 0) {
            const std::size_t first = buffer_size_;
            if (first == 0) {
                const auto* p = static_cast<const byte*>(suffix);
                const std::size_t word_count = suffix_len >> 3;
#pragma GCC unroll 8
                for (std::size_t i = 0; i < word_count; ++i) w[i] = load_be64(p + (i << 3));
                const std::size_t rem = suffix_len & 7;
                if (rem != 0) {
                    alignas(8) byte tail[8];
                    store_be64(tail, template_w_[word_count]);
                    std::memcpy(tail, p + (word_count << 3), rem);
                    w[word_count] = load_be64(tail);
                }
            } else if ((first & 7) == 0 && (suffix_len & 7) == 0) {
                const std::size_t w0 = first >> 3;
                const std::size_t word_count = suffix_len >> 3;
                const auto* p = static_cast<const byte*>(suffix);
#pragma GCC unroll 8
                for (std::size_t i = 0; i < word_count; ++i) w[w0 + i] = load_be64(p + (i << 3));
            } else {
                const std::size_t last = first + suffix_len - 1;
                const std::size_t w0 = first >> 3;
                const std::size_t w1 = last >> 3;
                const std::size_t byte0 = w0 << 3;

                alignas(64) byte patch[block_size];
                for (std::size_t i = w0; i <= w1; ++i)
                    store_be64(patch + ((i - w0) << 3), template_w_[i]);
                std::memcpy(patch + (first - byte0), suffix, suffix_len);
                for (std::size_t i = w0; i <= w1; ++i) w[i] = load_be64(patch + ((i - w0) << 3));
            }
        }

        auto state = template_mid_;
        compress_from(state, w, template_skip_);
        for (unsigned i = 0; i < 8; ++i) state[i] += h_[i];
        write_digest(state, out);
    }
};

#undef SHA512_FORCE_INLINE
#undef SHA512_UNROLL16

}  // namespace crypto
