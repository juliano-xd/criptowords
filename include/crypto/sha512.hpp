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
    static constexpr std::size_t block_size = 128;

   private:
#if defined(__GNUC__) || defined(__clang__)
#define SHA512_FORCE_INLINE inline __attribute__((always_inline))
#define SHA512_LAMBDA_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
#define SHA512_FORCE_INLINE __forceinline
#define SHA512_LAMBDA_INLINE [[msvc::forceinline]]
#else
#define SHA512_FORCE_INLINE inline
#define SHA512_LAMBDA_INLINE
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define SHA512_UNROLL16 _Pragma("GCC unroll 16")
#elif defined(__clang__)
#define SHA512_UNROLL16 _Pragma("clang loop unroll_count(16)")
#else
#define SHA512_UNROLL16
#endif

    static constexpr std::array<word, 8> IV_{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                                             0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
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
    std::size_t buffer_size_ = 0;

    bool template_single_block_ = false;
    std::size_t template_suffix_len_ = 0;
    std::uint32_t template_skip_ = 16;
    alignas(64) std::array<word, 16> template_w_{};
    alignas(64) std::array<word, 8> template_mid_{};

    static constexpr word bswap64(word x) noexcept {
#if defined(__cpp_lib_byteswap) && __cpp_lib_byteswap >= 202110L
        return std::byteswap(x);
#else
        return ((x & 0x00000000000000FFULL) << 56) | ((x & 0x000000000000FF00ULL) << 40) |
               ((x & 0x0000000000FF0000ULL) << 24) | ((x & 0x00000000FF000000ULL) << 8) |
               ((x & 0x000000FF00000000ULL) >> 8) | ((x & 0x0000FF0000000000ULL) >> 24) |
               ((x & 0x00FF000000000000ULL) >> 40) | ((x & 0xFF00000000000000ULL) >> 56);
#endif
    }

   public:
    SHA512_FORCE_INLINE static word load_be64(const void* p) noexcept {
        word v;
        std::memcpy(&v, p, sizeof(v));
        if constexpr (std::endian::native == std::endian::little)
            v = bswap64(v);
        return v;
    }

    SHA512_FORCE_INLINE static void store_be64(void* p, word v) noexcept {
        if constexpr (std::endian::native == std::endian::little)
            v = bswap64(v);
        std::memcpy(p, &v, sizeof(v));
    }

    SHA512_FORCE_INLINE static word ch(word x, word y, word z) noexcept { return z ^ (x & (y ^ z)); }

    SHA512_FORCE_INLINE static word maj(word x, word y, word z) noexcept { return (x & y) | (z & (x | y)); }

    SHA512_FORCE_INLINE static word big0(word x) noexcept {
        return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39);
    }

    SHA512_FORCE_INLINE static word big1(word x) noexcept {
        return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41);
    }

    SHA512_FORCE_INLINE static word small0(word x) noexcept { return std::rotr(x, 1) ^ std::rotr(x, 8) ^ (x >> 7); }

    SHA512_FORCE_INLINE static word small1(word x) noexcept { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }

    SHA512_FORCE_INLINE static void round(word& a, word& b, word& c, word& d, word& e, word& f, word& g, word& h,
                                          word k, word w) noexcept {
        const word kw = k + w;
        const word h_kw = h + kw;
        const word e_terms = big1(e) + ch(e, f, g);
        const word t1 = h_kw + e_terms;
        const word t2 = big0(a) + maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    static void compress(std::array<word, 8>& state, const byte* block) noexcept {
        alignas(64) word w[16];

        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i)
            w[i] = load_be64(block + (i << 3));

        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];

        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i)
            round(a, b, c, d, e, f, g, h, K_[i], w[i]);

        SHA512_UNROLL16
        for (unsigned t = 16; t < 80; ++t) {
            const unsigned i = t & 15;
            w[i] += small0(w[(i + 1) & 15]) + w[(i + 9) & 15] + small1(w[(i + 14) & 15]);
            round(a, b, c, d, e, f, g, h, K_[t], w[i]);
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    static void compress_words(std::array<word, 8>& state, const word w_in[16]) noexcept {
        alignas(64) word w[16];

        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i)
            w[i] = w_in[i];

        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];

        SHA512_UNROLL16
        for (unsigned i = 0; i < 16; ++i)
            round(a, b, c, d, e, f, g, h, K_[i], w[i]);

        SHA512_UNROLL16
        for (unsigned t = 16; t < 80; ++t) {
            const unsigned i = t & 15;
            w[i] += small0(w[(i + 1) & 15]) + w[(i + 9) & 15] + small1(w[(i + 14) & 15]);
            round(a, b, c, d, e, f, g, h, K_[t], w[i]);
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    static void compress_from(std::array<word, 8>& state, std::array<word, 16>& w, std::uint32_t first_round) noexcept {
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

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;
    }

#define SHA512_STEP_SCALAR(k_term, w_val)                                                                              \
    do {                                                                                                               \
        word T1 = (h) + (k_term) + (w_val) + big1(e) + ch(e, f, g);                                                    \
        word T2 = big0(a) + maj(a, b, c);                                                                              \
        h = g;                                                                                                         \
        g = f;                                                                                                         \
        f = e;                                                                                                         \
        e = d + T1;                                                                                                    \
        d = c;                                                                                                         \
        c = b;                                                                                                         \
        b = a;                                                                                                         \
        a = T1 + T2;                                                                                                   \
    } while (0)

#define SHA512_STEP_FUSED_SCALAR(k_fused)                                                                              \
    do {                                                                                                               \
        word T1 = (h) + (k_fused) + big1(e) + ch(e, f, g);                                                             \
        word T2 = big0(a) + maj(a, b, c);                                                                              \
        h = g;                                                                                                         \
        g = f;                                                                                                         \
        f = e;                                                                                                         \
        e = d + T1;                                                                                                    \
        d = c;                                                                                                         \
        c = b;                                                                                                         \
        b = a;                                                                                                         \
        a = T1 + T2;                                                                                                   \
    } while (0)

    SHA512_FORCE_INLINE static void compress_padded_block64(const word iv[8], word W[16], word out[8]) noexcept {
        constexpr word K_FUSED_8 = 0xd807aa98a3030242ULL + 0x8000000000000000ULL;
        constexpr word K_FUSED_15 = 0xc19bf174cf692694ULL + 0x0000000000000600ULL;
        constexpr word C_S1_W15 = 0x00c0000000003018ULL;
        constexpr word C_S0_W8 = 0x4180000000000000ULL;
        constexpr word C_S0_W15 = 0x000000000000030aULL;
        constexpr word C_W8 = 0x8000000000000000ULL;
        constexpr word C_W15 = 0x0000000000000600ULL;

        word a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];

        SHA512_STEP_SCALAR(K_[0], W[0]);
        W[0] += small0(W[1]);
        SHA512_STEP_SCALAR(K_[1], W[1]);
        W[1] += small0(W[2]) + C_S1_W15;
        SHA512_STEP_SCALAR(K_[2], W[2]);
        W[2] += small0(W[3]) + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]);
        W[3] += small0(W[4]) + small1(W[1]);
        SHA512_STEP_SCALAR(K_[4], W[4]);
        W[4] += small0(W[5]) + small1(W[2]);
        SHA512_STEP_SCALAR(K_[5], W[5]);
        W[5] += small0(W[6]) + small1(W[3]);
        SHA512_STEP_SCALAR(K_[6], W[6]);
        W[6] += small0(W[7]) + C_W15 + small1(W[4]);
        SHA512_STEP_SCALAR(K_[7], W[7]);
        W[7] += C_S0_W8 + W[0] + small1(W[5]);

        SHA512_STEP_FUSED_SCALAR(K_FUSED_8);
        W[8] = C_W8 + W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9]);
        W[9] = W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10]);
        W[10] = W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11]);
        W[11] = W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12]);
        W[12] = W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13]);
        W[13] = W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14]);
        W[14] = C_S0_W15 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_FUSED_15);
        W[15] = C_W15 + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
                if (r < 4) {
                    word sum_direct = W[i] + W[(i + 9) & 15];
                    word sig_terms = small0(W[(i + 1) & 15]) + small1(W[(i + 14) & 15]);
                    W[i] = sum_direct + sig_terms;
                }
            }
        }

        out[0] = iv[0] + a;
        out[1] = iv[1] + b;
        out[2] = iv[2] + c;
        out[3] = iv[3] + d;
        out[4] = iv[4] + e;
        out[5] = iv[5] + f;
        out[6] = iv[6] + g;
        out[7] = iv[7] + h;
    }

    SHA512_FORCE_INLINE static void compress_padded_block37(const word iv[8], word W[16], word out[8]) noexcept {
        constexpr word C_W15_37 = 1320ULL;
        constexpr word C_S0_1320 = (std::rotr(1320ULL, 1) ^ std::rotr(1320ULL, 8) ^ (1320ULL >> 7));
        constexpr word C_S1_1320 = (std::rotr(1320ULL, 19) ^ std::rotr(1320ULL, 61) ^ (1320ULL >> 6));
        constexpr word K_FUSED_15_37 = 0xc19bf174cf692694ULL + 1320ULL;

        word a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];

        SHA512_STEP_SCALAR(K_[0], W[0]);
        W[0] += small0(W[1]);
        SHA512_STEP_SCALAR(K_[1], W[1]);
        W[1] += small0(W[2]) + C_S1_1320;
        SHA512_STEP_SCALAR(K_[2], W[2]);
        W[2] += small0(W[3]) + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]);
        W[3] += small0(W[4]) + small1(W[1]);
        SHA512_STEP_SCALAR(K_[4], W[4]);
        W[4] += small1(W[2]);

        SHA512_STEP_FUSED_SCALAR(K_[5]);
        W[5] = small1(W[3]);
        SHA512_STEP_FUSED_SCALAR(K_[6]);
        W[6] = C_W15_37 + small1(W[4]);
        SHA512_STEP_FUSED_SCALAR(K_[7]);
        W[7] = W[0] + small1(W[5]);
        SHA512_STEP_FUSED_SCALAR(K_[8]);
        W[8] = W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9]);
        W[9] = W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10]);
        W[10] = W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11]);
        W[11] = W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12]);
        W[12] = W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13]);
        W[13] = W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14]);
        W[14] = C_S0_1320 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_FUSED_15_37);
        W[15] = C_W15_37 + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
                if (r < 4) {
                    W[i] += small0(W[(i + 1) & 15]) + W[(i + 9) & 15] + small1(W[(i + 14) & 15]);
                }
            }
        }

        out[0] = iv[0] + a;
        out[1] = iv[1] + b;
        out[2] = iv[2] + c;
        out[3] = iv[3] + d;
        out[4] = iv[4] + e;
        out[5] = iv[5] + f;
        out[6] = iv[6] + g;
        out[7] = iv[7] + h;
    }

    template <word PAD>
    SHA512_FORCE_INLINE static void compress_pad128_32bytekey(const word key_words[4], word out[8]) noexcept {
        constexpr word C_S0_PAD = (std::rotr(PAD, 1) ^ std::rotr(PAD, 8) ^ (PAD >> 7));
        constexpr word C_S1_PAD = (std::rotr(PAD, 19) ^ std::rotr(PAD, 61) ^ (PAD >> 6));
        constexpr word C_PAD_PLUS_S1 = PAD + C_S1_PAD;
        constexpr word C_PAD_PLUS_S0 = PAD + C_S0_PAD;
        constexpr word C_2PAD_PLUS_S0 = PAD + PAD + C_S0_PAD;

        word W[16];
        W[0] = key_words[0] ^ PAD;
        W[1] = key_words[1] ^ PAD;
        W[2] = key_words[2] ^ PAD;
        W[3] = key_words[3] ^ PAD;

        word a = IV_[0], b = IV_[1], c = IV_[2], d = IV_[3];
        word e = IV_[4], f = IV_[5], g = IV_[6], h = IV_[7];

        SHA512_STEP_SCALAR(K_[0], W[0]);
        W[0] += small0(W[1]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[1], W[1]);
        W[1] += small0(W[2]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[2], W[2]);
        W[2] += small0(W[3]) + PAD + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]);
        W[3] += C_PAD_PLUS_S0 + small1(W[1]);

        SHA512_STEP_FUSED_SCALAR(K_[4] + PAD);
        W[4] = C_2PAD_PLUS_S0 + small1(W[2]);
        SHA512_STEP_FUSED_SCALAR(K_[5] + PAD);
        W[5] = C_2PAD_PLUS_S0 + small1(W[3]);
        SHA512_STEP_FUSED_SCALAR(K_[6] + PAD);
        W[6] = C_2PAD_PLUS_S0 + small1(W[4]);
        SHA512_STEP_FUSED_SCALAR(K_[7] + PAD);
        W[7] = C_PAD_PLUS_S0 + W[0] + small1(W[5]);
        SHA512_STEP_FUSED_SCALAR(K_[8] + PAD);
        W[8] = C_PAD_PLUS_S0 + W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9] + PAD);
        W[9] = C_PAD_PLUS_S0 + W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10] + PAD);
        W[10] = C_PAD_PLUS_S0 + W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11] + PAD);
        W[11] = C_PAD_PLUS_S0 + W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12] + PAD);
        W[12] = C_PAD_PLUS_S0 + W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13] + PAD);
        W[13] = C_PAD_PLUS_S0 + W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14] + PAD);
        W[14] = C_PAD_PLUS_S0 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_[15] + PAD);
        W[15] = PAD + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
                if (r < 4) {
                    W[i] += small0(W[(i + 1) & 15]) + W[(i + 9) & 15] + small1(W[(i + 14) & 15]);
                }
            }
        }

        out[0] = IV_[0] + a;
        out[1] = IV_[1] + b;
        out[2] = IV_[2] + c;
        out[3] = IV_[3] + d;
        out[4] = IV_[4] + e;
        out[5] = IV_[5] + f;
        out[6] = IV_[6] + g;
        out[7] = IV_[7] + h;
    }

    template <word PAD>
    SHA512_FORCE_INLINE static void compress_pad128_64bytekey(const word key_words[8], word out[8]) noexcept {
        constexpr word C_S0_PAD = (std::rotr(PAD, 1) ^ std::rotr(PAD, 8) ^ (PAD >> 7));
        constexpr word C_S1_PAD = (std::rotr(PAD, 19) ^ std::rotr(PAD, 61) ^ (PAD >> 6));
        constexpr word C_PAD_PLUS_S0 = PAD + C_S0_PAD;
        constexpr word C_PAD_PLUS_S1 = PAD + C_S1_PAD;

        word W[16];
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            W[i] = key_words[i] ^ PAD;
        }

        word a = IV_[0], b = IV_[1], c = IV_[2], d = IV_[3];
        word e = IV_[4], f = IV_[5], g = IV_[6], h = IV_[7];

        SHA512_STEP_SCALAR(K_[0], W[0]);
        W[0] += small0(W[1]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[1], W[1]);
        W[1] += small0(W[2]) + C_PAD_PLUS_S1;
        SHA512_STEP_SCALAR(K_[2], W[2]);
        W[2] += small0(W[3]) + PAD + small1(W[0]);
        SHA512_STEP_SCALAR(K_[3], W[3]);
        W[3] += small0(W[4]) + PAD + small1(W[1]);
        SHA512_STEP_SCALAR(K_[4], W[4]);
        W[4] += small0(W[5]) + PAD + small1(W[2]);
        SHA512_STEP_SCALAR(K_[5], W[5]);
        W[5] += small0(W[6]) + PAD + small1(W[3]);
        SHA512_STEP_SCALAR(K_[6], W[6]);
        W[6] += small0(W[7]) + PAD + small1(W[4]);
        SHA512_STEP_SCALAR(K_[7], W[7]);
        W[7] += C_S0_PAD + W[0] + small1(W[5]);

        SHA512_STEP_FUSED_SCALAR(K_[8] + PAD);
        W[8] = C_PAD_PLUS_S0 + W[1] + small1(W[6]);
        SHA512_STEP_FUSED_SCALAR(K_[9] + PAD);
        W[9] = C_PAD_PLUS_S0 + W[2] + small1(W[7]);
        SHA512_STEP_FUSED_SCALAR(K_[10] + PAD);
        W[10] = C_PAD_PLUS_S0 + W[3] + small1(W[8]);
        SHA512_STEP_FUSED_SCALAR(K_[11] + PAD);
        W[11] = C_PAD_PLUS_S0 + W[4] + small1(W[9]);
        SHA512_STEP_FUSED_SCALAR(K_[12] + PAD);
        W[12] = C_PAD_PLUS_S0 + W[5] + small1(W[10]);
        SHA512_STEP_FUSED_SCALAR(K_[13] + PAD);
        W[13] = C_PAD_PLUS_S0 + W[6] + small1(W[11]);
        SHA512_STEP_FUSED_SCALAR(K_[14] + PAD);
        W[14] = C_PAD_PLUS_S0 + W[7] + small1(W[12]);
        SHA512_STEP_FUSED_SCALAR(K_[15] + PAD);
        W[15] = PAD + small0(W[0]) + W[8] + small1(W[13]);

#pragma GCC unroll 4
        for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                word T1 = h + K_[r * 16 + i] + W[i] + big1(e) + ch(e, f, g);
                word T2 = big0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
                if (r < 4) {
                    W[i] += small0(W[(i + 1) & 15]) + W[(i + 9) & 15] + small1(W[(i + 14) & 15]);
                }
            }
        }

        out[0] = IV_[0] + a;
        out[1] = IV_[1] + b;
        out[2] = IV_[2] + c;
        out[3] = IV_[3] + d;
        out[4] = IV_[4] + e;
        out[5] = IV_[5] + f;
        out[6] = IV_[6] + g;
        out[7] = IV_[7] + h;
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
        for (unsigned i = 0; i < 8; ++i)
            store_be64(out + (i << 3), state[i]);
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
        if (len == 0)
            return;

        const auto* p = static_cast<const byte*>(data);

        const std::uint64_t old = total_lo_;
        total_lo_ += static_cast<std::uint64_t>(len);
        total_hi_ += (total_lo_ < old) ? 1u : 0u;

        if (buffer_size_ != 0) {
            const std::size_t take = (block_size - buffer_size_ < len) ? (block_size - buffer_size_) : len;

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
            if (len != 0)
                std::memcpy(block.data(), data, len);

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

    void preset(const void* prefix, std::size_t prefix_len, const uint8_t suffix_len) noexcept {
        reset();
        update(prefix, prefix_len);
        template_suffix_len_ = suffix_len;

        if (suffix_len <= 111 - buffer_size_) {
            template_single_block_ = true;

            alignas(64) std::array<byte, block_size> block{};
            if (buffer_size_ != 0)
                std::memcpy(block.data(), buffer_.data(), buffer_size_);

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
                for (std::size_t i = 0; i < word_count; ++i) {
                    w[i] = load_be64(p + (i << 3));
                }
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
                for (std::size_t i = 0; i < word_count; ++i) {
                    w[w0 + i] = load_be64(p + (i << 3));
                }
            } else {
                const std::size_t last = first + suffix_len - 1;
                const std::size_t w0 = first >> 3;
                const std::size_t w1 = last >> 3;
                const std::size_t byte0 = w0 << 3;

                alignas(64) byte patch[block_size];
                for (std::size_t i = w0; i <= w1; ++i)
                    store_be64(patch + ((i - w0) << 3), template_w_[i]);
                std::memcpy(patch + (first - byte0), suffix, suffix_len);

                for (std::size_t i = w0; i <= w1; ++i)
                    w[i] = load_be64(patch + ((i - w0) << 3));
            }
        }

        auto state = template_mid_;
        compress_from(state, w, template_skip_);
        for (unsigned i = 0; i < 8; ++i)
            state[i] += h_[i];
        write_digest(state, out);
    }

    void complete_batch_scalar(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        const auto* base = static_cast<const byte*>(suffixes);
        std::size_t i = 0;
        for (; i + 1 < count; i += 2) {
            complete(base + i * stride, out + i * digest_size);
            complete(base + (i + 1) * stride, out + (i + 1) * digest_size);
        }
        for (; i < count; ++i)
            complete(base + i * stride, out + i * digest_size);
    }

#if defined(__SSE4_1__)
    void complete_batch_sse(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        const auto* base = static_cast<const byte*>(suffixes);
        const std::size_t suffix_len = template_suffix_len_;
        const std::size_t buffer_size = buffer_size_;
        const std::uint32_t skip = template_skip_;

        const std::size_t w_start = buffer_size >> 3;
        const std::size_t w_end = (suffix_len > 0) ? ((buffer_size + suffix_len - 1) >> 3) : w_start;

        alignas(16) static constexpr std::uint8_t shuf_ror8[16] = {1, 2,  3,  4,  5,  6,  7,  0,
                                                                   9, 10, 11, 12, 13, 14, 15, 8};
        alignas(16) static constexpr std::uint8_t bswap_mask_data[16] = {7,  6,  5,  4,  3,  2,  1, 0,
                                                                         15, 14, 13, 12, 11, 10, 9, 8};

        const __m128i v_shuf_ror8 = _mm_load_si128(reinterpret_cast<const __m128i*>(shuf_ror8));
        const __m128i bswap_mask = _mm_load_si128(reinterpret_cast<const __m128i*>(bswap_mask_data));

        __m128i W_const[16];
        for (std::size_t i = 0; i < 16; ++i) {
            W_const[i] = _mm_set1_epi64x(template_w_[i]);
        }

        __m128i k_sse[80];
        for (std::size_t i = 0; i < 80; ++i) {
            k_sse[i] = _mm_set1_epi64x(K_[i]);
        }

        const __m128i mid_a = _mm_set1_epi64x(template_mid_[0]);
        const __m128i mid_b = _mm_set1_epi64x(template_mid_[1]);
        const __m128i mid_c = _mm_set1_epi64x(template_mid_[2]);
        const __m128i mid_d = _mm_set1_epi64x(template_mid_[3]);
        const __m128i mid_e = _mm_set1_epi64x(template_mid_[4]);
        const __m128i mid_f = _mm_set1_epi64x(template_mid_[5]);
        const __m128i mid_g = _mm_set1_epi64x(template_mid_[6]);
        const __m128i mid_h = _mm_set1_epi64x(template_mid_[7]);

        const __m128i h_init[8] = {_mm_set1_epi64x(h_[0]), _mm_set1_epi64x(h_[1]), _mm_set1_epi64x(h_[2]),
                                   _mm_set1_epi64x(h_[3]), _mm_set1_epi64x(h_[4]), _mm_set1_epi64x(h_[5]),
                                   _mm_set1_epi64x(h_[6]), _mm_set1_epi64x(h_[7])};

        auto ror64 = [](__m128i x, int n) SHA512_LAMBDA_INLINE {
            return _mm_xor_si128(_mm_srli_epi64(x, n), _mm_slli_epi64(x, 64 - n));
        };
        auto ch_vec = [](__m128i x, __m128i y, __m128i z)
                          SHA512_LAMBDA_INLINE { return _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z))); };
        auto maj_vec = [](__m128i x, __m128i y, __m128i z) SHA512_LAMBDA_INLINE {
            return _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)));
        };
        auto s0_vec = [&](__m128i x) SHA512_LAMBDA_INLINE {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 1), _mm_shuffle_epi8(x, v_shuf_ror8)), _mm_srli_epi64(x, 7));
        };
        auto s1_vec = [&](__m128i x) SHA512_LAMBDA_INLINE {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 19), ror64(x, 61)), _mm_srli_epi64(x, 6));
        };
        auto big0_vec = [&](__m128i x) SHA512_LAMBDA_INLINE {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 28), ror64(x, 34)), ror64(x, 39));
        };
        auto big1_vec = [&](__m128i x) SHA512_LAMBDA_INLINE {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 14), ror64(x, 18)), ror64(x, 41));
        };

        auto round_step = [&](__m128i& a, __m128i& b, __m128i& c, __m128i& d, __m128i& e, __m128i& f, __m128i& g,
                              __m128i& h, __m128i k_term, __m128i w_val) SHA512_LAMBDA_INLINE {
            __m128i kw = _mm_add_epi64(k_term, w_val);
            __m128i h_kw = _mm_add_epi64(h, kw);
            __m128i e_terms = _mm_add_epi64(big1_vec(e), ch_vec(e, f, g));
            __m128i T1 = _mm_add_epi64(h_kw, e_terms);
            __m128i T2 = _mm_add_epi64(big0_vec(a), maj_vec(a, b, c));
            h = g;
            g = f;
            f = e;
            e = _mm_add_epi64(d, T1);
            d = c;
            c = b;
            b = a;
            a = _mm_add_epi64(T1, T2);
        };

        std::size_t i = 0;
        for (; i + 2 <= count; i += 2) {
            __m128i W[16];
            for (std::size_t w = 0; w < 16; ++w) {
                W[w] = W_const[w];
            }

            std::uint64_t lane_w[2][16];
            for (std::size_t l = 0; l < 2; ++l) {
                const auto* s = base + (i + l) * stride;
                if (buffer_size == 0) {
                    const std::size_t word_count = suffix_len >> 3;
                    for (std::size_t w = 0; w < word_count; ++w) {
                        lane_w[l][w] = load_be64(s + (w << 3));
                    }
                    const std::size_t rem = suffix_len & 7;
                    if (rem != 0) {
                        alignas(8) byte tail[8];
                        store_be64(tail, template_w_[word_count]);
                        std::memcpy(tail, s + (word_count << 3), rem);
                        lane_w[l][word_count] = load_be64(tail);
                    }
                } else if ((buffer_size & 7) == 0 && (suffix_len & 7) == 0) {
                    const std::size_t w0 = buffer_size >> 3;
                    const std::size_t word_count = suffix_len >> 3;
                    for (std::size_t w = 0; w < word_count; ++w) {
                        lane_w[l][w0 + w] = load_be64(s + (w << 3));
                    }
                } else {
                    const std::size_t last = buffer_size + suffix_len - 1;
                    const std::size_t w0 = buffer_size >> 3;
                    const std::size_t w1 = last >> 3;
                    const std::size_t byte0 = w0 << 3;
                    alignas(64) byte patch[block_size];
                    for (std::size_t w = w0; w <= w1; ++w)
                        store_be64(patch + ((w - w0) << 3), template_w_[w]);
                    std::memcpy(patch + (buffer_size - byte0), s, suffix_len);
                    for (std::size_t w = w0; w <= w1; ++w)
                        lane_w[l][w] = load_be64(patch + ((w - w0) << 3));
                }
            }

            for (std::size_t w = w_start; w <= w_end; ++w) {
                W[w] = _mm_set_epi64x(lane_w[1][w], lane_w[0][w]);
            }

            __m128i a = mid_a, b = mid_b, c = mid_c, d = mid_d;
            __m128i e = mid_e, f = mid_f, g = mid_g, h = mid_h;

            for (std::uint32_t t = skip; t < 16; ++t) {
                round_step(a, b, c, d, e, f, g, h, k_sse[t], W[t]);
            }

#pragma GCC unroll 4
            for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
                for (int idx = 0; idx < 16; ++idx) {
                    __m128i sum_direct = _mm_add_epi64(W[idx], W[(idx + 9) & 15]);
                    __m128i sig_terms = _mm_add_epi64(s0_vec(W[(idx + 1) & 15]), s1_vec(W[(idx + 14) & 15]));
                    W[idx] = _mm_add_epi64(sum_direct, sig_terms);
                    round_step(a, b, c, d, e, f, g, h, k_sse[r * 16 + idx], W[idx]);
                }
            }

            a = _mm_add_epi64(a, h_init[0]);
            b = _mm_add_epi64(b, h_init[1]);
            c = _mm_add_epi64(c, h_init[2]);
            d = _mm_add_epi64(d, h_init[3]);
            e = _mm_add_epi64(e, h_init[4]);
            f = _mm_add_epi64(f, h_init[5]);
            g = _mm_add_epi64(g, h_init[6]);
            h = _mm_add_epi64(h, h_init[7]);

            a = _mm_shuffle_epi8(a, bswap_mask);
            b = _mm_shuffle_epi8(b, bswap_mask);
            c = _mm_shuffle_epi8(c, bswap_mask);
            d = _mm_shuffle_epi8(d, bswap_mask);
            e = _mm_shuffle_epi8(e, bswap_mask);
            f = _mm_shuffle_epi8(f, bswap_mask);
            g = _mm_shuffle_epi8(g, bswap_mask);
            h = _mm_shuffle_epi8(h, bswap_mask);

            __m128i ab_lo = _mm_unpacklo_epi64(a, b);
            __m128i cd_lo = _mm_unpacklo_epi64(c, d);
            __m128i ef_lo = _mm_unpacklo_epi64(e, f);
            __m128i gh_lo = _mm_unpacklo_epi64(g, h);

            __m128i ab_hi = _mm_unpackhi_epi64(a, b);
            __m128i cd_hi = _mm_unpackhi_epi64(c, d);
            __m128i ef_hi = _mm_unpackhi_epi64(e, f);
            __m128i gh_hi = _mm_unpackhi_epi64(g, h);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 0) * digest_size + 0), ab_lo);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 0) * digest_size + 16), cd_lo);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 0) * digest_size + 32), ef_lo);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 0) * digest_size + 48), gh_lo);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 1) * digest_size + 0), ab_hi);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 1) * digest_size + 16), cd_hi);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 1) * digest_size + 32), ef_hi);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + (i + 1) * digest_size + 48), gh_hi);
        }

        for (; i < count; ++i) {
            complete(base + i * stride, out + i * digest_size);
        }
    }
#endif

#if defined(__AVX2__)
    void complete_batch_avx2(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        const auto* base = static_cast<const byte*>(suffixes);
        const std::size_t suffix_len = template_suffix_len_;
        const std::size_t buffer_size = buffer_size_;
        const std::uint32_t skip = template_skip_;

        const std::size_t w_start = buffer_size >> 3;
        const std::size_t w_end = (suffix_len > 0) ? ((buffer_size + suffix_len - 1) >> 3) : w_start;

        alignas(32) static constexpr std::uint8_t shuf_ror8[32] = {
            1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8, 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8};
        alignas(32) static constexpr std::uint8_t bswap_mask_data[32] = {
            7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8};

        const __m256i v_shuf_ror8 = _mm256_load_si256(reinterpret_cast<const __m256i*>(shuf_ror8));
        const __m256i bswap_mask = _mm256_load_si256(reinterpret_cast<const __m256i*>(bswap_mask_data));

        __m256i W_const[16];
        for (std::size_t i = 0; i < 16; ++i) {
            W_const[i] = _mm256_set1_epi64x(template_w_[i]);
        }

        __m256i k_avx2[80];
        for (std::size_t i = 0; i < 80; ++i) {
            k_avx2[i] = _mm256_set1_epi64x(K_[i]);
        }

        const __m256i mid_a = _mm256_set1_epi64x(template_mid_[0]);
        const __m256i mid_b = _mm256_set1_epi64x(template_mid_[1]);
        const __m256i mid_c = _mm256_set1_epi64x(template_mid_[2]);
        const __m256i mid_d = _mm256_set1_epi64x(template_mid_[3]);
        const __m256i mid_e = _mm256_set1_epi64x(template_mid_[4]);
        const __m256i mid_f = _mm256_set1_epi64x(template_mid_[5]);
        const __m256i mid_g = _mm256_set1_epi64x(template_mid_[6]);
        const __m256i mid_h = _mm256_set1_epi64x(template_mid_[7]);

        const __m256i h_init[8] = {_mm256_set1_epi64x(h_[0]), _mm256_set1_epi64x(h_[1]), _mm256_set1_epi64x(h_[2]),
                                   _mm256_set1_epi64x(h_[3]), _mm256_set1_epi64x(h_[4]), _mm256_set1_epi64x(h_[5]),
                                   _mm256_set1_epi64x(h_[6]), _mm256_set1_epi64x(h_[7])};

        auto ror64 = [](__m256i x, int n) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - n));
        };
        auto ch_vec = [](__m256i x, __m256i y, __m256i z) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)));
        };
        auto maj_vec = [](__m256i x, __m256i y, __m256i z) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)));
        };
        auto s0_vec = [&](__m256i x) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 1), _mm256_shuffle_epi8(x, v_shuf_ror8)),
                                    _mm256_srli_epi64(x, 7));
        };
        auto s1_vec = [&](__m256i x) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 19), ror64(x, 61)), _mm256_srli_epi64(x, 6));
        };
        auto big0_vec = [&](__m256i x) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 28), ror64(x, 34)), ror64(x, 39));
        };
        auto big1_vec = [&](__m256i x) SHA512_LAMBDA_INLINE {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 14), ror64(x, 18)), ror64(x, 41));
        };

        auto round_step = [&](__m256i& a, __m256i& b, __m256i& c, __m256i& d, __m256i& e, __m256i& f, __m256i& g,
                              __m256i& h, __m256i k_term, __m256i w_val) SHA512_LAMBDA_INLINE {
            __m256i kw = _mm256_add_epi64(k_term, w_val);
            __m256i h_kw = _mm256_add_epi64(h, kw);
            __m256i e_terms = _mm256_add_epi64(big1_vec(e), ch_vec(e, f, g));
            __m256i T1 = _mm256_add_epi64(h_kw, e_terms);
            __m256i T2 = _mm256_add_epi64(big0_vec(a), maj_vec(a, b, c));
            h = g;
            g = f;
            f = e;
            e = _mm256_add_epi64(d, T1);
            d = c;
            c = b;
            b = a;
            a = _mm256_add_epi64(T1, T2);
        };

        std::size_t i = 0;
        for (; i + 4 <= count; i += 4) {
            __m256i W[16];
            for (std::size_t w = 0; w < 16; ++w) {
                W[w] = W_const[w];
            }

            std::uint64_t lane_w[4][16];
            for (std::size_t l = 0; l < 4; ++l) {
                const auto* s = base + (i + l) * stride;
                if (buffer_size == 0) {
                    const std::size_t word_count = suffix_len >> 3;
                    for (std::size_t w = 0; w < word_count; ++w) {
                        lane_w[l][w] = load_be64(s + (w << 3));
                    }
                    const std::size_t rem = suffix_len & 7;
                    if (rem != 0) {
                        alignas(8) byte tail[8];
                        store_be64(tail, template_w_[word_count]);
                        std::memcpy(tail, s + (word_count << 3), rem);
                        lane_w[l][word_count] = load_be64(tail);
                    }
                } else if ((buffer_size & 7) == 0 && (suffix_len & 7) == 0) {
                    const std::size_t w0 = buffer_size >> 3;
                    const std::size_t word_count = suffix_len >> 3;
                    for (std::size_t w = 0; w < word_count; ++w) {
                        lane_w[l][w0 + w] = load_be64(s + (w << 3));
                    }
                } else {
                    const std::size_t last = buffer_size + suffix_len - 1;
                    const std::size_t w0 = buffer_size >> 3;
                    const std::size_t w1 = last >> 3;
                    const std::size_t byte0 = w0 << 3;
                    alignas(64) byte patch[block_size];
                    for (std::size_t w = w0; w <= w1; ++w)
                        store_be64(patch + ((w - w0) << 3), template_w_[w]);
                    std::memcpy(patch + (buffer_size - byte0), s, suffix_len);
                    for (std::size_t w = w0; w <= w1; ++w)
                        lane_w[l][w] = load_be64(patch + ((w - w0) << 3));
                }
            }

            for (std::size_t w = w_start; w <= w_end; ++w) {
                W[w] = _mm256_set_epi64x(lane_w[3][w], lane_w[2][w], lane_w[1][w], lane_w[0][w]);
            }

            __m256i a = mid_a, b = mid_b, c = mid_c, d = mid_d;
            __m256i e = mid_e, f = mid_f, g = mid_g, h = mid_h;

            for (std::uint32_t t = skip; t < 16; ++t) {
                round_step(a, b, c, d, e, f, g, h, k_avx2[t], W[t]);
            }

#pragma GCC unroll 4
            for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
                for (int idx = 0; idx < 16; ++idx) {
                    __m256i sum_direct = _mm256_add_epi64(W[idx], W[(idx + 9) & 15]);
                    __m256i sig_terms = _mm256_add_epi64(s0_vec(W[(idx + 1) & 15]), s1_vec(W[(idx + 14) & 15]));
                    W[idx] = _mm256_add_epi64(sum_direct, sig_terms);
                    round_step(a, b, c, d, e, f, g, h, k_avx2[r * 16 + idx], W[idx]);
                }
            }

            a = _mm256_add_epi64(a, h_init[0]);
            b = _mm256_add_epi64(b, h_init[1]);
            c = _mm256_add_epi64(c, h_init[2]);
            d = _mm256_add_epi64(d, h_init[3]);
            e = _mm256_add_epi64(e, h_init[4]);
            f = _mm256_add_epi64(f, h_init[5]);
            g = _mm256_add_epi64(g, h_init[6]);
            h = _mm256_add_epi64(h, h_init[7]);

            a = _mm256_shuffle_epi8(a, bswap_mask);
            b = _mm256_shuffle_epi8(b, bswap_mask);
            c = _mm256_shuffle_epi8(c, bswap_mask);
            d = _mm256_shuffle_epi8(d, bswap_mask);
            e = _mm256_shuffle_epi8(e, bswap_mask);
            f = _mm256_shuffle_epi8(f, bswap_mask);
            g = _mm256_shuffle_epi8(g, bswap_mask);
            h = _mm256_shuffle_epi8(h, bswap_mask);

            __m256i t0 = _mm256_unpacklo_epi64(a, b);
            __m256i t1 = _mm256_unpackhi_epi64(a, b);
            __m256i t2 = _mm256_unpacklo_epi64(c, d);
            __m256i t3 = _mm256_unpackhi_epi64(c, d);
            __m256i d0_lo = _mm256_permute2x128_si256(t0, t2, 0x20);
            __m256i d1_lo = _mm256_permute2x128_si256(t1, t3, 0x20);
            __m256i d2_lo = _mm256_permute2x128_si256(t0, t2, 0x31);
            __m256i d3_lo = _mm256_permute2x128_si256(t1, t3, 0x31);

            __m256i t4 = _mm256_unpacklo_epi64(e, f);
            __m256i t5 = _mm256_unpackhi_epi64(e, f);
            __m256i t6 = _mm256_unpacklo_epi64(g, h);
            __m256i t7 = _mm256_unpackhi_epi64(g, h);
            __m256i d0_hi = _mm256_permute2x128_si256(t4, t6, 0x20);
            __m256i d1_hi = _mm256_permute2x128_si256(t5, t7, 0x20);
            __m256i d2_hi = _mm256_permute2x128_si256(t4, t6, 0x31);
            __m256i d3_hi = _mm256_permute2x128_si256(t5, t7, 0x31);

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 0) * digest_size + 0), d0_lo);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 0) * digest_size + 32), d0_hi);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 1) * digest_size + 0), d1_lo);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 1) * digest_size + 32), d1_hi);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 2) * digest_size + 0), d2_lo);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 2) * digest_size + 32), d2_hi);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 3) * digest_size + 0), d3_lo);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i + 3) * digest_size + 32), d3_hi);
        }

        for (; i < count; ++i) {
            complete(base + i * stride, out + i * digest_size);
        }
    }
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__)
    void complete_batch_avx512(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        const auto* base = static_cast<const byte*>(suffixes);
        const std::size_t suffix_len = template_suffix_len_;
        const std::size_t buffer_size = buffer_size_;
        const std::uint32_t skip = template_skip_;

        const std::size_t w_start = buffer_size >> 3;
        const std::size_t w_end = (suffix_len > 0) ? ((buffer_size + suffix_len - 1) >> 3) : w_start;

        __m512i W_const[16];
        for (std::size_t i = 0; i < 16; ++i) {
            W_const[i] = _mm512_set1_epi64(template_w_[i]);
        }

        __m512i k_avx512[80];
        for (std::size_t i = 0; i < 80; ++i) {
            k_avx512[i] = _mm512_set1_epi64(K_[i]);
        }

        const __m512i mid_a = _mm512_set1_epi64(template_mid_[0]);
        const __m512i mid_b = _mm512_set1_epi64(template_mid_[1]);
        const __m512i mid_c = _mm512_set1_epi64(template_mid_[2]);
        const __m512i mid_d = _mm512_set1_epi64(template_mid_[3]);
        const __m512i mid_e = _mm512_set1_epi64(template_mid_[4]);
        const __m512i mid_f = _mm512_set1_epi64(template_mid_[5]);
        const __m512i mid_g = _mm512_set1_epi64(template_mid_[6]);
        const __m512i mid_h = _mm512_set1_epi64(template_mid_[7]);

        const __m512i h_init[8] = {_mm512_set1_epi64(h_[0]), _mm512_set1_epi64(h_[1]), _mm512_set1_epi64(h_[2]),
                                   _mm512_set1_epi64(h_[3]), _mm512_set1_epi64(h_[4]), _mm512_set1_epi64(h_[5]),
                                   _mm512_set1_epi64(h_[6]), _mm512_set1_epi64(h_[7])};

        auto ch_vec = [](__m512i x, __m512i y, __m512i z)
                          SHA512_LAMBDA_INLINE { return _mm512_ternarylogic_epi64(x, y, z, 0xCA); };
        auto maj_vec = [](__m512i x, __m512i y, __m512i z)
                           SHA512_LAMBDA_INLINE { return _mm512_ternarylogic_epi64(x, y, z, 0xE8); };
        auto big0_vec = [](__m512i x) SHA512_LAMBDA_INLINE {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34), _mm512_ror_epi64(x, 39),
                                             0x96);
        };
        auto big1_vec = [](__m512i x) SHA512_LAMBDA_INLINE {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18), _mm512_ror_epi64(x, 41),
                                             0x96);
        };
        auto s0_vec = [](__m512i x) SHA512_LAMBDA_INLINE {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 1), _mm512_ror_epi64(x, 8), _mm512_srli_epi64(x, 7),
                                             0x96);
        };
        auto s1_vec = [](__m512i x) SHA512_LAMBDA_INLINE {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61), _mm512_srli_epi64(x, 6),
                                             0x96);
        };

        auto round_step = [&](__m512i& a, __m512i& b, __m512i& c, __m512i& d, __m512i& e, __m512i& f, __m512i& g,
                              __m512i& h, __m512i k_term, __m512i w_val) SHA512_LAMBDA_INLINE {
            __m512i kw = _mm512_add_epi64(k_term, w_val);
            __m512i h_kw = _mm512_add_epi64(h, kw);
            __m512i e_terms = _mm512_add_epi64(big1_vec(e), ch_vec(e, f, g));
            __m512i T1 = _mm512_add_epi64(h_kw, e_terms);
            __m512i T2 = _mm512_add_epi64(big0_vec(a), maj_vec(a, b, c));
            h = g;
            g = f;
            f = e;
            e = _mm512_add_epi64(d, T1);
            d = c;
            c = b;
            b = a;
            a = _mm512_add_epi64(T1, T2);
        };

        std::size_t i = 0;
        for (; i + 8 <= count; i += 8) {
            __m512i W[16];
            for (std::size_t w = 0; w < 16; ++w) {
                W[w] = W_const[w];
            }

            std::uint64_t lane_w[8][16];
            for (std::size_t l = 0; l < 8; ++l) {
                const auto* s = base + (i + l) * stride;
                if (buffer_size == 0) {
                    const std::size_t word_count = suffix_len >> 3;
                    for (std::size_t w = 0; w < word_count; ++w) {
                        lane_w[l][w] = load_be64(s + (w << 3));
                    }
                    const std::size_t rem = suffix_len & 7;
                    if (rem != 0) {
                        alignas(8) byte tail[8];
                        store_be64(tail, template_w_[word_count]);
                        std::memcpy(tail, s + (word_count << 3), rem);
                        lane_w[l][word_count] = load_be64(tail);
                    }
                } else if ((buffer_size & 7) == 0 && (suffix_len & 7) == 0) {
                    const std::size_t w0 = buffer_size >> 3;
                    const std::size_t word_count = suffix_len >> 3;
                    for (std::size_t w = 0; w < word_count; ++w) {
                        lane_w[l][w0 + w] = load_be64(s + (w << 3));
                    }
                } else {
                    const std::size_t last = buffer_size + suffix_len - 1;
                    const std::size_t w0 = buffer_size >> 3;
                    const std::size_t w1 = last >> 3;
                    const std::size_t byte0 = w0 << 3;
                    alignas(64) byte patch[block_size];
                    for (std::size_t w = w0; w <= w1; ++w)
                        store_be64(patch + ((w - w0) << 3), template_w_[w]);
                    std::memcpy(patch + (buffer_size - byte0), s, suffix_len);
                    for (std::size_t w = w0; w <= w1; ++w)
                        lane_w[l][w] = load_be64(patch + ((w - w0) << 3));
                }
            }

            for (std::size_t w = w_start; w <= w_end; ++w) {
                W[w] = _mm512_set_epi64(lane_w[7][w], lane_w[6][w], lane_w[5][w], lane_w[4][w], lane_w[3][w],
                                        lane_w[2][w], lane_w[1][w], lane_w[0][w]);
            }

            __m512i a = mid_a, b = mid_b, c = mid_c, d = mid_d;
            __m512i e = mid_e, f = mid_f, g = mid_g, h = mid_h;

            for (std::uint32_t t = skip; t < 16; ++t) {
                round_step(a, b, c, d, e, f, g, h, k_avx512[t], W[t]);
            }

#pragma GCC unroll 4
            for (int r = 1; r < 5; ++r) {
#pragma GCC unroll 16
                for (int idx = 0; idx < 16; ++idx) {
                    __m512i sum_direct = _mm512_add_epi64(W[idx], W[(idx + 9) & 15]);
                    __m512i sig_terms = _mm512_add_epi64(s0_vec(W[(idx + 1) & 15]), s1_vec(W[(idx + 14) & 15]));
                    W[idx] = _mm512_add_epi64(sum_direct, sig_terms);
                    round_step(a, b, c, d, e, f, g, h, k_avx512[r * 16 + idx], W[idx]);
                }
            }

            a = _mm512_add_epi64(a, h_init[0]);
            b = _mm512_add_epi64(b, h_init[1]);
            c = _mm512_add_epi64(c, h_init[2]);
            d = _mm512_add_epi64(d, h_init[3]);
            e = _mm512_add_epi64(e, h_init[4]);
            f = _mm512_add_epi64(f, h_init[5]);
            g = _mm512_add_epi64(g, h_init[6]);
            h = _mm512_add_epi64(h, h_init[7]);

            alignas(64) std::uint64_t arr_a[8], arr_b[8], arr_c[8], arr_d[8], arr_e[8], arr_f[8], arr_g[8], arr_h[8];
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_a), a);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_b), b);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_c), c);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_d), d);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_e), e);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_f), f);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_g), g);
            _mm512_store_si512(reinterpret_cast<__m512i*>(arr_h), h);

            for (std::size_t l = 0; l < 8; ++l) {
                byte* dest = out + (i + l) * digest_size;
                store_be64(dest + 0, arr_a[l]);
                store_be64(dest + 8, arr_b[l]);
                store_be64(dest + 16, arr_c[l]);
                store_be64(dest + 24, arr_d[l]);
                store_be64(dest + 32, arr_e[l]);
                store_be64(dest + 40, arr_f[l]);
                store_be64(dest + 48, arr_g[l]);
                store_be64(dest + 56, arr_h[l]);
            }
        }

        for (; i < count; ++i) {
            complete(base + i * stride, out + i * digest_size);
        }
    }
#endif

    void complete_batch(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        if (!template_single_block_ || count == 0) {
            complete_batch_scalar(suffixes, stride, out, count);
            return;
        }

#if defined(__AVX512F__) && defined(__AVX512VL__)
        complete_batch_avx512(suffixes, stride, out, count);
#elif defined(__AVX2__)
        complete_batch_avx2(suffixes, stride, out, count);
#elif defined(__SSE4_1__)
        complete_batch_sse(suffixes, stride, out, count);
#else
        complete_batch_scalar(suffixes, stride, out, count);
#endif
    }

    static constexpr unsigned simd_lanes() noexcept {
#if defined(__AVX512F__) && defined(__AVX512VL__)
        return 8;
#elif defined(__AVX2__)
        return 4;
#elif defined(__SSE4_1__)
        return 2;
#else
        return 1;
#endif
    }

    static constexpr const char* simd_name() noexcept {
#if defined(__AVX512F__) && defined(__AVX512VL__)
        return "avx512";
#elif defined(__AVX2__)
        return "avx2";
#elif defined(__SSE4_1__)
        return "sse4.1";
#else
        return "scalar";
#endif
    }
};

#undef SHA512_FORCE_INLINE
#undef SHA512_LAMBDA_INLINE
#undef SHA512_UNROLL16

}  // namespace crypto
