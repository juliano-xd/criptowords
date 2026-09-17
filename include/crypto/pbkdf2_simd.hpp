#pragma once
#include "sha512.hpp"
#include <cstring>
#include <cstdint>
#include <immintrin.h>
alignas(64) static constexpr uint64_t K512_SIMD[80] = {
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
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline const __m128i* get_k512_sse() {
    alignas(16) static const __m128i K[80] = {
#define K_SSE(i) _mm_set1_epi64x((long long)K512_SIMD[i])
        K_SSE(0),  K_SSE(1),  K_SSE(2),  K_SSE(3),  K_SSE(4),  K_SSE(5),  K_SSE(6),  K_SSE(7),
        K_SSE(8),  K_SSE(9),  K_SSE(10), K_SSE(11), K_SSE(12), K_SSE(13), K_SSE(14), K_SSE(15),
        K_SSE(16), K_SSE(17), K_SSE(18), K_SSE(19), K_SSE(20), K_SSE(21), K_SSE(22), K_SSE(23),
        K_SSE(24), K_SSE(25), K_SSE(26), K_SSE(27), K_SSE(28), K_SSE(29), K_SSE(30), K_SSE(31),
        K_SSE(32), K_SSE(33), K_SSE(34), K_SSE(35), K_SSE(36), K_SSE(37), K_SSE(38), K_SSE(39),
        K_SSE(40), K_SSE(41), K_SSE(42), K_SSE(43), K_SSE(44), K_SSE(45), K_SSE(46), K_SSE(47),
        K_SSE(48), K_SSE(49), K_SSE(50), K_SSE(51), K_SSE(52), K_SSE(53), K_SSE(54), K_SSE(55),
        K_SSE(56), K_SSE(57), K_SSE(58), K_SSE(59), K_SSE(60), K_SSE(61), K_SSE(62), K_SSE(63),
        K_SSE(64), K_SSE(65), K_SSE(66), K_SSE(67), K_SSE(68), K_SSE(69), K_SSE(70), K_SSE(71),
        K_SSE(72), K_SSE(73), K_SSE(74), K_SSE(75), K_SSE(76), K_SSE(77), K_SSE(78), K_SSE(79)
#undef K_SSE
    };
    return K;
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline const __m128i* get_iv_sse() {
    alignas(16) static const __m128i IV[8] = {
        _mm_set1_epi64x((long long)0x6a09e667f3bcc908ULL),
        _mm_set1_epi64x((long long)0xbb67ae8584caa73bULL),
        _mm_set1_epi64x((long long)0x3c6ef372fe94f82bULL),
        _mm_set1_epi64x((long long)0xa54ff53a5f1d36f1ULL),
        _mm_set1_epi64x((long long)0x510e527fade682d1ULL),
        _mm_set1_epi64x((long long)0x9b05688c2b3e6c1fULL),
        _mm_set1_epi64x((long long)0x1f83d9abfb41bd6bULL),
        _mm_set1_epi64x((long long)0x5be0cd19137e2179ULL)
    };
    return IV;
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline const __m256i* get_k512_avx2() {
    alignas(32) static const __m256i K[80] = {
#define K_AVX2(i) _mm256_set1_epi64x((long long)K512_SIMD[i])
        K_AVX2(0),  K_AVX2(1),  K_AVX2(2),  K_AVX2(3),  K_AVX2(4),  K_AVX2(5),  K_AVX2(6),  K_AVX2(7),
        K_AVX2(8),  K_AVX2(9),  K_AVX2(10), K_AVX2(11), K_AVX2(12), K_AVX2(13), K_AVX2(14), K_AVX2(15),
        K_AVX2(16), K_AVX2(17), K_AVX2(18), K_AVX2(19), K_AVX2(20), K_AVX2(21), K_AVX2(22), K_AVX2(23),
        K_AVX2(24), K_AVX2(25), K_AVX2(26), K_AVX2(27), K_AVX2(28), K_AVX2(29), K_AVX2(30), K_AVX2(31),
        K_AVX2(32), K_AVX2(33), K_AVX2(34), K_AVX2(35), K_AVX2(36), K_AVX2(37), K_AVX2(38), K_AVX2(39),
        K_AVX2(40), K_AVX2(41), K_AVX2(42), K_AVX2(43), K_AVX2(44), K_AVX2(45), K_AVX2(46), K_AVX2(47),
        K_AVX2(48), K_AVX2(49), K_AVX2(50), K_AVX2(51), K_AVX2(52), K_AVX2(53), K_AVX2(54), K_AVX2(55),
        K_AVX2(56), K_AVX2(57), K_AVX2(58), K_AVX2(59), K_AVX2(60), K_AVX2(61), K_AVX2(62), K_AVX2(63),
        K_AVX2(64), K_AVX2(65), K_AVX2(66), K_AVX2(67), K_AVX2(68), K_AVX2(69), K_AVX2(70), K_AVX2(71),
        K_AVX2(72), K_AVX2(73), K_AVX2(74), K_AVX2(75), K_AVX2(76), K_AVX2(77), K_AVX2(78), K_AVX2(79)
#undef K_AVX2
    };
    return K;
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline const __m256i* get_iv_avx2() {
    alignas(32) static const __m256i IV[8] = {
        _mm256_set1_epi64x((long long)0x6a09e667f3bcc908ULL),
        _mm256_set1_epi64x((long long)0xbb67ae8584caa73bULL),
        _mm256_set1_epi64x((long long)0x3c6ef372fe94f82bULL),
        _mm256_set1_epi64x((long long)0xa54ff53a5f1d36f1ULL),
        _mm256_set1_epi64x((long long)0x510e527fade682d1ULL),
        _mm256_set1_epi64x((long long)0x9b05688c2b3e6c1fULL),
        _mm256_set1_epi64x((long long)0x1f83d9abfb41bd6bULL),
        _mm256_set1_epi64x((long long)0x5be0cd19137e2179ULL)
    };
    return IV;
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline const __m512i* get_k512_avx512() {
    alignas(64) static const __m512i K[80] = {
#define K_AVX512(i) _mm512_set1_epi64((long long)K512_SIMD[i])
        K_AVX512(0),  K_AVX512(1),  K_AVX512(2),  K_AVX512(3),  K_AVX512(4),  K_AVX512(5),  K_AVX512(6),  K_AVX512(7),
        K_AVX512(8),  K_AVX512(9),  K_AVX512(10), K_AVX512(11), K_AVX512(12), K_AVX512(13), K_AVX512(14), K_AVX512(15),
        K_AVX512(16), K_AVX512(17), K_AVX512(18), K_AVX512(19), K_AVX512(20), K_AVX512(21), K_AVX512(22), K_AVX512(23),
        K_AVX512(24), K_AVX512(25), K_AVX512(26), K_AVX512(27), K_AVX512(28), K_AVX512(29), K_AVX512(30), K_AVX512(31),
        K_AVX512(32), K_AVX512(33), K_AVX512(34), K_AVX512(35), K_AVX512(36), K_AVX512(37), K_AVX512(38), K_AVX512(39),
        K_AVX512(40), K_AVX512(41), K_AVX512(42), K_AVX512(43), K_AVX512(44), K_AVX512(45), K_AVX512(46), K_AVX512(47),
        K_AVX512(48), K_AVX512(49), K_AVX512(50), K_AVX512(51), K_AVX512(52), K_AVX512(53), K_AVX512(54), K_AVX512(55),
        K_AVX512(56), K_AVX512(57), K_AVX512(58), K_AVX512(59), K_AVX512(60), K_AVX512(61), K_AVX512(62), K_AVX512(63),
        K_AVX512(64), K_AVX512(65), K_AVX512(66), K_AVX512(67), K_AVX512(68), K_AVX512(69), K_AVX512(70), K_AVX512(71),
        K_AVX512(72), K_AVX512(73), K_AVX512(74), K_AVX512(75), K_AVX512(76), K_AVX512(77), K_AVX512(78), K_AVX512(79)
#undef K_AVX512
    };
    return K;
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline const __m512i* get_iv_avx512() {
    alignas(64) static const __m512i IV[8] = {
        _mm512_set1_epi64((long long)0x6a09e667f3bcc908ULL),
        _mm512_set1_epi64((long long)0xbb67ae8584caa73bULL),
        _mm512_set1_epi64((long long)0x3c6ef372fe94f82bULL),
        _mm512_set1_epi64((long long)0xa54ff53a5f1d36f1ULL),
        _mm512_set1_epi64((long long)0x510e527fade682d1ULL),
        _mm512_set1_epi64((long long)0x9b05688c2b3e6c1fULL),
        _mm512_set1_epi64((long long)0x1f83d9abfb41bd6bULL),
        _mm512_set1_epi64((long long)0x5be0cd19137e2179ULL)
    };
    return IV;
}

alignas(16) static constexpr uint8_t SHUF_ROR8_SSE[16] = {
    1, 2, 3, 4, 5, 6, 7, 0,
    9, 10, 11, 12, 13, 14, 15, 8
};

alignas(32) static constexpr uint8_t SHUF_ROR8_AVX2[32] = {
    1, 2, 3, 4, 5, 6, 7, 0,
    9, 10, 11, 12, 13, 14, 15, 8,
    1, 2, 3, 4, 5, 6, 7, 0,
    9, 10, 11, 12, 13, 14, 15, 8
};

// =========================================================================
// SSE4.1
// =========================================================================
#define ROR128_64(x, n) _mm_xor_si128(_mm_srli_epi64(x, n), _mm_slli_epi64(x, 64 - (n)))
#define CH_SSE(x, y, z) _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z)))
#define MAJ_SSE(x, y, z) _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)))
#define S0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 28), ROR128_64(x, 34)), ROR128_64(x, 39))
#define S1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 14), ROR128_64(x, 18)), ROR128_64(x, 41))
#define s0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 1), _mm_shuffle_epi8(x, _mm_load_si128((const __m128i*)SHUF_ROR8_SSE))), _mm_srli_epi64(x, 7))
#define s1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 19), ROR128_64(x, 61)), _mm_srli_epi64(x, 6))

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_block64_sse(
    const __m128i iv[8],
    __m128i W[16],
    __m128i out[8])
{
    __m128i a = iv[0]; __m128i b = iv[1]; __m128i c = iv[2]; __m128i d = iv[3];
    __m128i e = iv[4]; __m128i f = iv[5]; __m128i g = iv[6]; __m128i h = iv[7];

    const __m128i* k_tbl = get_k512_sse();
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m128i h_s1  = _mm_add_epi64(h, S1_SSE(e));
            __m128i ch_k  = _mm_add_epi64(CH_SSE(e, f, g), k_tbl[r * 16 + i]);
            __m128i ch_kw = _mm_add_epi64(ch_k, W[i]);
            __m128i T1    = _mm_add_epi64(h_s1, ch_kw);
            __m128i T2    = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));

            h = g; g = f; f = e;
            e = _mm_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm_add_epi64(T1, T2);

            if (r < 4) {
                const __m128i w1  = W[(i + 1)  & 15];
                const __m128i w9  = W[(i + 9)  & 15];
                const __m128i w14 = W[(i + 14) & 15];
                W[i] = _mm_add_epi64(W[i],
                        _mm_add_epi64(_mm_add_epi64(s0_SSE(w1), w9), s1_SSE(w14)));
            }
        }
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void inline_transform_sse(SHA512_SSE_State* ctx, const uint64_t W_in[16][2]) {
    __m128i iv[8], W[16], out[8];
    for (int i = 0; i < 8; ++i) iv[i] = _mm_loadu_si128((const __m128i*)ctx->state[i]);
    for (int i = 0; i < 16; ++i) W[i] = _mm_loadu_si128((const __m128i*)W_in[i]);
    sha512_block64_sse(iv, W, out);
    for (int i = 0; i < 8; ++i) _mm_storeu_si128((__m128i*)ctx->state[i], out[i]);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void pbkdf2_2lane_fused_stream(
    const __m128i ipad_iv[8], const __m128i opad_iv[8],
    const __m128i initial_digest[8],
    __m128i T[8],
    uint32_t iterations)
{
    __m128i W[16];
    const __m128i w8_val  = _mm_set1_epi64x((long long)0x8000000000000000ULL);
    const __m128i w_zero  = _mm_setzero_si128();
    const __m128i w15_val = _mm_set1_epi64x((long long)(128 + 64) * 8);

    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    for (uint32_t iter = 1; iter < iterations; ++iter) {
        W[8]  = w8_val;
        W[9]  = w_zero;  W[10] = w_zero; W[11] = w_zero;
        W[12] = w_zero;  W[13] = w_zero; W[14] = w_zero;
        W[15] = w15_val;

        // In-place zero-copy: output written directly to W[0..7]
        sha512_block64_sse(ipad_iv, W, W);

        W[8]  = w8_val;
        W[9]  = w_zero;  W[10] = w_zero; W[11] = w_zero;
        W[12] = w_zero;  W[13] = w_zero; W[14] = w_zero;
        W[15] = w15_val;

        sha512_block64_sse(opad_iv, W, W);

        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            T[i] = _mm_xor_si128(T[i], W[i]);
        }
    }
}

[[gnu::target("sse4.1")]]
inline void pbkdf2_hmac_sha512_4way_sse(
    const char* p1, size_t l1,     const char* p2, size_t l2,     const char* p3, size_t l3,     const char* p4, size_t l4,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64])
{
    auto populate_W = [&](const char* pass, size_t len, int lane, uint64_t W_ipad[16][2], uint64_t W_opad[16][2]) {
        uint8_t K[128] = {};
        if (len > 128) { crypto::SHA512::hash(pass, len, K); }
        else { memcpy(K, pass, len); }

        const uint64_t* K64 = reinterpret_cast<const uint64_t*>(K);
        for (int w = 0; w < 16; w++) {
            W_ipad[w][lane] = __builtin_bswap64(K64[w] ^ 0x3636363636363636ULL);
            W_opad[w][lane] = __builtin_bswap64(K64[w] ^ 0x5c5c5c5c5c5c5c5cULL);
        }
    };
    uint64_t W_ipad1[16][2] = {}; uint64_t W_opad1[16][2] = {};
    populate_W(p1, l1, 0, W_ipad1, W_opad1);
    populate_W(p2, l2, 1, W_ipad1, W_opad1);

    uint64_t W_ipad2[16][2] = {}; uint64_t W_opad2[16][2] = {};
    populate_W(p3, l3, 0, W_ipad2, W_opad2);
    populate_W(p4, l4, 1, W_ipad2, W_opad2);

    __m128i ipad1_vec[8], opad1_vec[8];
    __m128i ipad2_vec[8], opad2_vec[8];
    __m128i W1[16], W2[16];

    for (int i = 0; i < 16; ++i) W1[i] = _mm_loadu_si128((const __m128i*)W_ipad1[i]);
    sha512_block64_sse(get_iv_sse(), W1, ipad1_vec);

    for (int i = 0; i < 16; ++i) W1[i] = _mm_loadu_si128((const __m128i*)W_opad1[i]);
    sha512_block64_sse(get_iv_sse(), W1, opad1_vec);

    for (int i = 0; i < 16; ++i) W2[i] = _mm_loadu_si128((const __m128i*)W_ipad2[i]);
    sha512_block64_sse(get_iv_sse(), W2, ipad2_vec);

    for (int i = 0; i < 16; ++i) W2[i] = _mm_loadu_si128((const __m128i*)W_opad2[i]);
    sha512_block64_sse(get_iv_sse(), W2, opad2_vec);

    // Prepare Salt Block (shared across all lanes)
    __m128i msg_salt[16] = {};
    uint8_t salt_buf[128] = {};
    memcpy(salt_buf, salt, salt_len);
    salt_buf[salt_len]     = 0;
    salt_buf[salt_len + 1] = 0;
    salt_buf[salt_len + 2] = 0;
    salt_buf[salt_len + 3] = 1;
    salt_buf[salt_len + 4] = 0x80;

    uint64_t s_blk[16];
    memcpy(s_blk, salt_buf, 128);
    for (int w = 0; w < 15; ++w) {
        msg_salt[w] = _mm_set1_epi64x((long long)__builtin_bswap64(s_blk[w]));
    }
    msg_salt[15] = _mm_set1_epi64x((long long)(128 + salt_len + 4) * 8);

    // Inner hash of salt
    __m128i s1[8], s2[8];
    for (int w = 0; w < 16; ++w) { W1[w] = msg_salt[w]; W2[w] = msg_salt[w]; }
    sha512_block64_sse(ipad1_vec, W1, s1);
    sha512_block64_sse(ipad2_vec, W2, s2);

    // Outer hash: data is s1/s2 (64 bytes)
    const __m128i w8_val  = _mm_set1_epi64x((long long)0x8000000000000000ULL);
    const __m128i w_zero  = _mm_setzero_si128();
    const __m128i w15_val = _mm_set1_epi64x((long long)(128 + 64) * 8);

    for (int i = 0; i < 8; ++i) { W1[i] = s1[i]; W2[i] = s2[i]; }
    W1[8] = w8_val;  W2[8] = w8_val;
    W1[9] = w_zero;  W2[9] = w_zero;
    W1[10] = w_zero; W2[10] = w_zero;
    W1[11] = w_zero; W2[11] = w_zero;
    W1[12] = w_zero; W2[12] = w_zero;
    W1[13] = w_zero; W2[13] = w_zero;
    W1[14] = w_zero; W2[14] = w_zero;
    W1[15] = w15_val; W2[15] = w15_val;

    __m128i T1_vec[8], T2_vec[8];
    sha512_block64_sse(opad1_vec, W1, T1_vec);
    sha512_block64_sse(opad2_vec, W2, T2_vec);

    // PBKDF2 remaining iterations (1..iterations-1)
    pbkdf2_2lane_fused_stream(ipad1_vec, opad1_vec, T1_vec, T1_vec, iterations);
    pbkdf2_2lane_fused_stream(ipad2_vec, opad2_vec, T2_vec, T2_vec, iterations);

    alignas(16) uint64_t res1[8][2], res2[8][2];
    for (int i = 0; i < 8; ++i) {
        _mm_storeu_si128((__m128i*)res1[i], T1_vec[i]);
        _mm_storeu_si128((__m128i*)res2[i], T2_vec[i]);
    }

    for(int i = 0; i < 8; ++i) {
        uint64_t b1 = __builtin_bswap64(res1[i][0]); memcpy(out1 + i*8, &b1, 8);
        uint64_t b2 = __builtin_bswap64(res1[i][1]); memcpy(out2 + i*8, &b2, 8);
        uint64_t b3 = __builtin_bswap64(res2[i][0]); memcpy(out3 + i*8, &b3, 8);
        uint64_t b4 = __builtin_bswap64(res2[i][1]); memcpy(out4 + i*8, &b4, 8);
    }
}

// =========================================================================
// AVX2
// =========================================================================
#define ROR256_64(x, n) _mm256_or_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))
#define CH_AVX2(x, y, z) _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
#define MAJ_AVX2(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)))
#define S0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 28), ROR256_64(x, 34)), ROR256_64(x, 39))
#define S1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 14), ROR256_64(x, 18)), ROR256_64(x, 41))
#define s0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 1), _mm256_shuffle_epi8(x, _mm256_load_si256((const __m256i*)SHUF_ROR8_AVX2))), _mm256_srli_epi64(x, 7))
#define s1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 19), ROR256_64(x, 61)), _mm256_srli_epi64(x, 6))

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_block64_avx2(
    const __m256i iv[8],
    __m256i W[16],
    __m256i out[8])
{
    __m256i a = iv[0]; __m256i b = iv[1]; __m256i c = iv[2]; __m256i d = iv[3];
    __m256i e = iv[4]; __m256i f = iv[5]; __m256i g = iv[6]; __m256i h = iv[7];

    const __m256i* k_tbl = get_k512_avx2();
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m256i h_s1  = _mm256_add_epi64(h, S1_AVX2(e));
            __m256i ch_k  = _mm256_add_epi64(CH_AVX2(e, f, g), k_tbl[r * 16 + i]);
            __m256i ch_kw = _mm256_add_epi64(ch_k, W[i]);
            __m256i T1    = _mm256_add_epi64(h_s1, ch_kw);
            __m256i T2    = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));

            h = g; g = f; f = e;
            e = _mm256_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm256_add_epi64(T1, T2);

            if (r < 4) {
                const __m256i w1  = W[(i + 1)  & 15];
                const __m256i w9  = W[(i + 9)  & 15];
                const __m256i w14 = W[(i + 14) & 15];
                W[i] = _mm256_add_epi64(W[i],
                        _mm256_add_epi64(_mm256_add_epi64(s0_AVX2(w1), w9), s1_AVX2(w14)));
            }
        }
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void inline_transform_avx2(SHA512_AVX2_State* ctx, const uint64_t W_in[16][4]) {
    __m256i iv[8], W[16], out[8];
    for (int i = 0; i < 8; ++i) iv[i] = _mm256_loadu_si256((const __m256i*)ctx->state[i]);
    for (int i = 0; i < 16; ++i) W[i] = _mm256_loadu_si256((const __m256i*)W_in[i]);
    sha512_block64_avx2(iv, W, out);
    for (int i = 0; i < 8; ++i) _mm256_storeu_si256((__m256i*)ctx->state[i], out[i]);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void pbkdf2_4lane_fused_stream(
    const __m256i ipad_iv[8], const __m256i opad_iv[8],
    const __m256i initial_digest[8],
    __m256i T[8],
    uint32_t iterations)
{
    __m256i W[16];
    const __m256i w8_val  = _mm256_set1_epi64x((long long)0x8000000000000000ULL);
    const __m256i w_zero  = _mm256_setzero_si256();
    const __m256i w15_val = _mm256_set1_epi64x((long long)(128 + 64) * 8);

    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    for (uint32_t iter = 1; iter < iterations; ++iter) {
        W[8]  = w8_val;
        W[9]  = w_zero;  W[10] = w_zero; W[11] = w_zero;
        W[12] = w_zero;  W[13] = w_zero; W[14] = w_zero;
        W[15] = w15_val;

        // In-place zero-copy: output written directly into W[0..7]
        sha512_block64_avx2(ipad_iv, W, W);

        W[8]  = w8_val;
        W[9]  = w_zero;  W[10] = w_zero; W[11] = w_zero;
        W[12] = w_zero;  W[13] = w_zero; W[14] = w_zero;
        W[15] = w15_val;

        sha512_block64_avx2(opad_iv, W, W);

        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            T[i] = _mm256_xor_si256(T[i], W[i]);
        }
    }
}

[[gnu::target("avx2")]]
inline void pbkdf2_hmac_sha512_8way_avx2(
    const char* p1, size_t l1,     const char* p2, size_t l2,     const char* p3, size_t l3,     const char* p4, size_t l4,     const char* p5, size_t l5,     const char* p6, size_t l6,     const char* p7, size_t l7,     const char* p8, size_t l8,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64], uint8_t out5[64], uint8_t out6[64], uint8_t out7[64], uint8_t out8[64])
{
    auto populate_W = [&](const char* pass, size_t len, int lane, uint64_t W_ipad[16][4], uint64_t W_opad[16][4]) {
        uint8_t K[128] = {};
        if (len > 128) { crypto::SHA512::hash(pass, len, K); }
        else { memcpy(K, pass, len); }

        const uint64_t* K64 = reinterpret_cast<const uint64_t*>(K);
        for (int w = 0; w < 16; w++) {
            W_ipad[w][lane] = __builtin_bswap64(K64[w] ^ 0x3636363636363636ULL);
            W_opad[w][lane] = __builtin_bswap64(K64[w] ^ 0x5c5c5c5c5c5c5c5cULL);
        }
    };
    uint64_t W_ipad1[16][4] = {}; uint64_t W_opad1[16][4] = {};
    populate_W(p1, l1, 0, W_ipad1, W_opad1);
    populate_W(p2, l2, 1, W_ipad1, W_opad1);
    populate_W(p3, l3, 2, W_ipad1, W_opad1);
    populate_W(p4, l4, 3, W_ipad1, W_opad1);

    uint64_t W_ipad2[16][4] = {}; uint64_t W_opad2[16][4] = {};
    populate_W(p5, l5, 0, W_ipad2, W_opad2);
    populate_W(p6, l6, 1, W_ipad2, W_opad2);
    populate_W(p7, l7, 2, W_ipad2, W_opad2);
    populate_W(p8, l8, 3, W_ipad2, W_opad2);

    __m256i ipad1_vec[8], opad1_vec[8];
    __m256i ipad2_vec[8], opad2_vec[8];
    __m256i W1[16], W2[16];

    for (int i = 0; i < 16; ++i) W1[i] = _mm256_loadu_si256((const __m256i*)W_ipad1[i]);
    sha512_block64_avx2(get_iv_avx2(), W1, ipad1_vec);

    for (int i = 0; i < 16; ++i) W1[i] = _mm256_loadu_si256((const __m256i*)W_opad1[i]);
    sha512_block64_avx2(get_iv_avx2(), W1, opad1_vec);

    for (int i = 0; i < 16; ++i) W2[i] = _mm256_loadu_si256((const __m256i*)W_ipad2[i]);
    sha512_block64_avx2(get_iv_avx2(), W2, ipad2_vec);

    for (int i = 0; i < 16; ++i) W2[i] = _mm256_loadu_si256((const __m256i*)W_opad2[i]);
    sha512_block64_avx2(get_iv_avx2(), W2, opad2_vec);

    // Prepare Salt Block (shared across all lanes)
    __m256i msg_salt[16] = {};
    uint8_t salt_buf[128] = {};
    memcpy(salt_buf, salt, salt_len);
    salt_buf[salt_len]     = 0;
    salt_buf[salt_len + 1] = 0;
    salt_buf[salt_len + 2] = 0;
    salt_buf[salt_len + 3] = 1;
    salt_buf[salt_len + 4] = 0x80;

    uint64_t s_blk[16];
    memcpy(s_blk, salt_buf, 128);
    for (int w = 0; w < 15; ++w) {
        msg_salt[w] = _mm256_set1_epi64x((long long)__builtin_bswap64(s_blk[w]));
    }
    msg_salt[15] = _mm256_set1_epi64x((long long)(128 + salt_len + 4) * 8);

    // Inner hash of salt
    __m256i s1[8], s2[8];
    for (int w = 0; w < 16; ++w) { W1[w] = msg_salt[w]; W2[w] = msg_salt[w]; }
    sha512_block64_avx2(ipad1_vec, W1, s1);
    sha512_block64_avx2(ipad2_vec, W2, s2);

    // Outer hash: data is s1/s2 (64 bytes)
    const __m256i w8_val  = _mm256_set1_epi64x((long long)0x8000000000000000ULL);
    const __m256i w_zero  = _mm256_setzero_si256();
    const __m256i w15_val = _mm256_set1_epi64x((long long)(128 + 64) * 8);

    for (int i = 0; i < 8; ++i) { W1[i] = s1[i]; W2[i] = s2[i]; }
    W1[8] = w8_val;  W2[8] = w8_val;
    W1[9] = w_zero;  W2[9] = w_zero;
    W1[10] = w_zero; W2[10] = w_zero;
    W1[11] = w_zero; W2[11] = w_zero;
    W1[12] = w_zero; W2[12] = w_zero;
    W1[13] = w_zero; W2[13] = w_zero;
    W1[14] = w_zero; W2[14] = w_zero;
    W1[15] = w15_val; W2[15] = w15_val;

    __m256i T1_vec[8], T2_vec[8];
    sha512_block64_avx2(opad1_vec, W1, T1_vec);
    sha512_block64_avx2(opad2_vec, W2, T2_vec);

    // PBKDF2 remaining iterations (1..iterations-1)
    pbkdf2_4lane_fused_stream(ipad1_vec, opad1_vec, T1_vec, T1_vec, iterations);
    pbkdf2_4lane_fused_stream(ipad2_vec, opad2_vec, T2_vec, T2_vec, iterations);

    alignas(32) uint64_t res1[8][4], res2[8][4];
    for (int i = 0; i < 8; ++i) {
        _mm256_storeu_si256((__m256i*)res1[i], T1_vec[i]);
        _mm256_storeu_si256((__m256i*)res2[i], T2_vec[i]);
    }

    for (int i = 0; i < 8; ++i) {
        uint64_t b1 = __builtin_bswap64(res1[i][0]); memcpy(out1 + i*8, &b1, 8);
        uint64_t b2 = __builtin_bswap64(res1[i][1]); memcpy(out2 + i*8, &b2, 8);
        uint64_t b3 = __builtin_bswap64(res1[i][2]); memcpy(out3 + i*8, &b3, 8);
        uint64_t b4 = __builtin_bswap64(res1[i][3]); memcpy(out4 + i*8, &b4, 8);
        uint64_t b5 = __builtin_bswap64(res2[i][0]); memcpy(out5 + i*8, &b5, 8);
        uint64_t b6 = __builtin_bswap64(res2[i][1]); memcpy(out6 + i*8, &b6, 8);
        uint64_t b7 = __builtin_bswap64(res2[i][2]); memcpy(out7 + i*8, &b7, 8);
        uint64_t b8 = __builtin_bswap64(res2[i][3]); memcpy(out8 + i*8, &b8, 8);
    }
}

// =========================================================================
// AVX-512
// =========================================================================
#define CH_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xCA)
#define MAJ_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xE8)
#define S0_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34)), _mm512_ror_epi64(x, 39))
#define S1_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18)), _mm512_ror_epi64(x, 41))
#define s0_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 1), _mm512_ror_epi64(x, 8)), _mm512_srli_epi64(x, 7))
#define s1_AVX512(x) _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61)), _mm512_srli_epi64(x, 6))

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_block64_avx512(
    const __m512i iv[8],
    __m512i W[16],
    __m512i out[8])
{
    __m512i a = iv[0]; __m512i b = iv[1]; __m512i c = iv[2]; __m512i d = iv[3];
    __m512i e = iv[4]; __m512i f = iv[5]; __m512i g = iv[6]; __m512i h = iv[7];

    const __m512i* k_tbl = get_k512_avx512();
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m512i h_s1  = _mm512_add_epi64(h, S1_AVX512(e));
            __m512i ch_k  = _mm512_add_epi64(CH_AVX512(e, f, g), k_tbl[r * 16 + i]);
            __m512i ch_kw = _mm512_add_epi64(ch_k, W[i]);
            __m512i T1    = _mm512_add_epi64(h_s1, ch_kw);
            __m512i T2    = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));

            h = g; g = f; f = e;
            e = _mm512_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm512_add_epi64(T1, T2);

            if (r < 4) {
                const __m512i w1  = W[(i + 1)  & 15];
                const __m512i w9  = W[(i + 9)  & 15];
                const __m512i w14 = W[(i + 14) & 15];
                W[i] = _mm512_add_epi64(W[i],
                        _mm512_add_epi64(_mm512_add_epi64(s0_AVX512(w1), w9), s1_AVX512(w14)));
            }
        }
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void inline_transform_avx512(SHA512_AVX512_State* ctx, const uint64_t W_in[16][8]) {
    __m512i iv[8], W[16], out[8];
    for (int i = 0; i < 8; ++i) iv[i] = _mm512_loadu_si512((const __m512i*)ctx->state[i]);
    for (int i = 0; i < 16; ++i) W[i] = _mm512_loadu_si512((const __m512i*)W_in[i]);
    sha512_block64_avx512(iv, W, out);
    for (int i = 0; i < 8; ++i) _mm512_storeu_si512((__m512i*)ctx->state[i], out[i]);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void pbkdf2_8lane_fused_stream(
    const __m512i ipad_iv[8], const __m512i opad_iv[8],
    const __m512i initial_digest[8],
    __m512i T[8],
    uint32_t iterations)
{
    __m512i W[16];
    const __m512i w8_val  = _mm512_set1_epi64((long long)0x8000000000000000ULL);
    const __m512i w_zero  = _mm512_setzero_si512();
    const __m512i w15_val = _mm512_set1_epi64((long long)(128 + 64) * 8);

    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    for (uint32_t iter = 1; iter < iterations; ++iter) {
        W[8]  = w8_val;
        W[9]  = w_zero;  W[10] = w_zero; W[11] = w_zero;
        W[12] = w_zero;  W[13] = w_zero; W[14] = w_zero;
        W[15] = w15_val;

        // In-place zero-copy: output written directly into W[0..7]
        sha512_block64_avx512(ipad_iv, W, W);

        W[8]  = w8_val;
        W[9]  = w_zero;  W[10] = w_zero; W[11] = w_zero;
        W[12] = w_zero;  W[13] = w_zero; W[14] = w_zero;
        W[15] = w15_val;

        sha512_block64_avx512(opad_iv, W, W);

        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) {
            T[i] = _mm512_xor_si512(T[i], W[i]);
        }
    }
}

[[gnu::target("avx512f,avx512vl")]]
inline void pbkdf2_hmac_sha512_16way_avx512(
    const char* p1, size_t l1,     const char* p2, size_t l2,     const char* p3, size_t l3,     const char* p4, size_t l4,     const char* p5, size_t l5,     const char* p6, size_t l6,     const char* p7, size_t l7,     const char* p8, size_t l8,     const char* p9, size_t l9,     const char* p10, size_t l10,     const char* p11, size_t l11,     const char* p12, size_t l12,     const char* p13, size_t l13,     const char* p14, size_t l14,     const char* p15, size_t l15,     const char* p16, size_t l16,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64], uint8_t out5[64], uint8_t out6[64], uint8_t out7[64], uint8_t out8[64], uint8_t out9[64], uint8_t out10[64], uint8_t out11[64], uint8_t out12[64], uint8_t out13[64], uint8_t out14[64], uint8_t out15[64], uint8_t out16[64])
{
    auto populate_W = [&](const char* pass, size_t len, int lane, uint64_t W_ipad[16][8], uint64_t W_opad[16][8]) {
        uint8_t K[128] = {};
        if (len > 128) { crypto::SHA512::hash(pass, len, K); }
        else { memcpy(K, pass, len); }

        const uint64_t* K64 = reinterpret_cast<const uint64_t*>(K);
        for (int w = 0; w < 16; w++) {
            W_ipad[w][lane] = __builtin_bswap64(K64[w] ^ 0x3636363636363636ULL);
            W_opad[w][lane] = __builtin_bswap64(K64[w] ^ 0x5c5c5c5c5c5c5c5cULL);
        }
    };

    uint64_t W_ipad1[16][8] = {}; uint64_t W_opad1[16][8] = {};
    populate_W(p1, l1, 0, W_ipad1, W_opad1);
    populate_W(p2, l2, 1, W_ipad1, W_opad1);
    populate_W(p3, l3, 2, W_ipad1, W_opad1);
    populate_W(p4, l4, 3, W_ipad1, W_opad1);
    populate_W(p5, l5, 4, W_ipad1, W_opad1);
    populate_W(p6, l6, 5, W_ipad1, W_opad1);
    populate_W(p7, l7, 6, W_ipad1, W_opad1);
    populate_W(p8, l8, 7, W_ipad1, W_opad1);

    uint64_t W_ipad2[16][8] = {}; uint64_t W_opad2[16][8] = {};
    populate_W(p9, l9, 0, W_ipad2, W_opad2);
    populate_W(p10, l10, 1, W_ipad2, W_opad2);
    populate_W(p11, l11, 2, W_ipad2, W_opad2);
    populate_W(p12, l12, 3, W_ipad2, W_opad2);
    populate_W(p13, l13, 4, W_ipad2, W_opad2);
    populate_W(p14, l14, 5, W_ipad2, W_opad2);
    populate_W(p15, l15, 6, W_ipad2, W_opad2);
    populate_W(p16, l16, 7, W_ipad2, W_opad2);

    __m512i ipad1_vec[8], opad1_vec[8];
    __m512i ipad2_vec[8], opad2_vec[8];
    __m512i W1[16], W2[16];

    for (int i = 0; i < 16; ++i) W1[i] = _mm512_loadu_si512((const __m512i*)W_ipad1[i]);
    sha512_block64_avx512(get_iv_avx512(), W1, ipad1_vec);

    for (int i = 0; i < 16; ++i) W1[i] = _mm512_loadu_si512((const __m512i*)W_opad1[i]);
    sha512_block64_avx512(get_iv_avx512(), W1, opad1_vec);

    for (int i = 0; i < 16; ++i) W2[i] = _mm512_loadu_si512((const __m512i*)W_ipad2[i]);
    sha512_block64_avx512(get_iv_avx512(), W2, ipad2_vec);

    for (int i = 0; i < 16; ++i) W2[i] = _mm512_loadu_si512((const __m512i*)W_opad2[i]);
    sha512_block64_avx512(get_iv_avx512(), W2, opad2_vec);

    // Prepare Salt Block (shared across all lanes)
    __m512i msg_salt[16] = {};
    uint8_t salt_buf[128] = {};
    memcpy(salt_buf, salt, salt_len);
    salt_buf[salt_len]     = 0;
    salt_buf[salt_len + 1] = 0;
    salt_buf[salt_len + 2] = 0;
    salt_buf[salt_len + 3] = 1;
    salt_buf[salt_len + 4] = 0x80;

    uint64_t s_blk[16];
    memcpy(s_blk, salt_buf, 128);
    for (int w = 0; w < 15; ++w) {
        msg_salt[w] = _mm512_set1_epi64((long long)__builtin_bswap64(s_blk[w]));
    }
    msg_salt[15] = _mm512_set1_epi64((long long)(128 + salt_len + 4) * 8);

    // Inner hash of salt
    __m512i s1[8], s2[8];
    for (int w = 0; w < 16; ++w) { W1[w] = msg_salt[w]; W2[w] = msg_salt[w]; }
    sha512_block64_avx512(ipad1_vec, W1, s1);
    sha512_block64_avx512(ipad2_vec, W2, s2);

    // Outer hash: data is s1/s2 (64 bytes)
    const __m512i w8_val  = _mm512_set1_epi64((long long)0x8000000000000000ULL);
    const __m512i w_zero  = _mm512_setzero_si512();
    const __m512i w15_val = _mm512_set1_epi64((long long)(128 + 64) * 8);

    for (int i = 0; i < 8; ++i) { W1[i] = s1[i]; W2[i] = s2[i]; }
    W1[8] = w8_val;  W2[8] = w8_val;
    W1[9] = w_zero;  W2[9] = w_zero;
    W1[10] = w_zero; W2[10] = w_zero;
    W1[11] = w_zero; W2[11] = w_zero;
    W1[12] = w_zero; W2[12] = w_zero;
    W1[13] = w_zero; W2[13] = w_zero;
    W1[14] = w_zero; W2[14] = w_zero;
    W1[15] = w15_val; W2[15] = w15_val;

    __m512i T1_vec[8], T2_vec[8];
    sha512_block64_avx512(opad1_vec, W1, T1_vec);
    sha512_block64_avx512(opad2_vec, W2, T2_vec);

    // PBKDF2 remaining iterations (1..iterations-1)
    pbkdf2_8lane_fused_stream(ipad1_vec, opad1_vec, T1_vec, T1_vec, iterations);
    pbkdf2_8lane_fused_stream(ipad2_vec, opad2_vec, T2_vec, T2_vec, iterations);

    alignas(64) uint64_t res1[8][8], res2[8][8];
    for (int i=0; i<8; i++) {
        _mm512_storeu_si512((__m512i*)res1[i], T1_vec[i]);
        _mm512_storeu_si512((__m512i*)res2[i], T2_vec[i]);
    }

    for(int i = 0; i < 8; i++) {
        uint64_t b1 = __builtin_bswap64(res1[i][0]); memcpy(out1 + i*8, &b1, 8);
        uint64_t b2 = __builtin_bswap64(res1[i][1]); memcpy(out2 + i*8, &b2, 8);
        uint64_t b3 = __builtin_bswap64(res1[i][2]); memcpy(out3 + i*8, &b3, 8);
        uint64_t b4 = __builtin_bswap64(res1[i][3]); memcpy(out4 + i*8, &b4, 8);
        uint64_t b5 = __builtin_bswap64(res1[i][4]); memcpy(out5 + i*8, &b5, 8);
        uint64_t b6 = __builtin_bswap64(res1[i][5]); memcpy(out6 + i*8, &b6, 8);
        uint64_t b7 = __builtin_bswap64(res1[i][6]); memcpy(out7 + i*8, &b7, 8);
        uint64_t b8 = __builtin_bswap64(res1[i][7]); memcpy(out8 + i*8, &b8, 8);

        uint64_t b9 = __builtin_bswap64(res2[i][0]); memcpy(out9 + i*8, &b9, 8);
        uint64_t b10 = __builtin_bswap64(res2[i][1]); memcpy(out10 + i*8, &b10, 8);
        uint64_t b11 = __builtin_bswap64(res2[i][2]); memcpy(out11 + i*8, &b11, 8);
        uint64_t b12 = __builtin_bswap64(res2[i][3]); memcpy(out12 + i*8, &b12, 8);
        uint64_t b13 = __builtin_bswap64(res2[i][4]); memcpy(out13 + i*8, &b13, 8);
        uint64_t b14 = __builtin_bswap64(res2[i][5]); memcpy(out14 + i*8, &b14, 8);
        uint64_t b15 = __builtin_bswap64(res2[i][6]); memcpy(out15 + i*8, &b15, 8);
        uint64_t b16 = __builtin_bswap64(res2[i][7]); memcpy(out16 + i*8, &b16, 8);
    }
}
