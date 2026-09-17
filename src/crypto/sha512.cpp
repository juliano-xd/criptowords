#include "../../include/crypto/sha512.hpp"

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <bit>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>

// Defina SHA512_NO_SIMD para forcar a rota escalar (ARM/Termux, debug, etc).
#if !defined(SHA512_NO_SIMD) && (defined(__x86_64__) || defined(__i386__))
  #define SHA512_X86 1
  #include <immintrin.h>
#endif

// =========================================================================
// CONSTANTES
// =========================================================================

alignas(64) static constexpr uint64_t K512[80] = {
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

static constexpr uint64_t SHA512_IV[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// -------------------------------------------------------------------------
// Tabelas de K ja replicadas por lane.
// Permite `vpaddq ymm, ymm, [mem]` (1 uop) no lugar de
// `vpbroadcastq` + `vpaddq` (2 uops) — 80 uops economizados por bloco SIMD.
// AVX-512 nao precisa: tem broadcast embutido no operando de memoria.
// -------------------------------------------------------------------------
template <int N>
struct KLanes { alignas(64) uint64_t v[80][N]; };

template <int N>
static constexpr KLanes<N> make_klanes() {
    KLanes<N> t{};
    for (int i = 0; i < 80; ++i)
        for (int j = 0; j < N; ++j) t.v[i][j] = K512[i];
    return t;
}

#ifdef SHA512_X86
static constexpr KLanes<2> K512x2 = make_klanes<2>();
static constexpr KLanes<4> K512x4 = make_klanes<4>();
#endif

// =========================================================================
// PRIMITIVAS ESCALARES
// =========================================================================

namespace {

[[gnu::always_inline]] inline uint64_t Ch64  (uint64_t x, uint64_t y, uint64_t z) { return z ^ (x & (y ^ z)); }
[[gnu::always_inline]] inline uint64_t Maj64 (uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (z & (x | y)); }
[[gnu::always_inline]] inline uint64_t BSig0 (uint64_t x) { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); }
[[gnu::always_inline]] inline uint64_t BSig1 (uint64_t x) { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); }
[[gnu::always_inline]] inline uint64_t SSig0 (uint64_t x) { return std::rotr(x, 1)  ^ std::rotr(x, 8)  ^ (x >> 7); }
[[gnu::always_inline]] inline uint64_t SSig1 (uint64_t x) { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }

[[gnu::always_inline]] inline uint64_t load_be64(const uint8_t* p) {
    uint64_t v; std::memcpy(&v, p, 8); return __builtin_bswap64(v);
}

} // namespace

#define RND_S(K, WV)                                                    \
    do {                                                                \
        const uint64_t _t1 = h + BSig1(e) + Ch64(e, f, g) + (K) + (WV); \
        const uint64_t _t2 = BSig0(a) + Maj64(a, b, c);                 \
        h = g; g = f; f = e; e = d + _t1;                               \
        d = c; c = b; b = a; a = _t1 + _t2;                             \
    } while (0)

// =========================================================================
// DETECCAO DE ISA — resolvida UMA vez na inicializacao estatica.
// (o codigo anterior chamava __builtin_cpu_init/supports a cada batch)
// =========================================================================

namespace {

enum class Isa : int { Scalar = 0, Sse41 = 1, Avx2 = 2, Avx512 = 3 };

Isa detect_isa() {
#if defined(SHA512_X86) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    if (__builtin_cpu_supports("avx512f") &&
        __builtin_cpu_supports("avx512vl") &&
        __builtin_cpu_supports("avx512bw")) return Isa::Avx512;
    if (__builtin_cpu_supports("avx2"))     return Isa::Avx2;
    if (__builtin_cpu_supports("sse4.1"))   return Isa::Sse41;
#endif
    return Isa::Scalar;
}

const Isa g_isa = detect_isa();

} // namespace

// =========================================================================
// KERNELS SIMD
// =========================================================================

#ifdef SHA512_X86

// ---- rotacoes -----------------------------------------------------------
#define ROR128(x, n) _mm_xor_si128   (_mm_srli_epi64   (x, n), _mm_slli_epi64   (x, 64 - (n)))
#define ROR256(x, n) _mm256_xor_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))

// ror64 por 8 = 1 shuffle de bytes (vs. 3 ops shift/shift/xor)
#define ROR128_8(x) _mm_shuffle_epi8   (x, k_ror8_128)
#define ROR256_8(x) _mm256_shuffle_epi8(x, k_ror8_256)

// ---- SSE4.1 -------------------------------------------------------------
#define CH_S(x, y, z)  _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z)))
#define MAJ_S(x, y, z) _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)))
#define BS0_S(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 28), ROR128(x, 34)), ROR128(x, 39))
#define BS1_S(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 14), ROR128(x, 18)), ROR128(x, 41))
#define SS0_S(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 1),  ROR128_8(x)),   _mm_srli_epi64(x, 7))
#define SS1_S(x) _mm_xor_si128(_mm_xor_si128(ROR128(x, 19), ROR128(x, 61)), _mm_srli_epi64(x, 6))

#define RND_SSE(T, WV)                                                       \
    do {                                                                     \
        __m128i _t1 = _mm_add_epi64(                                         \
            _mm_add_epi64(h, BS1_S(e)),                                      \
            _mm_add_epi64(_mm_add_epi64(CH_S(e, f, g),                       \
                          _mm_load_si128((const __m128i*)K512x2.v[(T)])),    \
                          (WV)));                                            \
        __m128i _t2 = _mm_add_epi64(BS0_S(a), MAJ_S(a, b, c));               \
        h = g; g = f; f = e; e = _mm_add_epi64(d, _t1);                      \
        d = c; c = b; b = a; a = _mm_add_epi64(_t1, _t2);                    \
    } while (0)

#define EXPAND_SSE(W)                                                        \
    do {                                                                     \
        _Pragma("GCC unroll 16")                                             \
        for (int _i = 0; _i < 16; ++_i) {                                    \
            __m128i _w1  = W[(_i + 1)  & 15];                                \
            __m128i _w9  = W[(_i + 9)  & 15];                                \
            __m128i _w14 = W[(_i + 14) & 15];                                \
            W[_i] = _mm_add_epi64(W[_i],                                     \
                    _mm_add_epi64(_mm_add_epi64(SS0_S(_w1), _w9),            \
                                  SS1_S(_w14)));                             \
        }                                                                    \
    } while (0)

// ---- AVX2 ---------------------------------------------------------------
#define CH_A(x, y, z)  _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
#define MAJ_A(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)))
#define BS0_A(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 28), ROR256(x, 34)), ROR256(x, 39))
#define BS1_A(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 14), ROR256(x, 18)), ROR256(x, 41))
#define SS0_A(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 1),  ROR256_8(x)),   _mm256_srli_epi64(x, 7))
#define SS1_A(x) _mm256_xor_si256(_mm256_xor_si256(ROR256(x, 19), ROR256(x, 61)), _mm256_srli_epi64(x, 6))

#define RND_AVX2(T, WV)                                                          \
    do {                                                                         \
        __m256i _t1 = _mm256_add_epi64(                                          \
            _mm256_add_epi64(h, BS1_A(e)),                                       \
            _mm256_add_epi64(_mm256_add_epi64(CH_A(e, f, g),                     \
                             _mm256_load_si256((const __m256i*)K512x4.v[(T)])),  \
                             (WV)));                                             \
        __m256i _t2 = _mm256_add_epi64(BS0_A(a), MAJ_A(a, b, c));                \
        h = g; g = f; f = e; e = _mm256_add_epi64(d, _t1);                       \
        d = c; c = b; b = a; a = _mm256_add_epi64(_t1, _t2);                     \
    } while (0)

#define EXPAND_AVX2(W)                                                           \
    do {                                                                         \
        _Pragma("GCC unroll 16")                                                 \
        for (int _i = 0; _i < 16; ++_i) {                                        \
            __m256i _w1  = W[(_i + 1)  & 15];                                    \
            __m256i _w9  = W[(_i + 9)  & 15];                                    \
            __m256i _w14 = W[(_i + 14) & 15];                                    \
            W[_i] = _mm256_add_epi64(W[_i],                                      \
                    _mm256_add_epi64(_mm256_add_epi64(SS0_A(_w1), _w9),          \
                                     SS1_A(_w14)));                              \
        }                                                                        \
    } while (0)

// ---- AVX-512 ------------------------------------------------------------
// vpternlogq colapsa Ch, Maj e os XOR triplos das sigmas em 1 uop cada.
#define CH_Z(x, y, z)  _mm512_ternarylogic_epi64(x, y, z, 0xCA)
#define MAJ_Z(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xE8)
#define XOR3_Z(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0x96)
#define BS0_Z(x) XOR3_Z(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34), _mm512_ror_epi64(x, 39))
#define BS1_Z(x) XOR3_Z(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18), _mm512_ror_epi64(x, 41))
#define SS0_Z(x) XOR3_Z(_mm512_ror_epi64(x, 1),  _mm512_ror_epi64(x, 8),  _mm512_srli_epi64(x, 7))
#define SS1_Z(x) XOR3_Z(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61), _mm512_srli_epi64(x, 6))

#define RND_AVX512(T, WV)                                                        \
    do {                                                                         \
        __m512i _t1 = _mm512_add_epi64(                                          \
            _mm512_add_epi64(h, BS1_Z(e)),                                       \
            _mm512_add_epi64(_mm512_add_epi64(CH_Z(e, f, g),                     \
                             _mm512_set1_epi64((long long)K512[(T)])),           \
                             (WV)));                                             \
        __m512i _t2 = _mm512_add_epi64(BS0_Z(a), MAJ_Z(a, b, c));                \
        h = g; g = f; f = e; e = _mm512_add_epi64(d, _t1);                       \
        d = c; c = b; b = a; a = _mm512_add_epi64(_t1, _t2);                     \
    } while (0)

#define EXPAND_AVX512(W)                                                         \
    do {                                                                         \
        _Pragma("GCC unroll 16")                                                 \
        for (int _i = 0; _i < 16; ++_i) {                                        \
            __m512i _w1  = W[(_i + 1)  & 15];                                    \
            __m512i _w9  = W[(_i + 9)  & 15];                                    \
            __m512i _w14 = W[(_i + 14) & 15];                                    \
            W[_i] = _mm512_add_epi64(W[_i],                                      \
                    _mm512_add_epi64(_mm512_add_epi64(SS0_Z(_w1), _w9),          \
                                     SS1_Z(_w14)));                              \
        }                                                                        \
    } while (0)

// =========================================================================
// TRANSPOSICOES
// =========================================================================

[[gnu::target("avx2")]]
static inline void transpose4x4_epi64(__m256i v[4]) {
    __m256i a0 = _mm256_unpacklo_epi64(v[0], v[1]);
    __m256i a1 = _mm256_unpackhi_epi64(v[0], v[1]);
    __m256i a2 = _mm256_unpacklo_epi64(v[2], v[3]);
    __m256i a3 = _mm256_unpackhi_epi64(v[2], v[3]);
    v[0] = _mm256_permute2x128_si256(a0, a2, 0x20);
    v[1] = _mm256_permute2x128_si256(a1, a3, 0x20);
    v[2] = _mm256_permute2x128_si256(a0, a2, 0x31);
    v[3] = _mm256_permute2x128_si256(a1, a3, 0x31);
}

[[gnu::target("avx512f,avx512vl")]]
static inline void transpose8x8_epi64(__m512i v[8]) {
    __m512i a[8];
    a[0] = _mm512_unpacklo_epi64(v[0], v[1]);
    a[1] = _mm512_unpackhi_epi64(v[0], v[1]);
    a[2] = _mm512_unpacklo_epi64(v[2], v[3]);
    a[3] = _mm512_unpackhi_epi64(v[2], v[3]);
    a[4] = _mm512_unpacklo_epi64(v[4], v[5]);
    a[5] = _mm512_unpackhi_epi64(v[4], v[5]);
    a[6] = _mm512_unpacklo_epi64(v[6], v[7]);
    a[7] = _mm512_unpackhi_epi64(v[6], v[7]);

    __m512i b[8];
    b[0] = _mm512_shuffle_i64x2(a[0], a[2], 0x88);
    b[1] = _mm512_shuffle_i64x2(a[1], a[3], 0x88);
    b[2] = _mm512_shuffle_i64x2(a[0], a[2], 0xDD);
    b[3] = _mm512_shuffle_i64x2(a[1], a[3], 0xDD);
    b[4] = _mm512_shuffle_i64x2(a[4], a[6], 0x88);
    b[5] = _mm512_shuffle_i64x2(a[5], a[7], 0x88);
    b[6] = _mm512_shuffle_i64x2(a[4], a[6], 0xDD);
    b[7] = _mm512_shuffle_i64x2(a[5], a[7], 0xDD);

    v[0] = _mm512_shuffle_i64x2(b[0], b[4], 0x88);
    v[1] = _mm512_shuffle_i64x2(b[1], b[5], 0x88);
    v[2] = _mm512_shuffle_i64x2(b[2], b[6], 0x88);
    v[3] = _mm512_shuffle_i64x2(b[3], b[7], 0x88);
    v[4] = _mm512_shuffle_i64x2(b[0], b[4], 0xDD);
    v[5] = _mm512_shuffle_i64x2(b[1], b[5], 0xDD);
    v[6] = _mm512_shuffle_i64x2(b[2], b[6], 0xDD);
    v[7] = _mm512_shuffle_i64x2(b[3], b[7], 0xDD);
}

// =========================================================================
// KERNELS PUBLICOS (compatibilidade): 80 rodadas, feed-forward interno
// =========================================================================

void sha512_init_sse(SHA512_SSE_State* ctx) {
    for (int i = 0; i < 8; ++i) { ctx->state[i][0] = SHA512_IV[i]; ctx->state[i][1] = SHA512_IV[i]; }
}
void sha512_init_avx2(SHA512_AVX2_State* ctx) {
    for (int i = 0; i < 8; ++i) for (int j = 0; j < 4; ++j) ctx->state[i][j] = SHA512_IV[i];
}
void sha512_init_avx512(SHA512_AVX512_State* ctx) {
    for (int i = 0; i < 8; ++i) for (int j = 0; j < 8; ++j) ctx->state[i][j] = SHA512_IV[i];
}

[[gnu::target("sse4.1,ssse3")]]
void sha512_transform_sse(SHA512_SSE_State* ctx, const uint64_t W_in[16][2]) {
    const __m128i k_ror8_128 = _mm_setr_epi8(1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8);

    __m128i a = _mm_loadu_si128((const __m128i*)ctx->state[0]);
    __m128i b = _mm_loadu_si128((const __m128i*)ctx->state[1]);
    __m128i c = _mm_loadu_si128((const __m128i*)ctx->state[2]);
    __m128i d = _mm_loadu_si128((const __m128i*)ctx->state[3]);
    __m128i e = _mm_loadu_si128((const __m128i*)ctx->state[4]);
    __m128i f = _mm_loadu_si128((const __m128i*)ctx->state[5]);
    __m128i g = _mm_loadu_si128((const __m128i*)ctx->state[6]);
    __m128i h = _mm_loadu_si128((const __m128i*)ctx->state[7]);

    __m128i W[16];
    for (int t = 0; t < 16; ++t) W[t] = _mm_loadu_si128((const __m128i*)W_in[t]);

    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) RND_SSE(i, W[i]);
    for (int r = 1; r < 5; ++r) {
        EXPAND_SSE(W);
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) RND_SSE(r * 16 + i, W[i]);
    }

    #define ST(idx, reg) _mm_storeu_si128((__m128i*)ctx->state[idx], \
        _mm_add_epi64(_mm_loadu_si128((const __m128i*)ctx->state[idx]), (reg)))
    ST(0,a); ST(1,b); ST(2,c); ST(3,d); ST(4,e); ST(5,f); ST(6,g); ST(7,h);
    #undef ST
}

[[gnu::target("avx2")]]
void sha512_transform_avx2(SHA512_AVX2_State* ctx, const uint64_t W_in[16][4]) {
    const __m256i k_ror8_256 = _mm256_setr_epi8(1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8,
                                                1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8);

    __m256i a = _mm256_loadu_si256((const __m256i*)ctx->state[0]);
    __m256i b = _mm256_loadu_si256((const __m256i*)ctx->state[1]);
    __m256i c = _mm256_loadu_si256((const __m256i*)ctx->state[2]);
    __m256i d = _mm256_loadu_si256((const __m256i*)ctx->state[3]);
    __m256i e = _mm256_loadu_si256((const __m256i*)ctx->state[4]);
    __m256i f = _mm256_loadu_si256((const __m256i*)ctx->state[5]);
    __m256i g = _mm256_loadu_si256((const __m256i*)ctx->state[6]);
    __m256i h = _mm256_loadu_si256((const __m256i*)ctx->state[7]);

    __m256i W[16];
    for (int t = 0; t < 16; ++t) W[t] = _mm256_loadu_si256((const __m256i*)W_in[t]);

    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) RND_AVX2(i, W[i]);
    for (int r = 1; r < 5; ++r) {
        EXPAND_AVX2(W);
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) RND_AVX2(r * 16 + i, W[i]);
    }

    #define ST(idx, reg) _mm256_storeu_si256((__m256i*)ctx->state[idx], \
        _mm256_add_epi64(_mm256_loadu_si256((const __m256i*)ctx->state[idx]), (reg)))
    ST(0,a); ST(1,b); ST(2,c); ST(3,d); ST(4,e); ST(5,f); ST(6,g); ST(7,h);
    #undef ST
}

[[gnu::target("avx512f,avx512vl,avx512bw")]]
void sha512_transform_avx512(SHA512_AVX512_State* ctx, const uint64_t W_in[16][8]) {
    __m512i a = _mm512_loadu_si512((const __m512i*)ctx->state[0]);
    __m512i b = _mm512_loadu_si512((const __m512i*)ctx->state[1]);
    __m512i c = _mm512_loadu_si512((const __m512i*)ctx->state[2]);
    __m512i d = _mm512_loadu_si512((const __m512i*)ctx->state[3]);
    __m512i e = _mm512_loadu_si512((const __m512i*)ctx->state[4]);
    __m512i f = _mm512_loadu_si512((const __m512i*)ctx->state[5]);
    __m512i g = _mm512_loadu_si512((const __m512i*)ctx->state[6]);
    __m512i h = _mm512_loadu_si512((const __m512i*)ctx->state[7]);

    __m512i W[16];
    for (int t = 0; t < 16; ++t) W[t] = _mm512_loadu_si512((const __m512i*)W_in[t]);

    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) RND_AVX512(i, W[i]);
    for (int r = 1; r < 5; ++r) {
        EXPAND_AVX512(W);
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) RND_AVX512(r * 16 + i, W[i]);
    }

    #define ST(idx, reg) _mm512_storeu_si512((__m512i*)ctx->state[idx], \
        _mm512_add_epi64(_mm512_loadu_si512((const __m512i*)ctx->state[idx]), (reg)))
    ST(0,a); ST(1,b); ST(2,c); ST(3,d); ST(4,e); ST(5,f); ST(6,g); ST(7,h);
    #undef ST
}

#endif // SHA512_X86

// =========================================================================
// NUCLEO ESCALAR
// =========================================================================

namespace crypto {

SHA512::SHA512() { reset(); }

void SHA512::reset() {
    for (int i = 0; i < 8; ++i) h_[i] = SHA512_IV[i];
    total_len_ = 0;
    buf_len_   = 0;
    template_suffix_len_   = 0;
    template_single_block_ = false;
    tmpl_skip_ = 0;
    tmpl_vlo_  = 16;
    tmpl_vhi_  = 15;
}

void SHA512::update(const void* data, size_t len) {
    auto p = static_cast<const uint8_t*>(data);
    total_len_ += len;

    if (buf_len_ > 0) {
        size_t to_copy = std::min(len, static_cast<size_t>(128) - buf_len_);
        std::memcpy(buf_ + buf_len_, p, to_copy);
        buf_len_ += to_copy;
        p   += to_copy;
        len -= to_copy;
        if (buf_len_ == 128) { process_block(buf_); buf_len_ = 0; }
    }
    while (len >= 128) { process_block(p); p += 128; len -= 128; }
    if (len > 0) { std::memcpy(buf_, p, len); buf_len_ = len; }
}

void SHA512::finalize(uint8_t out[64]) {
    const uint64_t bit_len = total_len_ * 8;
    buf_[buf_len_++] = 0x80;
    if (buf_len_ > 112) {
        std::memset(buf_ + buf_len_, 0, 128 - buf_len_);
        process_block(buf_);
        buf_len_ = 0;
    }
    std::memset(buf_ + buf_len_, 0, 112 - buf_len_);
    std::memset(buf_ + 112, 0, 8);
    const uint64_t bit_len_be = __builtin_bswap64(bit_len);
    std::memcpy(buf_ + 120, &bit_len_be, 8);
    process_block(buf_);

    for (int i = 0; i < 8; ++i) {
        uint64_t v = __builtin_bswap64(h_[i]);
        std::memcpy(out + i * 8, &v, 8);
    }
}

void SHA512::hash(const void* data, size_t len, uint8_t out[64]) {
    SHA512 ctx; ctx.update(data, len); ctx.finalize(out);
}

void SHA512::process_block(const uint8_t block[128]) {
    uint64_t W[16];
    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) W[i] = load_be64(block + i * 8);

    uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

    #pragma GCC unroll 16
    for (int i = 0; i < 16; ++i) RND_S(K512[i], W[i]);

    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i)
            W[i] += SSig0(W[(i + 1) & 15]) + W[(i + 9) & 15] + SSig1(W[(i + 14) & 15]);
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) RND_S(K512[r * 16 + i], W[i]);
    }

    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

// =========================================================================
// TEMPLATE HASHING
// =========================================================================

void SHA512::build_template_tables() {
    for (int i = 0; i < 16; ++i) tmpl_w_[i] = load_be64(buf_ + i * 8);

    const size_t slot = buf_len_;
    const size_t slen = template_suffix_len_;

    if (slen == 0) {
        tmpl_vlo_ = 16; tmpl_vhi_ = 15;   // faixa variavel vazia
        tmpl_skip_ = 16;
    } else {
        tmpl_vlo_  = static_cast<uint32_t>(slot / 8);
        tmpl_vhi_  = static_cast<uint32_t>((slot + slen - 1) / 8);
        tmpl_skip_ = tmpl_vlo_;           // rodadas 0..vlo-1 usam W constante
    }

    // Midstate: roda as `tmpl_skip_` primeiras rodadas uma unica vez.
    uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (uint32_t t = 0; t < tmpl_skip_; ++t) RND_S(K512[t], tmpl_w_[t]);
    tmpl_mid_[0] = a; tmpl_mid_[1] = b; tmpl_mid_[2] = c; tmpl_mid_[3] = d;
    tmpl_mid_[4] = e; tmpl_mid_[5] = f; tmpl_mid_[6] = g; tmpl_mid_[7] = h;
}

void SHA512::preset(const void* prefix, size_t prefix_len, size_t suffix_len) {
    reset();
    update(prefix, prefix_len);
    template_suffix_len_ = suffix_len;

    if (buf_len_ + suffix_len <= 111) {
        template_single_block_ = true;
        const size_t pad_start = buf_len_ + suffix_len;

        // zera o slot do sufixo: torna tmpl_w_ deterministico
        std::memset(buf_ + buf_len_, 0, suffix_len);

        buf_[pad_start] = 0x80;
        if (pad_start + 1 < 112)
            std::memset(buf_ + pad_start + 1, 0, 112 - (pad_start + 1));

        const uint64_t total_bits  = (total_len_ + suffix_len) * 8;
        const uint64_t bit_len_be  = __builtin_bswap64(total_bits);
        std::memset(buf_ + 112, 0, 8);
        std::memcpy(buf_ + 120, &bit_len_be, 8);

        build_template_tables();
    } else {
        template_single_block_ = false;
        tmpl_skip_ = 0;
        tmpl_vlo_  = 16;
        tmpl_vhi_  = 15;
    }
}

void SHA512::complete(const void* suffix, uint8_t out[64]) const {
    complete(suffix, template_suffix_len_, out);
}

void SHA512::complete(const void* suffix, size_t suffix_len, uint8_t out[64]) const {
    if (!template_single_block_ || suffix_len != template_suffix_len_) {
        SHA512 temp = *this;
        temp.update(suffix, suffix_len);
        temp.finalize(out);
        return;
    }

    uint64_t W[16];
    std::memcpy(W, tmpl_w_, sizeof(W));

    if (tmpl_vlo_ <= tmpl_vhi_) {
        const size_t lo   = static_cast<size_t>(tmpl_vlo_) * 8;
        const size_t nreg = (static_cast<size_t>(tmpl_vhi_) - tmpl_vlo_ + 1) * 8;
        alignas(16) uint8_t reg[128];
        std::memcpy(reg + lo, buf_ + lo, nreg);
        std::memcpy(reg + buf_len_, suffix, suffix_len);
        for (uint32_t t = tmpl_vlo_; t <= tmpl_vhi_; ++t)
            W[t] = load_be64(reg + t * 8);
    }

    uint64_t a = tmpl_mid_[0], b = tmpl_mid_[1], c = tmpl_mid_[2], d = tmpl_mid_[3];
    uint64_t e = tmpl_mid_[4], f = tmpl_mid_[5], g = tmpl_mid_[6], h = tmpl_mid_[7];

    for (uint32_t t = tmpl_skip_; t < 16; ++t) RND_S(K512[t], W[t]);
    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i)
            W[i] += SSig0(W[(i + 1) & 15]) + W[(i + 9) & 15] + SSig1(W[(i + 14) & 15]);
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) RND_S(K512[r * 16 + i], W[i]);
    }

    const uint64_t fin[8] = { h_[0] + a, h_[1] + b, h_[2] + c, h_[3] + d,
                              h_[4] + e, h_[5] + f, h_[6] + g, h_[7] + h };
    for (int i = 0; i < 8; ++i) {
        uint64_t v = __builtin_bswap64(fin[i]);
        std::memcpy(out + i * 8, &v, 8);
    }
}

// =========================================================================
// BATCH
// =========================================================================

void SHA512::complete_batch_scalar(const void* suffixes, size_t stride,
                                   uint8_t* out, size_t count) const {
    const auto* base = static_cast<const uint8_t*>(suffixes);
    for (size_t i = 0; i < count; ++i)
        complete(base + i * stride, out + i * 64);
}

#ifdef SHA512_X86

// ------------------------------------------------------------------ SSE4.1
[[gnu::target("sse4.1,ssse3")]]
void SHA512::complete_batch_sse(const void* suffixes, size_t stride,
                                uint8_t* out, size_t count) const {
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    const __m128i k_ror8_128 = _mm_setr_epi8(1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8);

    const size_t   slot = buf_len_;
    const size_t   slen = template_suffix_len_;
    const uint32_t vlo  = tmpl_vlo_, vhi = tmpl_vhi_, skip = tmpl_skip_;
    const size_t   rlo  = static_cast<size_t>(vlo) * 8;
    const size_t   rlen = (static_cast<size_t>(vhi) - vlo + 1) * 8;
    const auto*    src  = static_cast<const uint8_t*>(suffixes);

    alignas(16) uint8_t vb[2][128];
    for (int l = 0; l < 2; ++l) std::memcpy(vb[l] + rlo, buf_ + rlo, rlen);

    // Palavras constantes do template: broadcast uma unica vez.
    // Wc e' o molde; W e' destruido pelo expand a cada bloco.
    __m128i Wc[16], W[16];
    for (uint32_t t = 0; t < 16; ++t) Wc[t] = _mm_set1_epi64x((long long)tmpl_w_[t]);

    for (size_t base = 0; base < count; base += 2) {
        const size_t lanes = (count - base < 2) ? (count - base) : 2;
        for (size_t l = 0; l < lanes; ++l)
            std::memcpy(vb[l] + slot, src + (base + l) * stride, slen);
        for (size_t l = lanes; l < 2; ++l)
            std::memcpy(vb[l] + slot, src + (base + lanes - 1) * stride, slen);

        #pragma GCC unroll 16
        for (int t = 0; t < 16; ++t) W[t] = Wc[t];
        for (uint32_t t = vlo; t <= vhi; ++t)
            W[t] = _mm_set_epi64x((long long)load_be64(vb[1] + t * 8),
                                  (long long)load_be64(vb[0] + t * 8));

        __m128i a = _mm_set1_epi64x((long long)tmpl_mid_[0]);
        __m128i b = _mm_set1_epi64x((long long)tmpl_mid_[1]);
        __m128i c = _mm_set1_epi64x((long long)tmpl_mid_[2]);
        __m128i d = _mm_set1_epi64x((long long)tmpl_mid_[3]);
        __m128i e = _mm_set1_epi64x((long long)tmpl_mid_[4]);
        __m128i f = _mm_set1_epi64x((long long)tmpl_mid_[5]);
        __m128i g = _mm_set1_epi64x((long long)tmpl_mid_[6]);
        __m128i h = _mm_set1_epi64x((long long)tmpl_mid_[7]);

        for (uint32_t t = skip; t < 16; ++t) RND_SSE(t, W[t]);
        for (int r = 1; r < 5; ++r) {
            EXPAND_SSE(W);
            #pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) RND_SSE(r * 16 + i, W[i]);
        }

        alignas(16) uint64_t st[8][2];
        _mm_store_si128((__m128i*)st[0], _mm_add_epi64(a, _mm_set1_epi64x((long long)h_[0])));
        _mm_store_si128((__m128i*)st[1], _mm_add_epi64(b, _mm_set1_epi64x((long long)h_[1])));
        _mm_store_si128((__m128i*)st[2], _mm_add_epi64(c, _mm_set1_epi64x((long long)h_[2])));
        _mm_store_si128((__m128i*)st[3], _mm_add_epi64(d, _mm_set1_epi64x((long long)h_[3])));
        _mm_store_si128((__m128i*)st[4], _mm_add_epi64(e, _mm_set1_epi64x((long long)h_[4])));
        _mm_store_si128((__m128i*)st[5], _mm_add_epi64(f, _mm_set1_epi64x((long long)h_[5])));
        _mm_store_si128((__m128i*)st[6], _mm_add_epi64(g, _mm_set1_epi64x((long long)h_[6])));
        _mm_store_si128((__m128i*)st[7], _mm_add_epi64(h, _mm_set1_epi64x((long long)h_[7])));

        for (size_t l = 0; l < lanes; ++l)
            for (int i = 0; i < 8; ++i) {
                uint64_t v = __builtin_bswap64(st[i][l]);
                std::memcpy(out + (base + l) * 64 + i * 8, &v, 8);
            }
    }
}

// -------------------------------------------------------------------- AVX2
[[gnu::target("avx2")]]
void SHA512::complete_batch_avx2(const void* suffixes, size_t stride,
                                 uint8_t* out, size_t count) const {
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    const __m256i k_ror8_256 = _mm256_setr_epi8(1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8,
                                                1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8);
    const __m256i k_bswap    = _mm256_setr_epi8(7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8,
                                                7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8);

    const size_t   slot = buf_len_;
    const size_t   slen = template_suffix_len_;
    const uint32_t vlo  = tmpl_vlo_, vhi = tmpl_vhi_, skip = tmpl_skip_;
    const size_t   rlo  = static_cast<size_t>(vlo) * 8;
    const size_t   rlen = (static_cast<size_t>(vhi) - vlo + 1) * 8;
    const auto*    src  = static_cast<const uint8_t*>(suffixes);

    alignas(32) uint8_t vb[4][128];
    for (int l = 0; l < 4; ++l) std::memcpy(vb[l] + rlo, buf_ + rlo, rlen);

    // Palavras constantes do template: broadcast uma unica vez.
    // Wc e' o molde; W e' destruido pelo expand a cada bloco.
    __m256i Wc[16], W[16];
    for (uint32_t t = 0; t < 16; ++t) Wc[t] = _mm256_set1_epi64x((long long)tmpl_w_[t]);

    const __m256i m0 = _mm256_set1_epi64x((long long)tmpl_mid_[0]);
    const __m256i m1 = _mm256_set1_epi64x((long long)tmpl_mid_[1]);
    const __m256i m2 = _mm256_set1_epi64x((long long)tmpl_mid_[2]);
    const __m256i m3 = _mm256_set1_epi64x((long long)tmpl_mid_[3]);
    const __m256i m4 = _mm256_set1_epi64x((long long)tmpl_mid_[4]);
    const __m256i m5 = _mm256_set1_epi64x((long long)tmpl_mid_[5]);
    const __m256i m6 = _mm256_set1_epi64x((long long)tmpl_mid_[6]);
    const __m256i m7 = _mm256_set1_epi64x((long long)tmpl_mid_[7]);

    for (size_t base = 0; base < count; base += 4) {
        const size_t lanes = (count - base < 4) ? (count - base) : 4;
        for (size_t l = 0; l < lanes; ++l)
            std::memcpy(vb[l] + slot, src + (base + l) * stride, slen);
        for (size_t l = lanes; l < 4; ++l)
            std::memcpy(vb[l] + slot, src + (base + lanes - 1) * stride, slen);

        #pragma GCC unroll 16
        for (int t = 0; t < 16; ++t) W[t] = Wc[t];
        // So as palavras que o sufixo toca sao reconstruidas (tipicamente 1-2).
        for (uint32_t t = vlo; t <= vhi; ++t)
            W[t] = _mm256_set_epi64x((long long)load_be64(vb[3] + t * 8),
                                     (long long)load_be64(vb[2] + t * 8),
                                     (long long)load_be64(vb[1] + t * 8),
                                     (long long)load_be64(vb[0] + t * 8));

        __m256i a = m0, b = m1, c = m2, d = m3, e = m4, f = m5, g = m6, h = m7;

        for (uint32_t t = skip; t < 16; ++t) RND_AVX2(t, W[t]);
        for (int r = 1; r < 5; ++r) {
            EXPAND_AVX2(W);
            #pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) RND_AVX2(r * 16 + i, W[i]);
        }

        alignas(32) __m256i st[8];
        st[0] = _mm256_add_epi64(a, _mm256_set1_epi64x((long long)h_[0]));
        st[1] = _mm256_add_epi64(b, _mm256_set1_epi64x((long long)h_[1]));
        st[2] = _mm256_add_epi64(c, _mm256_set1_epi64x((long long)h_[2]));
        st[3] = _mm256_add_epi64(d, _mm256_set1_epi64x((long long)h_[3]));
        st[4] = _mm256_add_epi64(e, _mm256_set1_epi64x((long long)h_[4]));
        st[5] = _mm256_add_epi64(f, _mm256_set1_epi64x((long long)h_[5]));
        st[6] = _mm256_add_epi64(g, _mm256_set1_epi64x((long long)h_[6]));
        st[7] = _mm256_add_epi64(h, _mm256_set1_epi64x((long long)h_[7]));

        transpose4x4_epi64(st);
        transpose4x4_epi64(st + 4);

        for (size_t l = 0; l < lanes; ++l) {
            _mm256_storeu_si256((__m256i*)(out + (base + l) * 64),
                                _mm256_shuffle_epi8(st[l], k_bswap));
            _mm256_storeu_si256((__m256i*)(out + (base + l) * 64 + 32),
                                _mm256_shuffle_epi8(st[l + 4], k_bswap));
        }
    }
}

// ----------------------------------------------------------------- AVX-512
[[gnu::target("avx512f,avx512vl,avx512bw")]]
void SHA512::complete_batch_avx512(const void* suffixes, size_t stride,
                                   uint8_t* out, size_t count) const {
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    const __m512i k_bswap = _mm512_set_epi8(
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7);

    const size_t   slot = buf_len_;
    const size_t   slen = template_suffix_len_;
    const uint32_t vlo  = tmpl_vlo_, vhi = tmpl_vhi_, skip = tmpl_skip_;
    const size_t   rlo  = static_cast<size_t>(vlo) * 8;
    const size_t   rlen = (static_cast<size_t>(vhi) - vlo + 1) * 8;
    const auto*    src  = static_cast<const uint8_t*>(suffixes);

    alignas(64) uint8_t vb[8][128];
    for (int l = 0; l < 8; ++l) std::memcpy(vb[l] + rlo, buf_ + rlo, rlen);

    __m512i Wc[16], W[16];
    for (uint32_t t = 0; t < 16; ++t) Wc[t] = _mm512_set1_epi64((long long)tmpl_w_[t]);

    for (size_t base = 0; base < count; base += 8) {
        const size_t lanes = (count - base < 8) ? (count - base) : 8;
        for (size_t l = 0; l < lanes; ++l)
            std::memcpy(vb[l] + slot, src + (base + l) * stride, slen);
        for (size_t l = lanes; l < 8; ++l)
            std::memcpy(vb[l] + slot, src + (base + lanes - 1) * stride, slen);

        #pragma GCC unroll 16
        for (int t = 0; t < 16; ++t) W[t] = Wc[t];
        for (uint32_t t = vlo; t <= vhi; ++t) {
            alignas(64) uint64_t w[8];
            for (int l = 0; l < 8; ++l) w[l] = load_be64(vb[l] + t * 8);
            W[t] = _mm512_load_si512((const __m512i*)w);
        }

        __m512i a = _mm512_set1_epi64((long long)tmpl_mid_[0]);
        __m512i b = _mm512_set1_epi64((long long)tmpl_mid_[1]);
        __m512i c = _mm512_set1_epi64((long long)tmpl_mid_[2]);
        __m512i d = _mm512_set1_epi64((long long)tmpl_mid_[3]);
        __m512i e = _mm512_set1_epi64((long long)tmpl_mid_[4]);
        __m512i f = _mm512_set1_epi64((long long)tmpl_mid_[5]);
        __m512i g = _mm512_set1_epi64((long long)tmpl_mid_[6]);
        __m512i h = _mm512_set1_epi64((long long)tmpl_mid_[7]);

        for (uint32_t t = skip; t < 16; ++t) RND_AVX512(t, W[t]);
        for (int r = 1; r < 5; ++r) {
            EXPAND_AVX512(W);
            #pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) RND_AVX512(r * 16 + i, W[i]);
        }

        alignas(64) __m512i st[8];
        st[0] = _mm512_add_epi64(a, _mm512_set1_epi64((long long)h_[0]));
        st[1] = _mm512_add_epi64(b, _mm512_set1_epi64((long long)h_[1]));
        st[2] = _mm512_add_epi64(c, _mm512_set1_epi64((long long)h_[2]));
        st[3] = _mm512_add_epi64(d, _mm512_set1_epi64((long long)h_[3]));
        st[4] = _mm512_add_epi64(e, _mm512_set1_epi64((long long)h_[4]));
        st[5] = _mm512_add_epi64(f, _mm512_set1_epi64((long long)h_[5]));
        st[6] = _mm512_add_epi64(g, _mm512_set1_epi64((long long)h_[6]));
        st[7] = _mm512_add_epi64(h, _mm512_set1_epi64((long long)h_[7]));

        transpose8x8_epi64(st);

        for (size_t l = 0; l < lanes; ++l)
            _mm512_storeu_si512((__m512i*)(out + (base + l) * 64), _mm512_shuffle_epi8(st[l], k_bswap));
    }
}

#else  // !SHA512_X86
    void SHA512::complete_batch_sse   (const void* s, size_t st, uint8_t* o, size_t c) const { complete_batch_scalar(s, st, o, c); }
    void SHA512::complete_batch_avx2  (const void* s, size_t st, uint8_t* o, size_t c) const { complete_batch_scalar(s, st, o, c); }
    void SHA512::complete_batch_avx512(const void* s, size_t st, uint8_t* o, size_t c) const { complete_batch_scalar(s, st, o, c); }
#endif // SHA512_X86

// =========================================================================
// DESPACHO
// =========================================================================

unsigned SHA512::simd_lanes() noexcept {
    switch (g_isa) {
        case Isa::Avx512: return 8;
        case Isa::Avx2:   return 4;
        case Isa::Sse41:  return 2;
        default:          return 1;
    }
}

const char* SHA512::simd_name() noexcept {
    switch (g_isa) {
        case Isa::Avx512: return "avx512";
        case Isa::Avx2:   return "avx2";
        case Isa::Sse41:  return "sse4.1";
        default:          return "scalar";
    }
}

void SHA512::complete_batch(const void* suffixes, size_t stride, uint8_t* out, size_t count) const {
    if (count == 0) return;
    if (!template_single_block_ || template_suffix_len_ == 0) {
        complete_batch_scalar(suffixes, stride, out, count);
        return;
    }

    switch (g_isa) {
        case Isa::Avx512: complete_batch_avx512(suffixes, stride, out, count); return;
        case Isa::Avx2:   complete_batch_avx2  (suffixes, stride, out, count); return;
        case Isa::Sse41:  complete_batch_sse   (suffixes, stride, out, count); return;
        default:          complete_batch_scalar(suffixes, stride, out, count); return;
    }
}

void SHA512::complete_batch_range(const void* suffixes, size_t stride,
                                  uint8_t* out, size_t first, size_t n) const {
    if (n == 0) return;
    const auto* src = static_cast<const uint8_t*>(suffixes) + first * stride;
    complete_batch(src, stride, out + first * 64, n);
}

// Fatia [first, first+n) do worker `id`, alinhada ao numero de lanes.
static void slice_of(size_t count, size_t lanes, unsigned nt, unsigned id,
                     size_t& first, size_t& n) {
    const size_t chunks = (count + lanes - 1) / lanes;
    const size_t base   = chunks / nt;
    const size_t rem    = chunks % nt;
    const size_t c0     = base * id + (id < rem ? id : rem);
    const size_t cn     = base + (id < rem ? 1 : 0);
    first = std::min(c0 * lanes, count);
    const size_t end = std::min((c0 + cn) * lanes, count);
    n = end - first;
}

void SHA512::complete_batch_mt(const void* suffixes, size_t stride,
                               uint8_t* out, size_t count, unsigned threads) const {
    if (count == 0) return;

    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 1;
    }

    const size_t lanes = simd_lanes();
    const size_t min_per_thread = lanes * 256;   // abaixo disso spawn domina

    if (threads <= 1 || count < min_per_thread * 2) {
        complete_batch(suffixes, stride, out, count);
        return;
    }

    unsigned nt = static_cast<unsigned>(
        std::min<size_t>(threads, (count + min_per_thread - 1) / min_per_thread));

    std::vector<std::thread> pool;
    pool.reserve(nt - 1);
    for (unsigned id = 1; id < nt; ++id) {
        size_t first, n;
        slice_of(count, lanes, nt, id, first, n);
        if (n == 0) continue;
        pool.emplace_back([this, suffixes, stride, out, first, n] {
            complete_batch_range(suffixes, stride, out, first, n);
        });
    }
    {
        size_t first, n;
        slice_of(count, lanes, nt, 0, first, n);
        complete_batch_range(suffixes, stride, out, first, n);
    }
    for (auto& th : pool) th.join();
}

// =========================================================================
// SHA512Pool
// =========================================================================

SHA512Pool::SHA512Pool(unsigned threads) {
    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 1;
    }
    nthreads_ = threads;
    workers_.reserve(nthreads_ - 1);
    for (unsigned id = 1; id < nthreads_; ++id)
        workers_.emplace_back([this, id] { worker(id); });
}

SHA512Pool::~SHA512Pool() {
    {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = true;
    }
    cv_start_.notify_all();
    for (auto& th : workers_) if (th.joinable()) th.join();
}

void SHA512Pool::worker(unsigned id) {
    uint64_t seen = 0;
    for (;;) {
        Job j;
        {
            std::unique_lock<std::mutex> lk(m_);
            cv_start_.wait(lk, [&] { return stop_ || gen_ != seen; });
            if (stop_) return;
            seen = gen_;
            j = job_;
        }

        size_t first, n;
        slice_of(j.count, SHA512::simd_lanes(), nthreads_, id, first, n);
        if (n) j.ctx->complete_batch_range(j.suffixes, j.stride, j.out, first, n);

        {
            std::lock_guard<std::mutex> lk(m_);
            if (--pending_ == 0) cv_done_.notify_one();
        }
    }
}

void SHA512Pool::complete_batch(const SHA512& ctx, const void* suffixes, size_t stride,
                                uint8_t* out, size_t count) {
    if (count == 0) return;

    const size_t lanes = SHA512::simd_lanes();
    if (nthreads_ <= 1 || count < lanes * 512) {
        ctx.complete_batch(suffixes, stride, out, count);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(m_);
        job_     = Job{ &ctx, suffixes, stride, out, count };
        pending_ = nthreads_ - 1;
        ++gen_;
    }
    cv_start_.notify_all();

    size_t first, n;
    slice_of(count, lanes, nthreads_, 0, first, n);
    if (n) ctx.complete_batch_range(suffixes, stride, out, first, n);

    {
        std::unique_lock<std::mutex> lk(m_);
        cv_done_.wait(lk, [&] { return pending_ == 0; });
    }
}

} // namespace crypto
