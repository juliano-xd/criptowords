#pragma once
#include "sha512.hpp"
#include <bit>
#include <cstdint>
#include <cstring>
#include <immintrin.h>

namespace pbkdf2_simd_detail {

// ============================================================================
// Constantes (uma única cópia para todas as ISAs)
// ============================================================================
alignas(64) inline constexpr uint64_t K512[80] = {
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

inline constexpr uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

// ============================================================================
// Helpers escalares (portáveis, endian-safe, sem UB)
// ============================================================================
[[gnu::always_inline]] inline uint64_t bswap64(uint64_t x) noexcept {
    if constexpr (std::endian::native == std::endian::little)
        return __builtin_bswap64(x);
    else
        return x;
}

[[gnu::always_inline]] inline uint64_t load_be64(const uint8_t* p) noexcept {
    uint64_t v; std::memcpy(&v, p, sizeof(v));
    if constexpr (std::endian::native == std::endian::little)
        v = __builtin_bswap64(v);
    return v;
}

// Lê a chave (normalizando p/ 128 bytes) e já aplica XOR com o pad.
// Saída: W[i] = big-endian word da chave XORed com `pad` repetido.
inline void prepare_key_W(const void* pass, size_t len, uint8_t pad,
                          uint64_t W[16]) noexcept
{
    alignas(16) uint8_t K[128] = {};
    if (len > 128)            crypto::SHA512::hash(pass, len, K);
    else if (len > 0)         std::memcpy(K, pass, len);

    const uint64_t pad_word = 0x0101010101010101ULL * pad;
    for (int i = 0; i < 16; ++i) {
        uint64_t v; std::memcpy(&v, K + i * 8, 8);
        // Aritmética XOR feita no valor big-endian diretamente.
        if constexpr (std::endian::native == std::endian::little)
            v = __builtin_bswap64(v);
        W[i] = v ^ pad_word;
    }
}

// Preenche W_ipad/W_opad para LANES chaves de uma vez.
template <size_t LANES>
inline void prepare_pads(const void* const* passes, const size_t* lens,
                         uint64_t W_ipad[16][LANES],
                         uint64_t W_opad[16][LANES]) noexcept
{
    for (size_t l = 0; l < LANES; ++l) {
        uint64_t tmp[16];
        prepare_key_W(passes[l], lens[l], 0x36, tmp);
        for (int w = 0; w < 16; ++w) W_ipad[w][l] = tmp[w];
        prepare_key_W(passes[l], lens[l], 0x5c, tmp);
        for (int w = 0; w < 16; ++w) W_opad[w][l] = tmp[w];
    }
}

// W[16] do bloco "salt || 0x00000001 || 0x80 || ... || bitlen".
// Requer salt_len <= 107 (senão não cabe em um bloco).
inline void prepare_salt_W(const uint8_t* salt, size_t salt_len,
                           uint64_t W[16]) noexcept
{
    alignas(16) uint8_t buf[128] = {};
    if (salt_len) std::memcpy(buf, salt, salt_len);
    buf[salt_len + 3] = 1;      // contador BE = 1
    buf[salt_len + 4] = 0x80;   // padding SHA-512
    for (int i = 0; i < 15; ++i) W[i] = load_be64(buf + i * 8);
    W[15] = static_cast<uint64_t>(128 + salt_len + 4) * 8;
}

// W[80] já somado com K512 (para o "fast forward" do bloco de salt).
inline void precompute_kw_salt_from_W(const uint64_t salt_W[16],
                                      uint64_t kw_salt[80]) noexcept
{
    uint64_t W[80];
    for (int i = 0; i < 16; ++i) W[i] = salt_W[i];
    for (int i = 16; i < 80; ++i) {
        const uint64_t s0 = std::rotr(W[i-15], 1) ^ std::rotr(W[i-15], 8) ^ (W[i-15] >> 7);
        const uint64_t s1 = std::rotr(W[i-2], 19) ^ std::rotr(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    for (int i = 0; i < 80; ++i) kw_salt[i] = K512[i] + W[i];
}

// Serialização BE de LANES digests (word-major) em LANES buffers.
template <size_t LANES>
[[gnu::always_inline]]
inline void store_digests_be(const uint64_t digest[8][LANES],
                             uint8_t* const* out) noexcept
{
    for (int i = 0; i < 8; ++i)
        for (size_t l = 0; l < LANES; ++l) {
            const uint64_t b = bswap64(digest[i][l]);
            std::memcpy(out[l] + i * 8, &b, 8);
        }
}

}  // namespace pbkdf2_simd_detail

// ============================================================================
// Broadcasters de K / IV por ISA
// ============================================================================
[[gnu::target("sse4.1"), gnu::always_inline]]
static inline const __m128i* get_k512_sse() {
    alignas(16) static const __m128i K[80] = {
#define K_SSE(i) _mm_set1_epi64x((long long)pbkdf2_simd_detail::K512[i])
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
    alignas(16) static const __m128i V[8] = {
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[0]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[1]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[2]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[3]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[4]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[5]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[6]),
        _mm_set1_epi64x((long long)pbkdf2_simd_detail::IV[7])
    };
    return V;
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline const __m256i* get_k512_avx2() {
    alignas(32) static const __m256i K[80] = {
#define K_AVX2(i) _mm256_set1_epi64x((long long)pbkdf2_simd_detail::K512[i])
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
    alignas(32) static const __m256i V[8] = {
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[0]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[1]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[2]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[3]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[4]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[5]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[6]),
        _mm256_set1_epi64x((long long)pbkdf2_simd_detail::IV[7])
    };
    return V;
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline const __m512i* get_k512_avx512() {
    alignas(64) static const __m512i K[80] = {
#define K_AVX512(i) _mm512_set1_epi64((long long)pbkdf2_simd_detail::K512[i])
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
    alignas(64) static const __m512i V[8] = {
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[0]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[1]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[2]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[3]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[4]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[5]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[6]),
        _mm512_set1_epi64((long long)pbkdf2_simd_detail::IV[7])
    };
    return V;
}

// Máscaras de byte-shuffle para o ROR8 dentro do small-sigma0.
alignas(16) static constexpr uint8_t SHUF_ROR8_SSE[16] = {
    1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8
};
alignas(32) static constexpr uint8_t SHUF_ROR8_AVX2[32] = {
    1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8,
    1,2,3,4,5,6,7,0, 9,10,11,12,13,14,15,8
};

// ============================================================================
// SSE 4.1
// ============================================================================
#define ROR128_64(x, n) _mm_xor_si128(_mm_srli_epi64(x, n), _mm_slli_epi64(x, 64 - (n)))
#define CH_SSE(x, y, z) _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z)))
#define MAJ_SSE(x, y, z) _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)))
#define S0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 28), ROR128_64(x, 34)), ROR128_64(x, 39))
#define S1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 14), ROR128_64(x, 18)), ROR128_64(x, 41))
#define s0_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 1), _mm_shuffle_epi8(x, _mm_load_si128((const __m128i*)SHUF_ROR8_SSE))), _mm_srli_epi64(x, 7))
#define s1_SSE(x) _mm_xor_si128(_mm_xor_si128(ROR128_64(x, 19), ROR128_64(x, 61)), _mm_srli_epi64(x, 6))

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_block64_sse(const __m128i iv[8], __m128i W[16], __m128i out[8]) {
    __m128i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    const __m128i* k_tbl = get_k512_sse();
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m128i kw      = _mm_add_epi64(k_tbl[r*16+i], W[i]);
            __m128i h_kw    = _mm_add_epi64(h, kw);
            __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));
            __m128i T1      = _mm_add_epi64(h_kw, e_terms);
            __m128i T2    = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));
            h = g; g = f; f = e;
            e = _mm_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm_add_epi64(W[i], _mm_add_epi64(
                       _mm_add_epi64(s0_SSE(W[(i+1)&15]), W[(i+9)&15]),
                       s1_SSE(W[(i+14)&15])));
            }
        }
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_padded_block64_sse(const __m128i iv[8], __m128i W[16], __m128i out[8]) {
    alignas(16) static const __m128i C_S1_W15  = _mm_set1_epi64x(0x00c0000000003018ULL);
    alignas(16) static const __m128i C_S0_W8   = _mm_set1_epi64x(0x4180000000000000ULL);
    alignas(16) static const __m128i C_S0_W15  = _mm_set1_epi64x(0x000000000000030aULL);
    alignas(16) static const __m128i C_W8      = _mm_set1_epi64x(0x8000000000000000ULL);
    alignas(16) static const __m128i C_W15     = _mm_set1_epi64x(0x0000000000000600ULL);
    alignas(16) static const __m128i K_FUSED_8  = _mm_set1_epi64x(0xd807aa98a3030242ULL + 0x8000000000000000ULL);
    alignas(16) static const __m128i K_FUSED_15 = _mm_set1_epi64x(0xc19bf174cf692694ULL + 0x0000000000000600ULL);

    __m128i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    const __m128i* k_tbl = get_k512_sse();

    #define STEP_SSE(k_term, w_val) do { \
        __m128i kw      = _mm_add_epi64((k_term), (w_val)); \
        __m128i h_kw    = _mm_add_epi64(h, kw); \
        __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g)); \
        __m128i T1      = _mm_add_epi64(h_kw, e_terms); \
        __m128i T2      = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c)); \
        h = g; g = f; f = e; \
        e = _mm_add_epi64(d, T1); \
        d = c; c = b; b = a; \
        a = _mm_add_epi64(T1, T2); \
    } while(0)

    #define STEP_FUSED_SSE(k_fused) do { \
        __m128i h_kw    = _mm_add_epi64(h, (k_fused)); \
        __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g)); \
        __m128i T1      = _mm_add_epi64(h_kw, e_terms); \
        __m128i T2      = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c)); \
        h = g; g = f; f = e; \
        e = _mm_add_epi64(d, T1); \
        d = c; c = b; b = a; \
        a = _mm_add_epi64(T1, T2); \
    } while(0)

    STEP_SSE(k_tbl[0], W[0]);  W[0] = _mm_add_epi64(W[0], s0_SSE(W[1]));
    STEP_SSE(k_tbl[1], W[1]);  W[1] = _mm_add_epi64(W[1], _mm_add_epi64(s0_SSE(W[2]), C_S1_W15));
    STEP_SSE(k_tbl[2], W[2]);  W[2] = _mm_add_epi64(W[2], _mm_add_epi64(s0_SSE(W[3]), s1_SSE(W[0])));
    STEP_SSE(k_tbl[3], W[3]);  W[3] = _mm_add_epi64(W[3], _mm_add_epi64(s0_SSE(W[4]), s1_SSE(W[1])));
    STEP_SSE(k_tbl[4], W[4]);  W[4] = _mm_add_epi64(W[4], _mm_add_epi64(s0_SSE(W[5]), s1_SSE(W[2])));
    STEP_SSE(k_tbl[5], W[5]);  W[5] = _mm_add_epi64(W[5], _mm_add_epi64(s0_SSE(W[6]), s1_SSE(W[3])));
    STEP_SSE(k_tbl[6], W[6]);  W[6] = _mm_add_epi64(W[6], _mm_add_epi64(_mm_add_epi64(s0_SSE(W[7]), C_W15), s1_SSE(W[4])));
    STEP_SSE(k_tbl[7], W[7]);  W[7] = _mm_add_epi64(W[7], _mm_add_epi64(_mm_add_epi64(C_S0_W8, W[0]), s1_SSE(W[5])));

    STEP_FUSED_SSE(K_FUSED_8);  W[8]  = _mm_add_epi64(C_W8, _mm_add_epi64(W[1], s1_SSE(W[6])));
    STEP_FUSED_SSE(k_tbl[9]);   W[9]  = _mm_add_epi64(W[2], s1_SSE(W[7]));
    STEP_FUSED_SSE(k_tbl[10]);  W[10] = _mm_add_epi64(W[3], s1_SSE(W[8]));
    STEP_FUSED_SSE(k_tbl[11]);  W[11] = _mm_add_epi64(W[4], s1_SSE(W[9]));
    STEP_FUSED_SSE(k_tbl[12]);  W[12] = _mm_add_epi64(W[5], s1_SSE(W[10]));
    STEP_FUSED_SSE(k_tbl[13]);  W[13] = _mm_add_epi64(W[6], s1_SSE(W[11]));
    STEP_FUSED_SSE(k_tbl[14]);  W[14] = _mm_add_epi64(C_S0_W15, _mm_add_epi64(W[7], s1_SSE(W[12])));
    STEP_FUSED_SSE(K_FUSED_15); W[15] = _mm_add_epi64(_mm_add_epi64(C_W15, s0_SSE(W[0])), _mm_add_epi64(W[8], s1_SSE(W[13])));

    #undef STEP_SSE
    #undef STEP_FUSED_SSE

    #pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m128i kw      = _mm_add_epi64(k_tbl[r*16+i], W[i]);
            __m128i h_kw    = _mm_add_epi64(h, kw);
            __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));
            __m128i T1      = _mm_add_epi64(h_kw, e_terms);
            __m128i T2    = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));
            h = g; g = f; f = e;
            e = _mm_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm_add_epi64(W[i], _mm_add_epi64(
                       _mm_add_epi64(s0_SSE(W[(i+1)&15]), W[(i+9)&15]),
                       s1_SSE(W[(i+14)&15])));
            }
        }
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void pbkdf2_2lane_fused_stream(
    const __m128i ipad_iv[8], const __m128i opad_iv[8],
    const __m128i initial_digest[8], __m128i T[8], uint32_t iterations)
{
    __m128i W[16];
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    for (uint32_t it = 1; it < iterations; ++it) {
        sha512_padded_block64_sse(ipad_iv, W, W);
        sha512_padded_block64_sse(opad_iv, W, W);
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) T[i] = _mm_xor_si128(T[i], W[i]);
    }
}

[[gnu::target("sse4.1"), gnu::always_inline]]
static inline void sha512_salt_fastforward_sse(const __m128i iv[8],
                                               const uint64_t kw_salt[80],
                                               __m128i out[8])
{
    __m128i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    #pragma GCC unroll 80
    for (int i = 0; i < 80; ++i) {
        __m128i kw      = _mm_set1_epi64x((long long)kw_salt[i]);
        __m128i h_kw    = _mm_add_epi64(h, kw);
        __m128i e_terms = _mm_add_epi64(S1_SSE(e), CH_SSE(e, f, g));
        __m128i T1      = _mm_add_epi64(h_kw, e_terms);
        __m128i T2      = _mm_add_epi64(S0_SSE(a), MAJ_SSE(a, b, c));
        h = g; g = f; f = e;
        e = _mm_add_epi64(d, T1);
        d = c; c = b; b = a;
        a = _mm_add_epi64(T1, T2);
    }
    out[0] = _mm_add_epi64(iv[0], a); out[1] = _mm_add_epi64(iv[1], b);
    out[2] = _mm_add_epi64(iv[2], c); out[3] = _mm_add_epi64(iv[3], d);
    out[4] = _mm_add_epi64(iv[4], e); out[5] = _mm_add_epi64(iv[5], f);
    out[6] = _mm_add_epi64(iv[6], g); out[7] = _mm_add_epi64(iv[7], h);
}

[[gnu::target("sse4.1")]]
inline void pbkdf2_hmac_sha512_4way_sse(
    const char* p1, size_t l1, const char* p2, size_t l2,
    const char* p3, size_t l3, const char* p4, size_t l4,
    const uint8_t* salt, size_t salt_len, uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64],
    const uint64_t* precomputed_salt_blk64 = nullptr,
    const uint64_t* precomputed_kw_salt = nullptr)
{
    using namespace pbkdf2_simd_detail;

    // --- 1. Preparação dos pads por lane ---
    const void*  passes[4] = { p1, p2, p3, p4 };
    const size_t lens  [4] = { l1, l2, l3, l4 };
    uint64_t ipad_all[16][4], opad_all[16][4];
    prepare_pads<4>(passes, lens, ipad_all, opad_all);

    alignas(16) uint64_t ipad_lo[16][2], ipad_hi[16][2];
    alignas(16) uint64_t opad_lo[16][2], opad_hi[16][2];
    for (int w = 0; w < 16; ++w) {
        ipad_lo[w][0]=ipad_all[w][0]; ipad_lo[w][1]=ipad_all[w][1];
        ipad_hi[w][0]=ipad_all[w][2]; ipad_hi[w][1]=ipad_all[w][3];
        opad_lo[w][0]=opad_all[w][0]; opad_lo[w][1]=opad_all[w][1];
        opad_hi[w][0]=opad_all[w][2]; opad_hi[w][1]=opad_all[w][3];
    }

    // --- 2. Estados pós ipad/opad ---
    __m128i ipad_iv_lo[8], ipad_iv_hi[8], opad_iv_lo[8], opad_iv_hi[8];
    __m128i W[16];
    for (int i=0;i<16;++i) W[i] = _mm_loadu_si128((const __m128i*)ipad_lo[i]);
    sha512_block64_sse(get_iv_sse(), W, ipad_iv_lo);
    for (int i=0;i<16;++i) W[i] = _mm_loadu_si128((const __m128i*)ipad_hi[i]);
    sha512_block64_sse(get_iv_sse(), W, ipad_iv_hi);
    for (int i=0;i<16;++i) W[i] = _mm_loadu_si128((const __m128i*)opad_lo[i]);
    sha512_block64_sse(get_iv_sse(), W, opad_iv_lo);
    for (int i=0;i<16;++i) W[i] = _mm_loadu_si128((const __m128i*)opad_hi[i]);
    sha512_block64_sse(get_iv_sse(), W, opad_iv_hi);

    // --- 3. Bloco do salt (U_1) ---
    __m128i s_lo[8], s_hi[8];
    if (precomputed_kw_salt) {
        sha512_salt_fastforward_sse(ipad_iv_lo, precomputed_kw_salt, s_lo);
        sha512_salt_fastforward_sse(ipad_iv_hi, precomputed_kw_salt, s_hi);
    } else {
        uint64_t salt_W[16];
        if (precomputed_salt_blk64) {
            for (int i=0;i<16;++i) salt_W[i] = precomputed_salt_blk64[i];
        } else {
            prepare_salt_W(salt, salt_len, salt_W);
        }
        __m128i Wsalt[16];
        for (int i=0;i<16;++i) Wsalt[i] = _mm_set1_epi64x((long long)salt_W[i]);
        for (int i=0;i<16;++i) W[i] = Wsalt[i];
        sha512_block64_sse(ipad_iv_lo, W, s_lo);
        for (int i=0;i<16;++i) W[i] = Wsalt[i];
        sha512_block64_sse(ipad_iv_hi, W, s_hi);
    }

    // --- 4. Outer hash de U_1 ---
    __m128i T_lo[8], T_hi[8];
    for (int i=0;i<8;++i) W[i] = s_lo[i];
    for (int i=8;i<16;++i) W[i] = _mm_setzero_si128();
    sha512_padded_block64_sse(opad_iv_lo, W, T_lo);
    for (int i=0;i<8;++i) W[i] = s_hi[i];
    for (int i=8;i<16;++i) W[i] = _mm_setzero_si128();
    sha512_padded_block64_sse(opad_iv_hi, W, T_hi);

    // --- 5. Iterações 2..N ---
    pbkdf2_2lane_fused_stream(ipad_iv_lo, opad_iv_lo, T_lo, T_lo, iterations);
    pbkdf2_2lane_fused_stream(ipad_iv_hi, opad_iv_hi, T_hi, T_hi, iterations);

    // --- 6. Serialização ---
    alignas(16) uint64_t lo[8][2], hi[8][2];
    for (int i=0;i<8;++i) {
        _mm_storeu_si128((__m128i*)lo[i], T_lo[i]);
        _mm_storeu_si128((__m128i*)hi[i], T_hi[i]);
    }
    uint64_t combined[8][4];
    for (int i=0;i<8;++i) {
        combined[i][0]=lo[i][0]; combined[i][1]=lo[i][1];
        combined[i][2]=hi[i][0]; combined[i][3]=hi[i][1];
    }
    uint8_t* outs[4] = { out1, out2, out3, out4 };
    store_digests_be<4>(combined, outs);
}

// ============================================================================
// AVX2
// ============================================================================
#define ROR256_64(x, n) _mm256_or_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))
#define CH_AVX2(x, y, z) _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
#define MAJ_AVX2(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)))
#define S0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 28), ROR256_64(x, 34)), ROR256_64(x, 39))
#define S1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 14), ROR256_64(x, 18)), ROR256_64(x, 41))
#define s0_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 1), _mm256_shuffle_epi8(x, _mm256_load_si256((const __m256i*)SHUF_ROR8_AVX2))), _mm256_srli_epi64(x, 7))
#define s1_AVX2(x) _mm256_xor_si256(_mm256_xor_si256(ROR256_64(x, 19), ROR256_64(x, 61)), _mm256_srli_epi64(x, 6))

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_block64_avx2(const __m256i iv[8], __m256i W[16], __m256i out[8]) {
    __m256i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    const __m256i* k_tbl = get_k512_avx2();
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m256i kw      = _mm256_add_epi64(k_tbl[r*16+i], W[i]);
            __m256i h_kw    = _mm256_add_epi64(h, kw);
            __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));
            __m256i T1      = _mm256_add_epi64(h_kw, e_terms);
            __m256i T2    = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));
            h = g; g = f; f = e;
            e = _mm256_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm256_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm256_add_epi64(W[i], _mm256_add_epi64(
                       _mm256_add_epi64(s0_AVX2(W[(i+1)&15]), W[(i+9)&15]),
                       s1_AVX2(W[(i+14)&15])));
            }
        }
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_padded_block64_avx2(const __m256i iv[8], __m256i W[16], __m256i out[8]) {
    alignas(32) static const __m256i C_S1_W15  = _mm256_set1_epi64x(0x00c0000000003018ULL);
    alignas(32) static const __m256i C_S0_W8   = _mm256_set1_epi64x(0x4180000000000000ULL);
    alignas(32) static const __m256i C_S0_W15  = _mm256_set1_epi64x(0x000000000000030aULL);
    alignas(32) static const __m256i C_W8      = _mm256_set1_epi64x(0x8000000000000000ULL);
    alignas(32) static const __m256i C_W15     = _mm256_set1_epi64x(0x0000000000000600ULL);
    alignas(32) static const __m256i K_FUSED_8  = _mm256_set1_epi64x(0xd807aa98a3030242ULL + 0x8000000000000000ULL);
    alignas(32) static const __m256i K_FUSED_15 = _mm256_set1_epi64x(0xc19bf174cf692694ULL + 0x0000000000000600ULL);

    __m256i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    const __m256i* k_tbl = get_k512_avx2();

    #define STEP_AVX2(k_term, w_val) do { \
        __m256i kw      = _mm256_add_epi64((k_term), (w_val)); \
        __m256i h_kw    = _mm256_add_epi64(h, kw); \
        __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g)); \
        __m256i T1      = _mm256_add_epi64(h_kw, e_terms); \
        __m256i T2      = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c)); \
        h = g; g = f; f = e; \
        e = _mm256_add_epi64(d, T1); \
        d = c; c = b; b = a; \
        a = _mm256_add_epi64(T1, T2); \
    } while(0)

    #define STEP_FUSED_AVX2(k_fused) do { \
        __m256i h_kw    = _mm256_add_epi64(h, (k_fused)); \
        __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g)); \
        __m256i T1      = _mm256_add_epi64(h_kw, e_terms); \
        __m256i T2      = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c)); \
        h = g; g = f; f = e; \
        e = _mm256_add_epi64(d, T1); \
        d = c; c = b; b = a; \
        a = _mm256_add_epi64(T1, T2); \
    } while(0)

    STEP_AVX2(k_tbl[0], W[0]);  W[0] = _mm256_add_epi64(W[0], s0_AVX2(W[1]));
    STEP_AVX2(k_tbl[1], W[1]);  W[1] = _mm256_add_epi64(W[1], _mm256_add_epi64(s0_AVX2(W[2]), C_S1_W15));
    STEP_AVX2(k_tbl[2], W[2]);  W[2] = _mm256_add_epi64(W[2], _mm256_add_epi64(s0_AVX2(W[3]), s1_AVX2(W[0])));
    STEP_AVX2(k_tbl[3], W[3]);  W[3] = _mm256_add_epi64(W[3], _mm256_add_epi64(s0_AVX2(W[4]), s1_AVX2(W[1])));
    STEP_AVX2(k_tbl[4], W[4]);  W[4] = _mm256_add_epi64(W[4], _mm256_add_epi64(s0_AVX2(W[5]), s1_AVX2(W[2])));
    STEP_AVX2(k_tbl[5], W[5]);  W[5] = _mm256_add_epi64(W[5], _mm256_add_epi64(s0_AVX2(W[6]), s1_AVX2(W[3])));
    STEP_AVX2(k_tbl[6], W[6]);  W[6] = _mm256_add_epi64(W[6], _mm256_add_epi64(_mm256_add_epi64(s0_AVX2(W[7]), C_W15), s1_AVX2(W[4])));
    STEP_AVX2(k_tbl[7], W[7]);  W[7] = _mm256_add_epi64(W[7], _mm256_add_epi64(_mm256_add_epi64(C_S0_W8, W[0]), s1_AVX2(W[5])));

    STEP_FUSED_AVX2(K_FUSED_8);  W[8]  = _mm256_add_epi64(C_W8, _mm256_add_epi64(W[1], s1_AVX2(W[6])));
    STEP_FUSED_AVX2(k_tbl[9]);   W[9]  = _mm256_add_epi64(W[2], s1_AVX2(W[7]));
    STEP_FUSED_AVX2(k_tbl[10]);  W[10] = _mm256_add_epi64(W[3], s1_AVX2(W[8]));
    STEP_FUSED_AVX2(k_tbl[11]);  W[11] = _mm256_add_epi64(W[4], s1_AVX2(W[9]));
    STEP_FUSED_AVX2(k_tbl[12]);  W[12] = _mm256_add_epi64(W[5], s1_AVX2(W[10]));
    STEP_FUSED_AVX2(k_tbl[13]);  W[13] = _mm256_add_epi64(W[6], s1_AVX2(W[11]));
    STEP_FUSED_AVX2(k_tbl[14]);  W[14] = _mm256_add_epi64(C_S0_W15, _mm256_add_epi64(W[7], s1_AVX2(W[12])));
    STEP_FUSED_AVX2(K_FUSED_15); W[15] = _mm256_add_epi64(_mm256_add_epi64(C_W15, s0_AVX2(W[0])), _mm256_add_epi64(W[8], s1_AVX2(W[13])));

    #undef STEP_AVX2
    #undef STEP_FUSED_AVX2

    #pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m256i kw      = _mm256_add_epi64(k_tbl[r*16+i], W[i]);
            __m256i h_kw    = _mm256_add_epi64(h, kw);
            __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));
            __m256i T1      = _mm256_add_epi64(h_kw, e_terms);
            __m256i T2    = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));
            h = g; g = f; f = e;
            e = _mm256_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm256_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm256_add_epi64(W[i], _mm256_add_epi64(
                       _mm256_add_epi64(s0_AVX2(W[(i+1)&15]), W[(i+9)&15]),
                       s1_AVX2(W[(i+14)&15])));
            }
        }
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void pbkdf2_4lane_fused_stream(
    const __m256i ipad_iv[8], const __m256i opad_iv[8],
    const __m256i initial_digest[8], __m256i T[8], uint32_t iterations)
{
    __m256i W[16];
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    for (uint32_t it = 1; it < iterations; ++it) {
        sha512_padded_block64_avx2(ipad_iv, W, W);
        sha512_padded_block64_avx2(opad_iv, W, W);
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) T[i] = _mm256_xor_si256(T[i], W[i]);
    }
}

[[gnu::target("avx2"), gnu::always_inline]]
static inline void sha512_salt_fastforward_avx2(const __m256i iv[8],
                                                const uint64_t kw_salt[80],
                                                __m256i out[8])
{
    __m256i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    #pragma GCC unroll 80
    for (int i = 0; i < 80; ++i) {
        __m256i kw      = _mm256_set1_epi64x((long long)kw_salt[i]);
        __m256i h_kw    = _mm256_add_epi64(h, kw);
        __m256i e_terms = _mm256_add_epi64(S1_AVX2(e), CH_AVX2(e, f, g));
        __m256i T1      = _mm256_add_epi64(h_kw, e_terms);
        __m256i T2      = _mm256_add_epi64(S0_AVX2(a), MAJ_AVX2(a, b, c));
        h = g; g = f; f = e;
        e = _mm256_add_epi64(d, T1);
        d = c; c = b; b = a;
        a = _mm256_add_epi64(T1, T2);
    }
    out[0] = _mm256_add_epi64(iv[0], a); out[1] = _mm256_add_epi64(iv[1], b);
    out[2] = _mm256_add_epi64(iv[2], c); out[3] = _mm256_add_epi64(iv[3], d);
    out[4] = _mm256_add_epi64(iv[4], e); out[5] = _mm256_add_epi64(iv[5], f);
    out[6] = _mm256_add_epi64(iv[6], g); out[7] = _mm256_add_epi64(iv[7], h);
}

// Compat: mantém a assinatura antiga (recebe salt_blk64 já pronto).
inline void precompute_kw_salt(const uint64_t salt_blk64[16], uint64_t kw_salt[80]) {
    pbkdf2_simd_detail::precompute_kw_salt_from_W(salt_blk64, kw_salt);
}

[[gnu::target("avx2")]]
inline void pbkdf2_hmac_sha512_8way_avx2(
    const char* p1, size_t l1, const char* p2, size_t l2,
    const char* p3, size_t l3, const char* p4, size_t l4,
    const char* p5, size_t l5, const char* p6, size_t l6,
    const char* p7, size_t l7, const char* p8, size_t l8,
    const uint8_t* salt, size_t salt_len, uint32_t iterations,
    uint8_t out1[64],  uint8_t out2[64],  uint8_t out3[64],  uint8_t out4[64],
    uint8_t out5[64],  uint8_t out6[64],  uint8_t out7[64],  uint8_t out8[64],
    const uint64_t* precomputed_salt_blk64 = nullptr,
    const uint64_t* precomputed_kw_salt = nullptr)
{
    using namespace pbkdf2_simd_detail;

    // --- 1. Preparação dos pads por lane ---
    const void*  passes[8] = { p1, p2, p3, p4, p5, p6, p7, p8 };
    const size_t lens  [8] = { l1, l2, l3, l4, l5, l6, l7, l8 };
    uint64_t ipad_all[16][8], opad_all[16][8];
    prepare_pads<8>(passes, lens, ipad_all, opad_all);

    alignas(32) uint64_t ipad_lo[16][4], ipad_hi[16][4];
    alignas(32) uint64_t opad_lo[16][4], opad_hi[16][4];
    for (int w = 0; w < 16; ++w) {
        for (int l = 0; l < 4; ++l) {
            ipad_lo[w][l] = ipad_all[w][l];
            ipad_hi[w][l] = ipad_all[w][4 + l];
            opad_lo[w][l] = opad_all[w][l];
            opad_hi[w][l] = opad_all[w][4 + l];
        }
    }

    // --- 2. Estados pós ipad/opad ---
    __m256i ipad_iv_lo[8], ipad_iv_hi[8], opad_iv_lo[8], opad_iv_hi[8];
    __m256i W[16];
    for (int i=0;i<16;++i) W[i] = _mm256_loadu_si256((const __m256i*)ipad_lo[i]);
    sha512_block64_avx2(get_iv_avx2(), W, ipad_iv_lo);
    for (int i=0;i<16;++i) W[i] = _mm256_loadu_si256((const __m256i*)ipad_hi[i]);
    sha512_block64_avx2(get_iv_avx2(), W, ipad_iv_hi);
    for (int i=0;i<16;++i) W[i] = _mm256_loadu_si256((const __m256i*)opad_lo[i]);
    sha512_block64_avx2(get_iv_avx2(), W, opad_iv_lo);
    for (int i=0;i<16;++i) W[i] = _mm256_loadu_si256((const __m256i*)opad_hi[i]);
    sha512_block64_avx2(get_iv_avx2(), W, opad_iv_hi);

    // --- 3. Bloco do salt (U_1) ---
    __m256i s_lo[8], s_hi[8];
    if (precomputed_kw_salt) {
        sha512_salt_fastforward_avx2(ipad_iv_lo, precomputed_kw_salt, s_lo);
        sha512_salt_fastforward_avx2(ipad_iv_hi, precomputed_kw_salt, s_hi);
    } else {
        uint64_t salt_W[16];
        if (precomputed_salt_blk64) {
            for (int i=0;i<16;++i) salt_W[i] = precomputed_salt_blk64[i];
        } else {
            prepare_salt_W(salt, salt_len, salt_W);
        }
        __m256i Wsalt[16];
        for (int i=0;i<16;++i) Wsalt[i] = _mm256_set1_epi64x((long long)salt_W[i]);
        for (int i=0;i<16;++i) W[i] = Wsalt[i];
        sha512_block64_avx2(ipad_iv_lo, W, s_lo);
        for (int i=0;i<16;++i) W[i] = Wsalt[i];
        sha512_block64_avx2(ipad_iv_hi, W, s_hi);
    }

    // --- 4. Outer hash de U_1 ---
    __m256i T_lo[8], T_hi[8];
    for (int i=0;i<8;++i) W[i] = s_lo[i];
    for (int i=8;i<16;++i) W[i] = _mm256_setzero_si256();
    sha512_padded_block64_avx2(opad_iv_lo, W, T_lo);
    for (int i=0;i<8;++i) W[i] = s_hi[i];
    for (int i=8;i<16;++i) W[i] = _mm256_setzero_si256();
    sha512_padded_block64_avx2(opad_iv_hi, W, T_hi);

    // --- 5. Iterações 2..N ---
    pbkdf2_4lane_fused_stream(ipad_iv_lo, opad_iv_lo, T_lo, T_lo, iterations);
    pbkdf2_4lane_fused_stream(ipad_iv_hi, opad_iv_hi, T_hi, T_hi, iterations);

    // --- 6. Serialização ---
    alignas(32) uint64_t lo[8][4], hi[8][4];
    for (int i=0;i<8;++i) {
        _mm256_storeu_si256((__m256i*)lo[i], T_lo[i]);
        _mm256_storeu_si256((__m256i*)hi[i], T_hi[i]);
    }
    uint64_t combined[8][8];
    for (int i=0;i<8;++i) {
        for (int l=0;l<4;++l) { combined[i][l]=lo[i][l]; combined[i][4+l]=hi[i][l]; }
    }
    uint8_t* outs[8] = { out1, out2, out3, out4, out5, out6, out7, out8 };
    store_digests_be<8>(combined, outs);
}

// ============================================================================
// AVX-512
// ============================================================================
#define CH_AVX512(x, y, z)  _mm512_ternarylogic_epi64(x, y, z, 0xCA)
#define MAJ_AVX512(x, y, z) _mm512_ternarylogic_epi64(x, y, z, 0xE8)
#define S0_AVX512(x) _mm512_ternarylogic_epi64(_mm512_ror_epi64(x,28), _mm512_ror_epi64(x,34), _mm512_ror_epi64(x,39), 0x96)
#define S1_AVX512(x) _mm512_ternarylogic_epi64(_mm512_ror_epi64(x,14), _mm512_ror_epi64(x,18), _mm512_ror_epi64(x,41), 0x96)
#define s0_AVX512(x) _mm512_ternarylogic_epi64(_mm512_ror_epi64(x,1),  _mm512_ror_epi64(x,8),  _mm512_srli_epi64(x,7),  0x96)
#define s1_AVX512(x) _mm512_ternarylogic_epi64(_mm512_ror_epi64(x,19), _mm512_ror_epi64(x,61), _mm512_srli_epi64(x,6),  0x96)

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_block64_avx512(const __m512i iv[8], __m512i W[16], __m512i out[8]) {
    __m512i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    const __m512i* k_tbl = get_k512_avx512();
    #pragma GCC unroll 5
    for (int r = 0; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m512i kw      = _mm512_add_epi64(k_tbl[r*16+i], W[i]);
            __m512i h_kw    = _mm512_add_epi64(h, kw);
            __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));
            __m512i T1      = _mm512_add_epi64(h_kw, e_terms);
            __m512i T2    = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));
            h = g; g = f; f = e;
            e = _mm512_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm512_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm512_add_epi64(W[i], _mm512_add_epi64(
                       _mm512_add_epi64(s0_AVX512(W[(i+1)&15]), W[(i+9)&15]),
                       s1_AVX512(W[(i+14)&15])));
            }
        }
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_padded_block64_avx512(const __m512i iv[8], __m512i W[16], __m512i out[8]) {
    alignas(64) static const __m512i C_S1_W15  = _mm512_set1_epi64(0x00c0000000003018ULL);
    alignas(64) static const __m512i C_S0_W8   = _mm512_set1_epi64(0x4180000000000000ULL);
    alignas(64) static const __m512i C_S0_W15  = _mm512_set1_epi64(0x000000000000030aULL);
    alignas(64) static const __m512i C_W8      = _mm512_set1_epi64(0x8000000000000000ULL);
    alignas(64) static const __m512i C_W15     = _mm512_set1_epi64(0x0000000000000600ULL);
    alignas(64) static const __m512i K_FUSED_8  = _mm512_set1_epi64(0xd807aa98a3030242ULL + 0x8000000000000000ULL);
    alignas(64) static const __m512i K_FUSED_15 = _mm512_set1_epi64(0xc19bf174cf692694ULL + 0x0000000000000600ULL);

    __m512i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    const __m512i* k_tbl = get_k512_avx512();

    #define STEP_AVX512(k_term, w_val) do { \
        __m512i kw      = _mm512_add_epi64((k_term), (w_val)); \
        __m512i h_kw    = _mm512_add_epi64(h, kw); \
        __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g)); \
        __m512i T1      = _mm512_add_epi64(h_kw, e_terms); \
        __m512i T2      = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c)); \
        h = g; g = f; f = e; \
        e = _mm512_add_epi64(d, T1); \
        d = c; c = b; b = a; \
        a = _mm512_add_epi64(T1, T2); \
    } while(0)

    #define STEP_FUSED_AVX512(k_fused) do { \
        __m512i h_kw    = _mm512_add_epi64(h, (k_fused)); \
        __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g)); \
        __m512i T1      = _mm512_add_epi64(h_kw, e_terms); \
        __m512i T2      = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c)); \
        h = g; g = f; f = e; \
        e = _mm512_add_epi64(d, T1); \
        d = c; c = b; b = a; \
        a = _mm512_add_epi64(T1, T2); \
    } while(0)

    STEP_AVX512(k_tbl[0], W[0]);  W[0] = _mm512_add_epi64(W[0], s0_AVX512(W[1]));
    STEP_AVX512(k_tbl[1], W[1]);  W[1] = _mm512_add_epi64(W[1], _mm512_add_epi64(s0_AVX512(W[2]), C_S1_W15));
    STEP_AVX512(k_tbl[2], W[2]);  W[2] = _mm512_add_epi64(W[2], _mm512_add_epi64(s0_AVX512(W[3]), s1_AVX512(W[0])));
    STEP_AVX512(k_tbl[3], W[3]);  W[3] = _mm512_add_epi64(W[3], _mm512_add_epi64(s0_AVX512(W[4]), s1_AVX512(W[1])));
    STEP_AVX512(k_tbl[4], W[4]);  W[4] = _mm512_add_epi64(W[4], _mm512_add_epi64(s0_AVX512(W[5]), s1_AVX512(W[2])));
    STEP_AVX512(k_tbl[5], W[5]);  W[5] = _mm512_add_epi64(W[5], _mm512_add_epi64(s0_AVX512(W[6]), s1_AVX512(W[3])));
    STEP_AVX512(k_tbl[6], W[6]);  W[6] = _mm512_add_epi64(W[6], _mm512_add_epi64(_mm512_add_epi64(s0_AVX512(W[7]), C_W15), s1_AVX512(W[4])));
    STEP_AVX512(k_tbl[7], W[7]);  W[7] = _mm512_add_epi64(W[7], _mm512_add_epi64(_mm512_add_epi64(C_S0_W8, W[0]), s1_AVX512(W[5])));

    STEP_FUSED_AVX512(K_FUSED_8);  W[8]  = _mm512_add_epi64(C_W8, _mm512_add_epi64(W[1], s1_AVX512(W[6])));
    STEP_FUSED_AVX512(k_tbl[9]);   W[9]  = _mm512_add_epi64(W[2], s1_AVX512(W[7]));
    STEP_FUSED_AVX512(k_tbl[10]);  W[10] = _mm512_add_epi64(W[3], s1_AVX512(W[8]));
    STEP_FUSED_AVX512(k_tbl[11]);  W[11] = _mm512_add_epi64(W[4], s1_AVX512(W[9]));
    STEP_FUSED_AVX512(k_tbl[12]);  W[12] = _mm512_add_epi64(W[5], s1_AVX512(W[10]));
    STEP_FUSED_AVX512(k_tbl[13]);  W[13] = _mm512_add_epi64(W[6], s1_AVX512(W[11]));
    STEP_FUSED_AVX512(k_tbl[14]);  W[14] = _mm512_add_epi64(C_S0_W15, _mm512_add_epi64(W[7], s1_AVX512(W[12])));
    STEP_FUSED_AVX512(K_FUSED_15); W[15] = _mm512_add_epi64(_mm512_add_epi64(C_W15, s0_AVX512(W[0])), _mm512_add_epi64(W[8], s1_AVX512(W[13])));

    #undef STEP_AVX512
    #undef STEP_FUSED_AVX512

    #pragma GCC unroll 4
    for (int r = 1; r < 5; ++r) {
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            __m512i kw      = _mm512_add_epi64(k_tbl[r*16+i], W[i]);
            __m512i h_kw    = _mm512_add_epi64(h, kw);
            __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));
            __m512i T1      = _mm512_add_epi64(h_kw, e_terms);
            __m512i T2    = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));
            h = g; g = f; f = e;
            e = _mm512_add_epi64(d, T1);
            d = c; c = b; b = a;
            a = _mm512_add_epi64(T1, T2);
            if (r < 4) {
                W[i] = _mm512_add_epi64(W[i], _mm512_add_epi64(
                       _mm512_add_epi64(s0_AVX512(W[(i+1)&15]), W[(i+9)&15]),
                       s1_AVX512(W[(i+14)&15])));
            }
        }
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void pbkdf2_8lane_fused_stream(
    const __m512i ipad_iv[8], const __m512i opad_iv[8],
    const __m512i initial_digest[8], __m512i T[8], uint32_t iterations)
{
    __m512i W[16];
    #pragma GCC unroll 8
    for (int i = 0; i < 8; ++i) W[i] = initial_digest[i];

    for (uint32_t it = 1; it < iterations; ++it) {
        sha512_padded_block64_avx512(ipad_iv, W, W);
        sha512_padded_block64_avx512(opad_iv, W, W);
        #pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) T[i] = _mm512_xor_si512(T[i], W[i]);
    }
}

[[gnu::target("avx512f,avx512vl"), gnu::always_inline]]
static inline void sha512_salt_fastforward_avx512(const __m512i iv[8],
                                                  const uint64_t kw_salt[80],
                                                  __m512i out[8])
{
    __m512i a=iv[0], b=iv[1], c=iv[2], d=iv[3], e=iv[4], f=iv[5], g=iv[6], h=iv[7];
    #pragma GCC unroll 80
    for (int i = 0; i < 80; ++i) {
        __m512i kw      = _mm512_set1_epi64((long long)kw_salt[i]);
        __m512i h_kw    = _mm512_add_epi64(h, kw);
        __m512i e_terms = _mm512_add_epi64(S1_AVX512(e), CH_AVX512(e, f, g));
        __m512i T1      = _mm512_add_epi64(h_kw, e_terms);
        __m512i T2      = _mm512_add_epi64(S0_AVX512(a), MAJ_AVX512(a, b, c));
        h = g; g = f; f = e;
        e = _mm512_add_epi64(d, T1);
        d = c; c = b; b = a;
        a = _mm512_add_epi64(T1, T2);
    }
    out[0] = _mm512_add_epi64(iv[0], a); out[1] = _mm512_add_epi64(iv[1], b);
    out[2] = _mm512_add_epi64(iv[2], c); out[3] = _mm512_add_epi64(iv[3], d);
    out[4] = _mm512_add_epi64(iv[4], e); out[5] = _mm512_add_epi64(iv[5], f);
    out[6] = _mm512_add_epi64(iv[6], g); out[7] = _mm512_add_epi64(iv[7], h);
}

[[gnu::target("avx512f,avx512vl")]]
inline void pbkdf2_hmac_sha512_16way_avx512(
    const char* p1,  size_t l1,  const char* p2,  size_t l2,
    const char* p3,  size_t l3,  const char* p4,  size_t l4,
    const char* p5,  size_t l5,  const char* p6,  size_t l6,
    const char* p7,  size_t l7,  const char* p8,  size_t l8,
    const char* p9,  size_t l9,  const char* p10, size_t l10,
    const char* p11, size_t l11, const char* p12, size_t l12,
    const char* p13, size_t l13, const char* p14, size_t l14,
    const char* p15, size_t l15, const char* p16, size_t l16,
    const uint8_t* salt, size_t salt_len, uint32_t iterations,
    uint8_t out1[64],  uint8_t out2[64],  uint8_t out3[64],  uint8_t out4[64],
    uint8_t out5[64],  uint8_t out6[64],  uint8_t out7[64],  uint8_t out8[64],
    uint8_t out9[64],  uint8_t out10[64], uint8_t out11[64], uint8_t out12[64],
    uint8_t out13[64], uint8_t out14[64], uint8_t out15[64], uint8_t out16[64],
    const uint64_t* precomputed_salt_blk64 = nullptr,
    const uint64_t* precomputed_kw_salt = nullptr)
{
    using namespace pbkdf2_simd_detail;

    // --- 1. Preparação dos pads por lane ---
    const void*  passes[16] = { p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16 };
    const size_t lens  [16] = { l1,l2,l3,l4,l5,l6,l7,l8,l9,l10,l11,l12,l13,l14,l15,l16 };
    uint64_t ipad_all[16][16], opad_all[16][16];
    prepare_pads<16>(passes, lens, ipad_all, opad_all);

    alignas(64) uint64_t ipad_lo[16][8], ipad_hi[16][8];
    alignas(64) uint64_t opad_lo[16][8], opad_hi[16][8];
    for (int w = 0; w < 16; ++w) {
        for (int l = 0; l < 8; ++l) {
            ipad_lo[w][l] = ipad_all[w][l];
            ipad_hi[w][l] = ipad_all[w][8 + l];
            opad_lo[w][l] = opad_all[w][l];
            opad_hi[w][l] = opad_all[w][8 + l];
        }
    }

    // --- 2. Estados pós ipad/opad ---
    __m512i ipad_iv_lo[8], ipad_iv_hi[8], opad_iv_lo[8], opad_iv_hi[8];
    __m512i W[16];
    for (int i=0;i<16;++i) W[i] = _mm512_loadu_si512((const __m512i*)ipad_lo[i]);
    sha512_block64_avx512(get_iv_avx512(), W, ipad_iv_lo);
    for (int i=0;i<16;++i) W[i] = _mm512_loadu_si512((const __m512i*)ipad_hi[i]);
    sha512_block64_avx512(get_iv_avx512(), W, ipad_iv_hi);
    for (int i=0;i<16;++i) W[i] = _mm512_loadu_si512((const __m512i*)opad_lo[i]);
    sha512_block64_avx512(get_iv_avx512(), W, opad_iv_lo);
    for (int i=0;i<16;++i) W[i] = _mm512_loadu_si512((const __m512i*)opad_hi[i]);
    sha512_block64_avx512(get_iv_avx512(), W, opad_iv_hi);

    // --- 3. Bloco do salt (U_1) ---
    __m512i s_lo[8], s_hi[8];
    if (precomputed_kw_salt) {
        sha512_salt_fastforward_avx512(ipad_iv_lo, precomputed_kw_salt, s_lo);
        sha512_salt_fastforward_avx512(ipad_iv_hi, precomputed_kw_salt, s_hi);
    } else {
        uint64_t salt_W[16];
        if (precomputed_salt_blk64) {
            for (int i=0;i<16;++i) salt_W[i] = precomputed_salt_blk64[i];
        } else {
            prepare_salt_W(salt, salt_len, salt_W);
        }
        __m512i Wsalt[16];
        for (int i=0;i<16;++i) Wsalt[i] = _mm512_set1_epi64((long long)salt_W[i]);
        for (int i=0;i<16;++i) W[i] = Wsalt[i];
        sha512_block64_avx512(ipad_iv_lo, W, s_lo);
        for (int i=0;i<16;++i) W[i] = Wsalt[i];
        sha512_block64_avx512(ipad_iv_hi, W, s_hi);
    }

    // --- 4. Outer hash de U_1 ---
    __m512i T_lo[8], T_hi[8];
    for (int i=0;i<8;++i) W[i] = s_lo[i];
    for (int i=8;i<16;++i) W[i] = _mm512_setzero_si512();
    sha512_padded_block64_avx512(opad_iv_lo, W, T_lo);
    for (int i=0;i<8;++i) W[i] = s_hi[i];
    for (int i=8;i<16;++i) W[i] = _mm512_setzero_si512();
    sha512_padded_block64_avx512(opad_iv_hi, W, T_hi);

    // --- 5. Iterações 2..N ---
    pbkdf2_8lane_fused_stream(ipad_iv_lo, opad_iv_lo, T_lo, T_lo, iterations);
    pbkdf2_8lane_fused_stream(ipad_iv_hi, opad_iv_hi, T_hi, T_hi, iterations);

    // --- 6. Serialização ---
    alignas(64) uint64_t lo[8][8], hi[8][8];
    for (int i=0;i<8;++i) {
        _mm512_storeu_si512((__m512i*)lo[i], T_lo[i]);
        _mm512_storeu_si512((__m512i*)hi[i], T_hi[i]);
    }
    uint64_t combined[8][16];
    for (int i=0;i<8;++i) {
        for (int l=0;l<8;++l) { combined[i][l]=lo[i][l]; combined[i][8+l]=hi[i][l]; }
    }
    uint8_t* outs[16] = {
        out1, out2, out3, out4, out5, out6, out7, out8,
        out9, out10, out11, out12, out13, out14, out15, out16
    };
    store_digests_be<16>(combined, outs);
}

// ============================================================================
// Macros de limpeza (higiene de cabeçalho)
// ============================================================================
#undef ROR128_64
#undef CH_SSE
#undef MAJ_SSE
#undef S0_SSE
#undef S1_SSE
#undef s0_SSE
#undef s1_SSE

#undef ROR256_64
#undef CH_AVX2
#undef MAJ_AVX2
#undef S0_AVX2
#undef S1_AVX2
#undef s0_AVX2
#undef s1_AVX2

#undef CH_AVX512
#undef MAJ_AVX512
#undef S0_AVX512
#undef S1_AVX512
#undef s0_AVX512
#undef s1_AVX512
