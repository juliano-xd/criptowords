#pragma once

// Implementação SHA-512 compatível com C++23 e C++26.
// O SIMD em lote usa flags de compilação; SHA-512 nativo é selecionado em runtime.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif
#endif

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
// Alguns compiladores só expõem esses intrinsics quando o recurso está ligado
// globalmente. A função acelerada abaixo tem target próprio, então habilitamos
// as declarações somente durante a inclusão do header e restauramos a macro.
#if !defined(__ARM_FEATURE_SHA512)
#define CRYPTO_SHA512_DEFINED_ARM_FEATURE_SHA512
#define __ARM_FEATURE_SHA512 1
#endif
#include <arm_neon.h>
#if defined(CRYPTO_SHA512_DEFINED_ARM_FEATURE_SHA512)
#undef __ARM_FEATURE_SHA512
#undef CRYPTO_SHA512_DEFINED_ARM_FEATURE_SHA512
#endif
#if defined(__ANDROID__)
#if !defined(__ANDROID_API__) || (__ANDROID_API__ >= 18)
#include <sys/auxv.h>
#endif
#elif defined(__linux__)
#include <sys/auxv.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
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

    static constexpr word bswap64(word x) noexcept { return std::byteswap(x); }

   public:
    static word load_be64(const void* p) noexcept {
        word v;
        std::memcpy(&v, p, sizeof(v));
        if constexpr (std::endian::native == std::endian::little)
            v = bswap64(v);
        return v;
    }

    static void store_be64(void* p, word v) noexcept {
        if constexpr (std::endian::native == std::endian::little)
            v = bswap64(v);
        std::memcpy(p, &v, sizeof(v));
    }

    static word ch(word x, word y, word z) noexcept { return z ^ (x & (y ^ z)); }

    static word maj(word x, word y, word z) noexcept { return (x & y) | (z & (x | y)); }

    static word big0(word x) noexcept {
        return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39);
    }

    static word big1(word x) noexcept {
        return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41);
    }

    static word small0(word x) noexcept { return std::rotr(x, 1) ^ std::rotr(x, 8) ^ (x >> 7); }

    static word small1(word x) noexcept { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }

    static void round(word& a, word& b, word& c, word& d, word& e, word& f, word& g, word& h,
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

    using NativeCompress = void (*)(std::array<word, 8>&, const word*) noexcept;

#if (defined(__x86_64__) || defined(__i386__)) && ((defined(__clang__) && __clang_major__ >= 17) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 14))
    static bool detect_x86_sha512() noexcept {
        if (__get_cpuid_max(0, nullptr) < 7)
            return false;

        unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid_count(1, 0, eax, ebx, ecx, edx);
        constexpr unsigned osxsave = 1u << 27;
        constexpr unsigned avx = 1u << 28;
        if ((ecx & (osxsave | avx)) != (osxsave | avx))
            return false;

        std::uint32_t xcr0_lo = 0, xcr0_hi = 0;
        __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
        const std::uint64_t xcr0 = (static_cast<std::uint64_t>(xcr0_hi) << 32) | xcr0_lo;
        if ((xcr0 & 0x6u) != 0x6u) // O sistema operacional deve salvar XMM/YMM.
            return false;

        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        if (eax < 1 || (ebx & (1u << 5)) == 0) // Subfolha 7.1 e AVX2.
            return false;

        __cpuid_count(7, 1, eax, ebx, ecx, edx);
        return (eax & 1u) != 0; // CPUID.(7,1):EAX[0] = SHA512.
    }
#endif

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
    static bool detect_arm64_sha512() noexcept {
#if defined(__linux__) || defined(__ANDROID__)
#if defined(__ANDROID_API__) && (__ANDROID_API__ < 18)
        return false; // getauxval não está disponível em APIs Android tão antigas.
#else
        constexpr unsigned long hwcap_sha512 = 1UL << 21;
        return (getauxval(AT_HWCAP) & hwcap_sha512) != 0;
#endif
#elif defined(__APPLE__)
        int enabled = 0;
        std::size_t size = sizeof(enabled);
        return sysctlbyname("hw.optional.armv8_2_sha512", &enabled, &size, nullptr, 0) == 0 && enabled != 0;
#else
        return false; // Sem consulta portátil de HWCAP, não executar instruções opcionais.
#endif
    }
#endif

#if (defined(__x86_64__) || defined(__i386__)) && ((defined(__clang__) && __clang_major__ >= 17) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 14))
    // Intel SHA-512 (VSHA512): esta implementação usa AVX2 + a extensão SHA512.
    // A detecção de CPU e do estado YMM acontece antes de despachar para esta função.
    static __attribute__((target("sha512,avx2"))) void compress_native_x86(
        std::array<word, 8>& state, const word* input) noexcept {
        alignas(64) word w[16];
        for (unsigned i = 0; i < 16; ++i)
            w[i] = input[i];

        __m256i state0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state.data()));
        __m256i state1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(state.data() + 4));
        __m256i tmp;

        // Layout exigido por VSHA512RNDS2: state0 = CDGH; state1 = ABEF.
        state0 = _mm256_shuffle_epi32(state0, 0x4e);
        state1 = _mm256_shuffle_epi32(state1, 0x4e);
        tmp = state0;
        state0 = _mm256_permute2x128_si256(state0, state1, 0x13);
        state1 = _mm256_permute2x128_si256(tmp, state1, 0x02);

        const __m256i state0_initial = state0;
        const __m256i state1_initial = state1;

        for (unsigned t = 0; t < 80; t += 4) {
            alignas(32) word wk[4];
            for (unsigned j = 0; j < 4; ++j) {
                const unsigned r = t + j;
                const unsigned i = r & 15u;
                if (r >= 16) {
                    w[i] += small0(w[(i + 1) & 15u]) + w[(i + 9) & 15u] + small1(w[(i + 14) & 15u]);
                }
                wk[j] = w[i] + K_[r];
            }

            const __m256i msg = _mm256_load_si256(reinterpret_cast<const __m256i*>(wk));
            state0 = _mm256_sha512rnds2_epi64(state0, state1, _mm256_castsi256_si128(msg));
            state1 = _mm256_sha512rnds2_epi64(state1, state0, _mm256_extracti128_si256(msg, 1));
        }

        state0 = _mm256_add_epi64(state0, state0_initial);
        state1 = _mm256_add_epi64(state1, state1_initial);

        // Volta do layout CDGH/ABEF para A..H, preservando o feed-forward.
        state0 = _mm256_shuffle_epi32(state0, 0x4e);
        state1 = _mm256_shuffle_epi32(state1, 0x4e);
        tmp = state0;
        state0 = _mm256_permute2x128_si256(state0, state1, 0x13);
        state1 = _mm256_permute2x128_si256(tmp, state1, 0x02);

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(state.data()), state0);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(state.data() + 4), state1);
    }
#endif

#if defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
#if defined(__clang__)
    static __attribute__((target("sha3"))) void compress_native_arm64(
        std::array<word, 8>& state, const word* input) noexcept {
#else
    static __attribute__((target("arch=armv8.2-a+sha3"))) void compress_native_arm64(
        std::array<word, 8>& state, const word* input) noexcept {
#endif
        // 1. Carrega as 16 palavras da mensagem inicial diretamente em 8 registadores NEON
        uint64x2_t w0 = vld1q_u64(input + 0);
        uint64x2_t w1 = vld1q_u64(input + 2);
        uint64x2_t w2 = vld1q_u64(input + 4);
        uint64x2_t w3 = vld1q_u64(input + 6);
        uint64x2_t w4 = vld1q_u64(input + 8);
        uint64x2_t w5 = vld1q_u64(input + 10);
        uint64x2_t w6 = vld1q_u64(input + 12);
        uint64x2_t w7 = vld1q_u64(input + 14);

        // 2. Carrega o estado inicial do hash
        uint64x2_t q0 = vld1q_u64(reinterpret_cast<const uint64_t*>(state.data()));
        uint64x2_t q1 = vld1q_u64(reinterpret_cast<const uint64_t*>(state.data() + 2));
        uint64x2_t q2 = vld1q_u64(reinterpret_cast<const uint64_t*>(state.data() + 4));
        uint64x2_t q3 = vld1q_u64(reinterpret_cast<const uint64_t*>(state.data() + 6));

        const uint64x2_t q0_initial = q0;
        const uint64x2_t q1_initial = q1;
        const uint64x2_t q2_initial = q2;
        const uint64x2_t q3_initial = q3;

        // Macro para processar duas rounds do SHA-512 e rodar os registos a0-a3
        #define SHA512_ROUND_ARM(wa, wb, k_idx) \
            do { \
                uint64x2_t kw = vaddq_u64(wa, vld1q_u64(&K_[k_idx])); \
                uint64x2_t v = vaddq_u64(vextq_u64(kw, kw, 1), q3); \
                v = vsha512hq_u64(v, vextq_u64(q2, q3, 1), vextq_u64(q1, q2, 1)); \
                uint64x2_t next_q3 = vsha512h2q_u64(v, q1, q0); \
                q1 = vaddq_u64(q1, v); \
                q0 = q1; q1 = q2; q2 = q3; q3 = next_q3; \
            } while (0)

        // Macro para expandir a mensagem (Message Schedule) para as próximas rounds
        #define SHA512_SU_ARM(wa, wb, wc, wd, we) \
            do { \
                wa = vsha512su1q_u64(vsha512su0q_u64(wa, wb), wc, vextq_u64(wd, we, 1)); \
            } while (0)

        // Rounds 0-15 (Mensagem original sem expansão)
        SHA512_ROUND_ARM(w0, w1, 0);  SHA512_ROUND_ARM(w1, w2, 2);
        SHA512_ROUND_ARM(w2, w3, 4);  SHA512_ROUND_ARM(w3, w4, 6);
        SHA512_ROUND_ARM(w4, w5, 8);  SHA512_ROUND_ARM(w5, w6, 10);
        SHA512_ROUND_ARM(w6, w7, 12); SHA512_ROUND_ARM(w7, w0, 14);

        // Rounds 16-79 (Expansão da mensagem entremeada com as rounds do hash)
        for (unsigned t = 16; t < 80; t += 16) {
            SHA512_SU_ARM(w0, w1, w7, w4, w5); SHA512_ROUND_ARM(w0, w1, t + 0);
            SHA512_SU_ARM(w1, w2, w0, w5, w6); SHA512_ROUND_ARM(w1, w2, t + 2);
            SHA512_SU_ARM(w2, w3, w1, w6, w7); SHA512_ROUND_ARM(w2, w3, t + 4);
            SHA512_SU_ARM(w3, w4, w2, w7, w0); SHA512_ROUND_ARM(w3, w4, t + 6);
            SHA512_SU_ARM(w4, w5, w3, w0, w1); SHA512_ROUND_ARM(w4, w5, t + 8);
            SHA512_SU_ARM(w5, w6, w4, w1, w2); SHA512_ROUND_ARM(w5, w6, t + 10);
            SHA512_SU_ARM(w6, w7, w5, w2, w3); SHA512_ROUND_ARM(w6, w7, t + 12);
            SHA512_SU_ARM(w7, w0, w6, w3, w4); SHA512_ROUND_ARM(w7, w0, t + 14);
        }

        #undef SHA512_ROUND_ARM
        #undef SHA512_SU_ARM

        // 3. Adiciona o estado final ao estado inicial (feed-forward)
        q0 = vaddq_u64(q0, q0_initial);
        q1 = vaddq_u64(q1, q1_initial);
        q2 = vaddq_u64(q2, q2_initial);
        q3 = vaddq_u64(q3, q3_initial);

        vst1q_u64(reinterpret_cast<uint64_t*>(state.data()), q0);
        vst1q_u64(reinterpret_cast<uint64_t*>(state.data() + 2), q1);
        vst1q_u64(reinterpret_cast<uint64_t*>(state.data() + 4), q2);
        vst1q_u64(reinterpret_cast<uint64_t*>(state.data() + 6), q3);
    }
#endif

    static NativeCompress native_compressor() noexcept {
        static const NativeCompress selected = []() noexcept -> NativeCompress {
#if (defined(__x86_64__) || defined(__i386__)) && ((defined(__clang__) && __clang_major__ >= 17) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 14))
            if (detect_x86_sha512())
                return &compress_native_x86;
#elif defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
            if (detect_arm64_sha512())
                return &compress_native_arm64;
#endif
            return nullptr;
        }();
        return selected;
    }

    static void compress_software_words(std::array<word, 8>& state, const word* input) noexcept {
        alignas(64) word w[16];
        for (unsigned i = 0; i < 16; ++i)
            w[i] = input[i];

        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];
        for (unsigned i = 0; i < 16; ++i)
            round(a, b, c, d, e, f, g, h, K_[i], w[i]);
        for (unsigned t = 16; t < 80; ++t) {
            const unsigned i = t & 15u;
            w[i] += small0(w[(i + 1) & 15u]) + w[(i + 9) & 15u] + small1(w[(i + 14) & 15u]);
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

    static void compress(std::array<word, 8>& state, const byte* block) noexcept {
        alignas(64) word input[16];
        for (unsigned i = 0; i < 16; ++i)
            input[i] = load_be64(block + (i << 3));
        compress_words(state, input);
    }

    static void compress_words(std::array<word, 8>& state, const word w_in[16]) noexcept {
        if (const NativeCompress native = native_compressor()) {
            native(state, w_in);
            return;
        }
        compress_software_words(state, w_in);
    }

    static void compress_from(std::array<word, 8>& state, std::array<word, 16>& w,
                              std::uint32_t first_round) noexcept {
        word a = state[0], b = state[1], c = state[2], d = state[3];
        word e = state[4], f = state[5], g = state[6], h = state[7];

        for (std::uint32_t t = first_round; t < 16; ++t)
            round(a, b, c, d, e, f, g, h, K_[t], w[t]);
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

    static void compress_padded_block64(const word iv[8], word W[16], word out[8]) noexcept {
        // if (native_compressor() != nullptr) {
        //     std::array<word, 16> words{};
        //     for (unsigned i = 0; i < 8; ++i)
        //         words[i] = W[i];
        //     words[8] = 0x8000000000000000ULL;
        //     words[15] = 512;
        //     std::array<word, 8> state;
        //     for (unsigned i = 0; i < 8; ++i)
        //         state[i] = iv[i];
        //     compress_words(state, words.data());
        //     for (unsigned i = 0; i < 8; ++i)
        //         out[i] = state[i];
        //     return;
        // }
        constexpr word K_FUSED_8 = 0xd807aa98a3030242ULL + 0x8000000000000000ULL;
        constexpr word K_FUSED_15 = 0xc19bf174cf692694ULL + 0x0000000000000600ULL;
        constexpr word C_S1_W15 = 0x00c0000000003018ULL;
        constexpr word C_S0_W8 = 0x4180000000000000ULL;
        constexpr word C_S0_W15 = 0x000000000000030aULL;
        constexpr word C_W8 = 0x8000000000000000ULL;
        constexpr word C_W15 = 0x0000000000000600ULL;

        word a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];

        round(a, b, c, d, e, f, g, h, K_[0], W[0]);
        W[0] += small0(W[1]);
        round(a, b, c, d, e, f, g, h, K_[1], W[1]);
        W[1] += small0(W[2]) + C_S1_W15;
        round(a, b, c, d, e, f, g, h, K_[2], W[2]);
        W[2] += small0(W[3]) + small1(W[0]);
        round(a, b, c, d, e, f, g, h, K_[3], W[3]);
        W[3] += small0(W[4]) + small1(W[1]);
        round(a, b, c, d, e, f, g, h, K_[4], W[4]);
        W[4] += small0(W[5]) + small1(W[2]);
        round(a, b, c, d, e, f, g, h, K_[5], W[5]);
        W[5] += small0(W[6]) + small1(W[3]);
        round(a, b, c, d, e, f, g, h, K_[6], W[6]);
        W[6] += small0(W[7]) + C_W15 + small1(W[4]);
        round(a, b, c, d, e, f, g, h, K_[7], W[7]);
        W[7] += C_S0_W8 + W[0] + small1(W[5]);

        round(a, b, c, d, e, f, g, h, K_FUSED_8, 0);
        W[8] = C_W8 + W[1] + small1(W[6]);
        round(a, b, c, d, e, f, g, h, K_[9], 0);
        W[9] = W[2] + small1(W[7]);
        round(a, b, c, d, e, f, g, h, K_[10], 0);
        W[10] = W[3] + small1(W[8]);
        round(a, b, c, d, e, f, g, h, K_[11], 0);
        W[11] = W[4] + small1(W[9]);
        round(a, b, c, d, e, f, g, h, K_[12], 0);
        W[12] = W[5] + small1(W[10]);
        round(a, b, c, d, e, f, g, h, K_[13], 0);
        W[13] = W[6] + small1(W[11]);
        round(a, b, c, d, e, f, g, h, K_[14], 0);
        W[14] = C_S0_W15 + W[7] + small1(W[12]);
        round(a, b, c, d, e, f, g, h, K_FUSED_15, 0);
        W[15] = C_W15 + small0(W[0]) + W[8] + small1(W[13]);
        for (int r = 1; r < 5; ++r) {
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

    static void compress_padded_block37(const word iv[8], word W[16], word out[8]) noexcept {
        if (native_compressor() != nullptr) {
            std::array<word, 16> words{};
            for (unsigned i = 0; i < 5; ++i)
                words[i] = W[i];
            words[15] = 1320ULL; // 128 bytes do bloco anterior + 37 bytes de dados.
            std::array<word, 8> state;
            for (unsigned i = 0; i < 8; ++i)
                state[i] = iv[i];
            compress_words(state, words.data());
            for (unsigned i = 0; i < 8; ++i)
                out[i] = state[i];
            return;
        }
        constexpr word C_W15_37 = 1320ULL;
        constexpr word C_S0_1320 = (std::rotr(1320ULL, 1) ^ std::rotr(1320ULL, 8) ^ (1320ULL >> 7));
        constexpr word C_S1_1320 = (std::rotr(1320ULL, 19) ^ std::rotr(1320ULL, 61) ^ (1320ULL >> 6));
        constexpr word K_FUSED_15_37 = 0xc19bf174cf692694ULL + 1320ULL;

        word a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], h = iv[7];

        round(a, b, c, d, e, f, g, h, K_[0], W[0]);
        W[0] += small0(W[1]);
        round(a, b, c, d, e, f, g, h, K_[1], W[1]);
        W[1] += small0(W[2]) + C_S1_1320;
        round(a, b, c, d, e, f, g, h, K_[2], W[2]);
        W[2] += small0(W[3]) + small1(W[0]);
        round(a, b, c, d, e, f, g, h, K_[3], W[3]);
        W[3] += small0(W[4]) + small1(W[1]);
        round(a, b, c, d, e, f, g, h, K_[4], W[4]);
        W[4] += small1(W[2]);

        round(a, b, c, d, e, f, g, h, K_[5], 0);
        W[5] = small1(W[3]);
        round(a, b, c, d, e, f, g, h, K_[6], 0);
        W[6] = C_W15_37 + small1(W[4]);
        round(a, b, c, d, e, f, g, h, K_[7], 0);
        W[7] = W[0] + small1(W[5]);
        round(a, b, c, d, e, f, g, h, K_[8], 0);
        W[8] = W[1] + small1(W[6]);
        round(a, b, c, d, e, f, g, h, K_[9], 0);
        W[9] = W[2] + small1(W[7]);
        round(a, b, c, d, e, f, g, h, K_[10], 0);
        W[10] = W[3] + small1(W[8]);
        round(a, b, c, d, e, f, g, h, K_[11], 0);
        W[11] = W[4] + small1(W[9]);
        round(a, b, c, d, e, f, g, h, K_[12], 0);
        W[12] = W[5] + small1(W[10]);
        round(a, b, c, d, e, f, g, h, K_[13], 0);
        W[13] = W[6] + small1(W[11]);
        round(a, b, c, d, e, f, g, h, K_[14], 0);
        W[14] = C_S0_1320 + W[7] + small1(W[12]);
        round(a, b, c, d, e, f, g, h, K_FUSED_15_37, 0);
        W[15] = C_W15_37 + small0(W[0]) + W[8] + small1(W[13]);
        for (int r = 1; r < 5; ++r) {
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
    static void compress_pad128_32bytekey(const word key_words[4], word out[8]) noexcept {
        // if (native_compressor() != nullptr) {
        //     std::array<word, 16> words;
        //     words.fill(PAD);
        //     for (unsigned i = 0; i < 4; ++i)
        //         words[i] = key_words[i] ^ PAD;
        //     auto state = IV_;
        //     compress_words(state, words.data());
        //     for (unsigned i = 0; i < 8; ++i)
        //         out[i] = state[i];
        //     return;
        // }
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

        round(a, b, c, d, e, f, g, h, K_[0], W[0]);
        W[0] += small0(W[1]) + C_PAD_PLUS_S1;
        round(a, b, c, d, e, f, g, h, K_[1], W[1]);
        W[1] += small0(W[2]) + C_PAD_PLUS_S1;
        round(a, b, c, d, e, f, g, h, K_[2], W[2]);
        W[2] += small0(W[3]) + PAD + small1(W[0]);
        round(a, b, c, d, e, f, g, h, K_[3], W[3]);
        W[3] += C_PAD_PLUS_S0 + small1(W[1]);

        round(a, b, c, d, e, f, g, h, K_[4] + PAD, 0);
        W[4] = C_2PAD_PLUS_S0 + small1(W[2]);
        round(a, b, c, d, e, f, g, h, K_[5] + PAD, 0);
        W[5] = C_2PAD_PLUS_S0 + small1(W[3]);
        round(a, b, c, d, e, f, g, h, K_[6] + PAD, 0);
        W[6] = C_2PAD_PLUS_S0 + small1(W[4]);
        round(a, b, c, d, e, f, g, h, K_[7] + PAD, 0);
        W[7] = C_PAD_PLUS_S0 + W[0] + small1(W[5]);
        round(a, b, c, d, e, f, g, h, K_[8] + PAD, 0);
        W[8] = C_PAD_PLUS_S0 + W[1] + small1(W[6]);
        round(a, b, c, d, e, f, g, h, K_[9] + PAD, 0);
        W[9] = C_PAD_PLUS_S0 + W[2] + small1(W[7]);
        round(a, b, c, d, e, f, g, h, K_[10] + PAD, 0);
        W[10] = C_PAD_PLUS_S0 + W[3] + small1(W[8]);
        round(a, b, c, d, e, f, g, h, K_[11] + PAD, 0);
        W[11] = C_PAD_PLUS_S0 + W[4] + small1(W[9]);
        round(a, b, c, d, e, f, g, h, K_[12] + PAD, 0);
        W[12] = C_PAD_PLUS_S0 + W[5] + small1(W[10]);
        round(a, b, c, d, e, f, g, h, K_[13] + PAD, 0);
        W[13] = C_PAD_PLUS_S0 + W[6] + small1(W[11]);
        round(a, b, c, d, e, f, g, h, K_[14] + PAD, 0);
        W[14] = C_PAD_PLUS_S0 + W[7] + small1(W[12]);
        round(a, b, c, d, e, f, g, h, K_[15] + PAD, 0);
        W[15] = PAD + small0(W[0]) + W[8] + small1(W[13]);
        for (int r = 1; r < 5; ++r) {
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
    static void compress_pad128_64bytekey(const word key_words[8], word out[8]) noexcept {
        if (native_compressor() != nullptr) {
            std::array<word, 16> words;
            words.fill(PAD);
            for (unsigned i = 0; i < 8; ++i)
                words[i] = key_words[i] ^ PAD;
            auto state = IV_;
            compress_words(state, words.data());
            for (unsigned i = 0; i < 8; ++i)
                out[i] = state[i];
            return;
        }
        constexpr word C_S0_PAD = (std::rotr(PAD, 1) ^ std::rotr(PAD, 8) ^ (PAD >> 7));
        constexpr word C_S1_PAD = (std::rotr(PAD, 19) ^ std::rotr(PAD, 61) ^ (PAD >> 6));
        constexpr word C_PAD_PLUS_S0 = PAD + C_S0_PAD;
        constexpr word C_PAD_PLUS_S1 = PAD + C_S1_PAD;

        word W[16];
        for (int i = 0; i < 8; ++i) {
            W[i] = key_words[i] ^ PAD;
        }

        word a = IV_[0], b = IV_[1], c = IV_[2], d = IV_[3];
        word e = IV_[4], f = IV_[5], g = IV_[6], h = IV_[7];

        round(a, b, c, d, e, f, g, h, K_[0], W[0]);
        W[0] += small0(W[1]) + C_PAD_PLUS_S1;
        round(a, b, c, d, e, f, g, h, K_[1], W[1]);
        W[1] += small0(W[2]) + C_PAD_PLUS_S1;
        round(a, b, c, d, e, f, g, h, K_[2], W[2]);
        W[2] += small0(W[3]) + PAD + small1(W[0]);
        round(a, b, c, d, e, f, g, h, K_[3], W[3]);
        W[3] += small0(W[4]) + PAD + small1(W[1]);
        round(a, b, c, d, e, f, g, h, K_[4], W[4]);
        W[4] += small0(W[5]) + PAD + small1(W[2]);
        round(a, b, c, d, e, f, g, h, K_[5], W[5]);
        W[5] += small0(W[6]) + PAD + small1(W[3]);
        round(a, b, c, d, e, f, g, h, K_[6], W[6]);
        W[6] += small0(W[7]) + PAD + small1(W[4]);
        round(a, b, c, d, e, f, g, h, K_[7], W[7]);
        W[7] += C_S0_PAD + W[0] + small1(W[5]);

        round(a, b, c, d, e, f, g, h, K_[8] + PAD, 0);
        W[8] = C_PAD_PLUS_S0 + W[1] + small1(W[6]);
        round(a, b, c, d, e, f, g, h, K_[9] + PAD, 0);
        W[9] = C_PAD_PLUS_S0 + W[2] + small1(W[7]);
        round(a, b, c, d, e, f, g, h, K_[10] + PAD, 0);
        W[10] = C_PAD_PLUS_S0 + W[3] + small1(W[8]);
        round(a, b, c, d, e, f, g, h, K_[11] + PAD, 0);
        W[11] = C_PAD_PLUS_S0 + W[4] + small1(W[9]);
        round(a, b, c, d, e, f, g, h, K_[12] + PAD, 0);
        W[12] = C_PAD_PLUS_S0 + W[5] + small1(W[10]);
        round(a, b, c, d, e, f, g, h, K_[13] + PAD, 0);
        W[13] = C_PAD_PLUS_S0 + W[6] + small1(W[11]);
        round(a, b, c, d, e, f, g, h, K_[14] + PAD, 0);
        W[14] = C_PAD_PLUS_S0 + W[7] + small1(W[12]);
        round(a, b, c, d, e, f, g, h, K_[15] + PAD, 0);
        W[15] = PAD + small0(W[0]) + W[8] + small1(W[13]);
        for (int r = 1; r < 5; ++r) {
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

    // Disponibiliza a decisão do dispatcher para benchmarks e diagnósticos.
    static bool has_native_sha512() noexcept { return native_compressor() != nullptr; }

    static const char* native_backend_name() noexcept {
#if (defined(__x86_64__) || defined(__i386__)) && ((defined(__clang__) && __clang_major__ >= 17) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 14))
        return has_native_sha512() ? "x86-vsha512" : "software";
#elif defined(__aarch64__) && ((defined(__clang__) && __clang_major__ >= 14) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 9))
        return has_native_sha512() ? "arm64-sha512" : "software";
#else
        return "software";
#endif
    }

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

    void preset(const void* prefix, std::size_t prefix_len, const std::uint8_t suffix_len) noexcept {
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

            if (native_compressor() == nullptr)
                build_template_tables(block.data());
            else
                template_skip_ = 0;
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

        // if (native_compressor() != nullptr) {
        //     alignas(64) std::array<byte, block_size> block{};
        //     if (buffer_size_ != 0)
        //         std::memcpy(block.data(), buffer_.data(), buffer_size_);
        //     if (suffix_len != 0)
        //         std::memcpy(block.data() + buffer_size_, suffix, suffix_len);

        //     const std::size_t used = buffer_size_ + suffix_len;
        //     block[used] = 0x80;

        //     const std::uint64_t bytes = total_lo_ + static_cast<std::uint64_t>(suffix_len);
        //     const std::uint64_t high_bytes = total_hi_ + (bytes < total_lo_ ? 1u : 0u);
        //     const std::uint64_t bit_lo = bytes << 3;
        //     const std::uint64_t bit_hi = (high_bytes << 3) | (bytes >> 61);
        //     store_be64(block.data() + 112, bit_hi);
        //     store_be64(block.data() + 120, bit_lo);

        //     auto state = h_;
        //     compress(state, block.data());
        //     write_digest(state, out);
        //     return;
        // }

        alignas(64) std::array<word, 16> w = template_w_;

        if (suffix_len != 0) {
            const std::size_t first = buffer_size_;
            if (first == 0) {
                const auto* p = static_cast<const byte*>(suffix);
                const std::size_t word_count = suffix_len >> 3;
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
    // Tabelas K512 pré-broadcastadas em tempo de compilação (zero inicialização por chamada).
    // Antes: 80/160/240 broadcasts _mm_set1_epi64x eram executados a cada invocação
    // de complete_batch_*. Agora as constantes residem diretas em .rodata alinhadas.
    // O ctor recebe K_ por parâmetro: a tabela aninhada não pode usar membros da
    // classe externa em expressão constante antes da definição completa dela.
    struct K512_SSE_Table {
        alignas(16) std::uint64_t data[80][2];
        constexpr K512_SSE_Table(const std::array<word, 80>& K) : data{} {
            for (std::size_t i = 0; i < 80; ++i)
                data[i][0] = data[i][1] = K[i];
        }
    };

    void complete_batch_sse(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        static constexpr K512_SSE_Table k512_sse_tbl{K_};
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

        const __m128i* k_sse = reinterpret_cast<const __m128i*>(k512_sse_tbl.data);

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

        auto ror64 = [](__m128i x, int n) {
            return _mm_xor_si128(_mm_srli_epi64(x, n), _mm_slli_epi64(x, 64 - n));
        };
        auto ch_vec = [](__m128i x, __m128i y, __m128i z)
                          { return _mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128(y, z))); };
        auto maj_vec = [](__m128i x, __m128i y, __m128i z) {
            return _mm_xor_si128(_mm_and_si128(x, y), _mm_and_si128(z, _mm_xor_si128(x, y)));
        };
        auto s0_vec = [&](__m128i x) {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 1), _mm_shuffle_epi8(x, v_shuf_ror8)), _mm_srli_epi64(x, 7));
        };
        auto s1_vec = [&](__m128i x) {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 19), ror64(x, 61)), _mm_srli_epi64(x, 6));
        };
        auto big0_vec = [&](__m128i x) {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 28), ror64(x, 34)), ror64(x, 39));
        };
        auto big1_vec = [&](__m128i x) {
            return _mm_xor_si128(_mm_xor_si128(ror64(x, 14), ror64(x, 18)), ror64(x, 41));
        };

        auto round_step = [&](__m128i& a, __m128i& b, __m128i& c, __m128i& d, __m128i& e, __m128i& f, __m128i& g,
                              __m128i& h, __m128i k_term, __m128i w_val) {
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

            for (std::size_t w = w_start; suffix_len != 0 && w <= w_end; ++w) {
                W[w] = _mm_set_epi64x(lane_w[1][w], lane_w[0][w]);
            }

            __m128i a = mid_a, b = mid_b, c = mid_c, d = mid_d;
            __m128i e = mid_e, f = mid_f, g = mid_g, h = mid_h;

            for (std::uint32_t t = skip; t < 16; ++t) {
                round_step(a, b, c, d, e, f, g, h, k_sse[t], W[t]);
            }
            for (int r = 1; r < 5; ++r) {
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
    struct K512_AVX2_Table {
        alignas(32) std::uint64_t data[80][4];
        constexpr K512_AVX2_Table(const std::array<word, 80>& K) : data{} {
            for (std::size_t i = 0; i < 80; ++i)
                for (std::size_t j = 0; j < 4; ++j)
                    data[i][j] = K[i];
        }
    };

    void complete_batch_avx2(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        static constexpr K512_AVX2_Table k512_avx2_tbl{K_};
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

        const __m256i* k_avx2 = reinterpret_cast<const __m256i*>(k512_avx2_tbl.data);

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

        auto ror64 = [](__m256i x, int n) {
            return _mm256_xor_si256(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - n));
        };
        auto ch_vec = [](__m256i x, __m256i y, __m256i z) {
            return _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)));
        };
        auto maj_vec = [](__m256i x, __m256i y, __m256i z) {
            return _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_xor_si256(x, y)));
        };
        auto s0_vec = [&](__m256i x) {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 1), _mm256_shuffle_epi8(x, v_shuf_ror8)),
                                    _mm256_srli_epi64(x, 7));
        };
        auto s1_vec = [&](__m256i x) {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 19), ror64(x, 61)), _mm256_srli_epi64(x, 6));
        };
        auto big0_vec = [&](__m256i x) {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 28), ror64(x, 34)), ror64(x, 39));
        };
        auto big1_vec = [&](__m256i x) {
            return _mm256_xor_si256(_mm256_xor_si256(ror64(x, 14), ror64(x, 18)), ror64(x, 41));
        };

        auto round_step = [&](__m256i& a, __m256i& b, __m256i& c, __m256i& d, __m256i& e, __m256i& f, __m256i& g,
                              __m256i& h, __m256i k_term, __m256i w_val) {
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

            for (std::size_t w = w_start; suffix_len != 0 && w <= w_end; ++w) {
                W[w] = _mm256_set_epi64x(lane_w[3][w], lane_w[2][w], lane_w[1][w], lane_w[0][w]);
            }

            __m256i a = mid_a, b = mid_b, c = mid_c, d = mid_d;
            __m256i e = mid_e, f = mid_f, g = mid_g, h = mid_h;

            for (std::uint32_t t = skip; t < 16; ++t) {
                round_step(a, b, c, d, e, f, g, h, k_avx2[t], W[t]);
            }
            for (int r = 1; r < 5; ++r) {
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
    struct K512_AVX512_Table {
        alignas(64) std::uint64_t data[80][8];
        constexpr K512_AVX512_Table(const std::array<word, 80>& K) : data{} {
            for (std::size_t i = 0; i < 80; ++i)
                for (std::size_t j = 0; j < 8; ++j)
                    data[i][j] = K[i];
        }
    };

    void complete_batch_avx512(const void* suffixes, std::size_t stride, byte* out, std::size_t count) const noexcept {
        static constexpr K512_AVX512_Table k512_avx512_tbl{K_};
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

        const __m512i* k_avx512 = reinterpret_cast<const __m512i*>(k512_avx512_tbl.data);

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
                          { return _mm512_ternarylogic_epi64(x, y, z, 0xCA); };
        auto maj_vec = [](__m512i x, __m512i y, __m512i z)
                           { return _mm512_ternarylogic_epi64(x, y, z, 0xE8); };
        auto big0_vec = [](__m512i x) {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 28), _mm512_ror_epi64(x, 34), _mm512_ror_epi64(x, 39),
                                             0x96);
        };
        auto big1_vec = [](__m512i x) {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 14), _mm512_ror_epi64(x, 18), _mm512_ror_epi64(x, 41),
                                             0x96);
        };
        auto s0_vec = [](__m512i x) {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 1), _mm512_ror_epi64(x, 8), _mm512_srli_epi64(x, 7),
                                             0x96);
        };
        auto s1_vec = [](__m512i x) {
            return _mm512_ternarylogic_epi64(_mm512_ror_epi64(x, 19), _mm512_ror_epi64(x, 61), _mm512_srli_epi64(x, 6),
                                             0x96);
        };

        auto round_step = [&](__m512i& a, __m512i& b, __m512i& c, __m512i& d, __m512i& e, __m512i& f, __m512i& g,
                              __m512i& h, __m512i k_term, __m512i w_val) {
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

            for (std::size_t w = w_start; suffix_len != 0 && w <= w_end; ++w) {
                W[w] = _mm512_set_epi64(lane_w[7][w], lane_w[6][w], lane_w[5][w], lane_w[4][w], lane_w[3][w],
                                        lane_w[2][w], lane_w[1][w], lane_w[0][w]);
            }

            __m512i a = mid_a, b = mid_b, c = mid_c, d = mid_d;
            __m512i e = mid_e, f = mid_f, g = mid_g, h = mid_h;

            for (std::uint32_t t = skip; t < 16; ++t) {
                round_step(a, b, c, d, e, f, g, h, k_avx512[t], W[t]);
            }
            for (int r = 1; r < 5; ++r) {
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
        // if (native_compressor() != nullptr) {
        //     complete_batch_scalar(suffixes, stride, out, count);
        //     return;
        // }
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
}  // namespace crypto
