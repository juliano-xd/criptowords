#pragma once

#include <array>
#include <cstdint>
#include <cstring>

// ATENÇÃO: headers de sistema/chamadas a `#include` NUNCA podem ficar dentro de
// um namespace — incluí-los aqui corrompe a stdlib (ex.: "'abs' has not been
// declared in '::'") e esconde as intrínsecas do compilador.
#if defined(__SHA__)
# include <immintrin.h>
# if defined(__GNUC__)
#  include <stdint.h>
#  include <x86intrin.h>
# endif
# if defined(_MSC_VER)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
# endif
#endif

#ifndef FORCE_INLINE
#if defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define FORCE_INLINE inline __attribute__((always_inline))
#else
#define FORCE_INLINE inline
#endif
#endif

namespace cryptowords::detail {

inline void set_11bits(uint8_t* buf, size_t bit_offset, uint16_t val) {
    val &= 0x7FF;
    size_t byte_pos = bit_offset / 8;
    size_t bit_pos  = bit_offset % 8;

    uint32_t current = (static_cast<uint32_t>(buf[byte_pos]) << 16) |
                       (static_cast<uint32_t>(buf[byte_pos + 1]) << 8) |
                       (static_cast<uint32_t>(buf[byte_pos + 2]));

    uint32_t shift = 24 - 11 - bit_pos;
    uint32_t mask = (0x7FFu << shift);

    current = (current & ~mask) | (static_cast<uint32_t>(val) << shift);

    buf[byte_pos]     = static_cast<uint8_t>((current >> 16) & 0xFF);
    buf[byte_pos + 1] = static_cast<uint8_t>((current >> 8) & 0xFF);
    buf[byte_pos + 2] = static_cast<uint8_t>(current & 0xFF);
}

#if defined(__SHA__)
/* sha256-x86.c - Intel SHA extensions using C intrinsics  */
/*   Written and place in public domain by Jeffrey Walton  */
/*   Based on code from Intel, and by Sean Gulley for      */
/*   the miTLS project.                                    */

/* gcc -DTEST_MAIN -msse4.1 -msha sha256-x86.c -o sha256.exe   */

/* Microsoft supports Intel SHA ACLE extensions as of Visual Studio 2015 */
#if defined(_MSC_VER)
typedef UINT32 uint32_t;
typedef UINT8 uint8_t;
#endif

/* Process multiple blocks. The caller is responsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
inline void sha256_process_x86(uint32_t state[8], const uint8_t data[], uint32_t length)
{
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load initial values */
    TMP = _mm_loadu_si128((const __m128i*) &state[0]);
    STATE1 = _mm_loadu_si128((const __m128i*) &state[4]);


    TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

    while (length >= 64)
    {
        /* Save current state */
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* Rounds 0-3 */
        MSG = _mm_loadu_si128((const __m128i*) (data+0));
        MSG0 = _mm_shuffle_epi8(MSG, MASK);
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 4-7 */
        MSG1 = _mm_loadu_si128((const __m128i*) (data+16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 8-11 */
        MSG2 = _mm_loadu_si128((const __m128i*) (data+32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 12-15 */
        MSG3 = _mm_loadu_si128((const __m128i*) (data+48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 16-19 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 20-23 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 24-27 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 28-31 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 32-35 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 36-39 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 40-43 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 44-47 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 48-51 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 52-55 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 56-59 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 60-63 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Combine state  */
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        data += 64;
        length -= 64;
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

    /* Save state */
    _mm_storeu_si128((__m128i*) &state[0], STATE0);
    _mm_storeu_si128((__m128i*) &state[4], STATE1);
}


/* Specialized SHA-NI for BIP-39 with Mid-State Caching (OTM-18):
   MSG0, MSG2, MSG3 are invariant; only MSG1 changes per candidate */
FORCE_INLINE uint8_t sha256_bip39_msg1_variable_shani_reg(
    __m128i STATE0_r3, __m128i STATE1_r3,
    __m128i MSG0, __m128i MSG2, __m128i MSG3,
    __m128i ABEF_SAVE,
    __m128i MSG1)
{
    __m128i STATE0 = STATE0_r3;
    __m128i STATE1 = STATE1_r3;
    __m128i MSG, TMP;

    /* Rounds 4-7 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    __m128i M0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    __m128i M1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    M0 = _mm_add_epi32(M0, TMP);
    M0 = _mm_sha256msg2_epu32(M0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    __m128i M2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M0, MSG3, 4);
    M1 = _mm_add_epi32(M1, TMP);
    M1 = _mm_sha256msg2_epu32(M1, M0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    __m128i M3 = _mm_sha256msg1_epu32(MSG3, M0);

    /* Rounds 20-23 */
    MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M1, M0, 4);
    M2 = _mm_add_epi32(M2, TMP);
    M2 = _mm_sha256msg2_epu32(M2, M1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M0 = _mm_sha256msg1_epu32(M0, M1);

    /* Rounds 24-27 */
    MSG = _mm_add_epi32(M2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M2, M1, 4);
    M3 = _mm_add_epi32(M3, TMP);
    M3 = _mm_sha256msg2_epu32(M3, M2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M1 = _mm_sha256msg1_epu32(M1, M2);

    /* Rounds 28-31 */
    MSG = _mm_add_epi32(M3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M3, M2, 4);
    M0 = _mm_add_epi32(M0, TMP);
    M0 = _mm_sha256msg2_epu32(M0, M3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M2 = _mm_sha256msg1_epu32(M2, M3);

    /* Rounds 32-35 */
    MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M0, M3, 4);
    M1 = _mm_add_epi32(M1, TMP);
    M1 = _mm_sha256msg2_epu32(M1, M0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M3 = _mm_sha256msg1_epu32(M3, M0);

    /* Rounds 36-39 */
    MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M1, M0, 4);
    M2 = _mm_add_epi32(M2, TMP);
    M2 = _mm_sha256msg2_epu32(M2, M1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M0 = _mm_sha256msg1_epu32(M0, M1);

    /* Rounds 40-43 */
    MSG = _mm_add_epi32(M2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M2, M1, 4);
    M3 = _mm_add_epi32(M3, TMP);
    M3 = _mm_sha256msg2_epu32(M3, M2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M1 = _mm_sha256msg1_epu32(M1, M2);

    /* Rounds 44-47 */
    MSG = _mm_add_epi32(M3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M3, M2, 4);
    M0 = _mm_add_epi32(M0, TMP);
    M0 = _mm_sha256msg2_epu32(M0, M3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M2 = _mm_sha256msg1_epu32(M2, M3);

    /* Rounds 48-51 */
    MSG = _mm_add_epi32(M0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M0, M3, 4);
    M1 = _mm_add_epi32(M1, TMP);
    M1 = _mm_sha256msg2_epu32(M1, M0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    M3 = _mm_sha256msg1_epu32(M3, M0);

    /* Rounds 52-55 */
    MSG = _mm_add_epi32(M1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M1, M0, 4);
    M2 = _mm_add_epi32(M2, TMP);
    M2 = _mm_sha256msg2_epu32(M2, M1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 56-59 */
    MSG = _mm_add_epi32(M2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(M2, M1, 4);
    M3 = _mm_add_epi32(M3, TMP);
    M3 = _mm_sha256msg2_epu32(M3, M2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG = _mm_add_epi32(M3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Combine state */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    return static_cast<uint8_t>(_mm_extract_epi8(STATE0, 15));
}

FORCE_INLINE uint8_t sha256_bip39_msg1_variable_shani(
    __m128i STATE0_r3, __m128i STATE1_r3,
    __m128i MSG0, __m128i MSG2, __m128i MSG3,
    __m128i ABEF_SAVE,
    const uint8_t* data16)
{
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i MSG1 = _mm_loadu_si128((const __m128i*) data16);
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    return sha256_bip39_msg1_variable_shani_reg(
        STATE0_r3, STATE1_r3, MSG0, MSG2, MSG3, ABEF_SAVE, MSG1);
}

/* Specialized 2-Way Interleaved SHA-NI for BIP-39 (OTM-37):
   Hides 4-cycle execution latency by dual-dispatching 2 candidates simultaneously */
FORCE_INLINE void sha256_bip39_msg1_variable_shani_x2(
    __m128i STATE0_r3, __m128i STATE1_r3,
    __m128i MSG0, __m128i MSG2, __m128i MSG3,
    __m128i ABEF_SAVE,
    __m128i MSG1_A, __m128i MSG1_B,
    uint8_t& out_a, uint8_t& out_b)
{
    __m128i STATE0_A = STATE0_r3;
    __m128i STATE1_A = STATE1_r3;
    __m128i STATE0_B = STATE0_r3;
    __m128i STATE1_B = STATE1_r3;
    __m128i MSG_A, MSG_B, TMP_A, TMP_B;

    /* Rounds 4-7 */
    const __m128i K4 = _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL);
    MSG_A = _mm_add_epi32(MSG1_A, K4);
    MSG_B = _mm_add_epi32(MSG1_B, K4);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    __m128i M0_A = _mm_sha256msg1_epu32(MSG0, MSG1_A);
    __m128i M0_B = _mm_sha256msg1_epu32(MSG0, MSG1_B);

    /* Rounds 8-11 */
    const __m128i K8 = _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL);
    MSG_A = _mm_add_epi32(MSG2, K8);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_A);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_A);
    __m128i M1_A = _mm_sha256msg1_epu32(MSG1_A, MSG2);
    __m128i M1_B = _mm_sha256msg1_epu32(MSG1_B, MSG2);

    /* Rounds 12-15 */
    const __m128i K12 = _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL);
    MSG_A = _mm_add_epi32(MSG3, K12);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_A);
    const __m128i TMP_COMM = _mm_alignr_epi8(MSG3, MSG2, 4);
    M0_A = _mm_add_epi32(M0_A, TMP_COMM);
    M0_B = _mm_add_epi32(M0_B, TMP_COMM);
    M0_A = _mm_sha256msg2_epu32(M0_A, MSG3);
    M0_B = _mm_sha256msg2_epu32(M0_B, MSG3);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_A);
    const __m128i M2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    const __m128i K16 = _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL);
    MSG_A = _mm_add_epi32(M0_A, K16);
    MSG_B = _mm_add_epi32(M0_B, K16);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M0_A, MSG3, 4);
    TMP_B = _mm_alignr_epi8(M0_B, MSG3, 4);
    M1_A = _mm_add_epi32(M1_A, TMP_A);
    M1_B = _mm_add_epi32(M1_B, TMP_B);
    M1_A = _mm_sha256msg2_epu32(M1_A, M0_A);
    M1_B = _mm_sha256msg2_epu32(M1_B, M0_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    __m128i M3_A = _mm_sha256msg1_epu32(MSG3, M0_A);
    __m128i M3_B = _mm_sha256msg1_epu32(MSG3, M0_B);

    /* Rounds 20-23 */
    const __m128i K20 = _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL);
    MSG_A = _mm_add_epi32(M1_A, K20);
    MSG_B = _mm_add_epi32(M1_B, K20);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M1_A, M0_A, 4);
    TMP_B = _mm_alignr_epi8(M1_B, M0_B, 4);
    __m128i M2_A = _mm_add_epi32(M2, TMP_A);
    __m128i M2_B = _mm_add_epi32(M2, TMP_B);
    M2_A = _mm_sha256msg2_epu32(M2_A, M1_A);
    M2_B = _mm_sha256msg2_epu32(M2_B, M1_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M0_A = _mm_sha256msg1_epu32(M0_A, M1_A);
    M0_B = _mm_sha256msg1_epu32(M0_B, M1_B);

    /* Rounds 24-27 */
    const __m128i K24 = _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL);
    MSG_A = _mm_add_epi32(M2_A, K24);
    MSG_B = _mm_add_epi32(M2_B, K24);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M2_A, M1_A, 4);
    TMP_B = _mm_alignr_epi8(M2_B, M1_B, 4);
    M3_A = _mm_add_epi32(M3_A, TMP_A);
    M3_B = _mm_add_epi32(M3_B, TMP_B);
    M3_A = _mm_sha256msg2_epu32(M3_A, M2_A);
    M3_B = _mm_sha256msg2_epu32(M3_B, M2_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M1_A = _mm_sha256msg1_epu32(M1_A, M2_A);
    M1_B = _mm_sha256msg1_epu32(M1_B, M2_B);

    /* Rounds 28-31 */
    const __m128i K28 = _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL);
    MSG_A = _mm_add_epi32(M3_A, K28);
    MSG_B = _mm_add_epi32(M3_B, K28);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M3_A, M2_A, 4);
    TMP_B = _mm_alignr_epi8(M3_B, M2_B, 4);
    M0_A = _mm_add_epi32(M0_A, TMP_A);
    M0_B = _mm_add_epi32(M0_B, TMP_B);
    M0_A = _mm_sha256msg2_epu32(M0_A, M3_A);
    M0_B = _mm_sha256msg2_epu32(M0_B, M3_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M2_A = _mm_sha256msg1_epu32(M2_A, M3_A);
    M2_B = _mm_sha256msg1_epu32(M2_B, M3_B);

    /* Rounds 32-35 */
    const __m128i K32 = _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL);
    MSG_A = _mm_add_epi32(M0_A, K32);
    MSG_B = _mm_add_epi32(M0_B, K32);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M0_A, M3_A, 4);
    TMP_B = _mm_alignr_epi8(M0_B, M3_B, 4);
    M1_A = _mm_add_epi32(M1_A, TMP_A);
    M1_B = _mm_add_epi32(M1_B, TMP_B);
    M1_A = _mm_sha256msg2_epu32(M1_A, M0_A);
    M1_B = _mm_sha256msg2_epu32(M1_B, M0_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M3_A = _mm_sha256msg1_epu32(M3_A, M0_A);
    M3_B = _mm_sha256msg1_epu32(M3_B, M0_B);

    /* Rounds 36-39 */
    const __m128i K36 = _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL);
    MSG_A = _mm_add_epi32(M1_A, K36);
    MSG_B = _mm_add_epi32(M1_B, K36);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M1_A, M0_A, 4);
    TMP_B = _mm_alignr_epi8(M1_B, M0_B, 4);
    M2_A = _mm_add_epi32(M2_A, TMP_A);
    M2_B = _mm_add_epi32(M2_B, TMP_B);
    M2_A = _mm_sha256msg2_epu32(M2_A, M1_A);
    M2_B = _mm_sha256msg2_epu32(M2_B, M1_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M0_A = _mm_sha256msg1_epu32(M0_A, M1_A);
    M0_B = _mm_sha256msg1_epu32(M0_B, M1_B);

    /* Rounds 40-43 */
    const __m128i K40 = _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL);
    MSG_A = _mm_add_epi32(M2_A, K40);
    MSG_B = _mm_add_epi32(M2_B, K40);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M2_A, M1_A, 4);
    TMP_B = _mm_alignr_epi8(M2_B, M1_B, 4);
    M3_A = _mm_add_epi32(M3_A, TMP_A);
    M3_B = _mm_add_epi32(M3_B, TMP_B);
    M3_A = _mm_sha256msg2_epu32(M3_A, M2_A);
    M3_B = _mm_sha256msg2_epu32(M3_B, M2_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M1_A = _mm_sha256msg1_epu32(M1_A, M2_A);
    M1_B = _mm_sha256msg1_epu32(M1_B, M2_B);

    /* Rounds 44-47 */
    const __m128i K44 = _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL);
    MSG_A = _mm_add_epi32(M3_A, K44);
    MSG_B = _mm_add_epi32(M3_B, K44);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M3_A, M2_A, 4);
    TMP_B = _mm_alignr_epi8(M3_B, M2_B, 4);
    M0_A = _mm_add_epi32(M0_A, TMP_A);
    M0_B = _mm_add_epi32(M0_B, TMP_B);
    M0_A = _mm_sha256msg2_epu32(M0_A, M3_A);
    M0_B = _mm_sha256msg2_epu32(M0_B, M3_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M2_A = _mm_sha256msg1_epu32(M2_A, M3_A);
    M2_B = _mm_sha256msg1_epu32(M2_B, M3_B);

    /* Rounds 48-51 */
    const __m128i K48 = _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL);
    MSG_A = _mm_add_epi32(M0_A, K48);
    MSG_B = _mm_add_epi32(M0_B, K48);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M0_A, M3_A, 4);
    TMP_B = _mm_alignr_epi8(M0_B, M3_B, 4);
    M1_A = _mm_add_epi32(M1_A, TMP_A);
    M1_B = _mm_add_epi32(M1_B, TMP_B);
    M1_A = _mm_sha256msg2_epu32(M1_A, M0_A);
    M1_B = _mm_sha256msg2_epu32(M1_B, M0_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M3_A = _mm_sha256msg1_epu32(M3_A, M0_A);
    M3_B = _mm_sha256msg1_epu32(M3_B, M0_B);

    /* Rounds 52-55 */
    const __m128i K52 = _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL);
    MSG_A = _mm_add_epi32(M1_A, K52);
    MSG_B = _mm_add_epi32(M1_B, K52);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M1_A, M0_A, 4);
    TMP_B = _mm_alignr_epi8(M1_B, M0_B, 4);
    M2_A = _mm_add_epi32(M2_A, TMP_A);
    M2_B = _mm_add_epi32(M2_B, TMP_B);
    M2_A = _mm_sha256msg2_epu32(M2_A, M1_A);
    M2_B = _mm_sha256msg2_epu32(M2_B, M1_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Rounds 56-59 */
    const __m128i K56 = _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL);
    MSG_A = _mm_add_epi32(M2_A, K56);
    MSG_B = _mm_add_epi32(M2_B, K56);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M2_A, M1_A, 4);
    TMP_B = _mm_alignr_epi8(M2_B, M1_B, 4);
    M3_A = _mm_add_epi32(M3_A, TMP_A);
    M3_B = _mm_add_epi32(M3_B, TMP_B);
    M3_A = _mm_sha256msg2_epu32(M3_A, M2_A);
    M3_B = _mm_sha256msg2_epu32(M3_B, M2_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Rounds 60-63 */
    const __m128i K60 = _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL);
    MSG_A = _mm_add_epi32(M3_A, K60);
    MSG_B = _mm_add_epi32(M3_B, K60);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Combine state */
    STATE0_A = _mm_add_epi32(STATE0_A, ABEF_SAVE);
    STATE0_B = _mm_add_epi32(STATE0_B, ABEF_SAVE);
    out_a = static_cast<uint8_t>(_mm_extract_epi8(STATE0_A, 15));
    out_b = static_cast<uint8_t>(_mm_extract_epi8(STATE0_B, 15));
}

/* Specialized 2-Way Interleaved SHA-NI for BIP-39 where MSG0 is variable (OTM-37 / OTM-38):
   Used for 12-word mnemonics where word 10 falls entirely in MSG0 (bytes 0..15).
   MSG1, MSG2, MSG3 are invariant. */
FORCE_INLINE void sha256_bip39_msg0_variable_shani_x2(
    __m128i MSG1, __m128i MSG2, __m128i MSG3,
    __m128i MSG0_A, __m128i MSG0_B,
    uint8_t& out_a, uint8_t& out_b)
{
    const __m128i ABEF_SAVE = _mm_set_epi32(0x6a09e667, 0xbb67ae85, 0x510e527f, 0x9b05688c);
    const __m128i INIT_CDGH = _mm_set_epi32(0x3c6ef372, 0xa54ff53a, 0x1f83d9ab, 0x5be0cd19);

    __m128i STATE0_A = ABEF_SAVE;
    __m128i STATE1_A = INIT_CDGH;
    __m128i STATE0_B = ABEF_SAVE;
    __m128i STATE1_B = INIT_CDGH;
    __m128i MSG_A, MSG_B, TMP_A, TMP_B;

    /* Rounds 0-3 */
    const __m128i K0 = _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL);
    MSG_A = _mm_add_epi32(MSG0_A, K0);
    MSG_B = _mm_add_epi32(MSG0_B, K0);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Rounds 4-7 */
    const __m128i K4 = _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL);
    MSG_A = _mm_add_epi32(MSG1, K4);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_A);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_A);
    __m128i M0_A = _mm_sha256msg1_epu32(MSG0_A, MSG1);
    __m128i M0_B = _mm_sha256msg1_epu32(MSG0_B, MSG1);

    /* Rounds 8-11 */
    const __m128i K8 = _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL);
    MSG_A = _mm_add_epi32(MSG2, K8);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_A);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_A);
    const __m128i M1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    const __m128i K12 = _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL);
    MSG_A = _mm_add_epi32(MSG3, K12);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_A);
    const __m128i TMP_COMM = _mm_alignr_epi8(MSG3, MSG2, 4);
    M0_A = _mm_add_epi32(M0_A, TMP_COMM);
    M0_B = _mm_add_epi32(M0_B, TMP_COMM);
    M0_A = _mm_sha256msg2_epu32(M0_A, MSG3);
    M0_B = _mm_sha256msg2_epu32(M0_B, MSG3);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_A);
    const __m128i M2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    const __m128i K16 = _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL);
    MSG_A = _mm_add_epi32(M0_A, K16);
    MSG_B = _mm_add_epi32(M0_B, K16);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M0_A, MSG3, 4);
    TMP_B = _mm_alignr_epi8(M0_B, MSG3, 4);
    __m128i M1_A = _mm_add_epi32(M1, TMP_A);
    __m128i M1_B = _mm_add_epi32(M1, TMP_B);
    M1_A = _mm_sha256msg2_epu32(M1_A, M0_A);
    M1_B = _mm_sha256msg2_epu32(M1_B, M0_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    __m128i M3_A = _mm_sha256msg1_epu32(MSG3, M0_A);
    __m128i M3_B = _mm_sha256msg1_epu32(MSG3, M0_B);

    /* Rounds 20-23 */
    const __m128i K20 = _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL);
    MSG_A = _mm_add_epi32(M1_A, K20);
    MSG_B = _mm_add_epi32(M1_B, K20);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M1_A, M0_A, 4);
    TMP_B = _mm_alignr_epi8(M1_B, M0_B, 4);
    __m128i M2_A = _mm_add_epi32(M2, TMP_A);
    __m128i M2_B = _mm_add_epi32(M2, TMP_B);
    M2_A = _mm_sha256msg2_epu32(M2_A, M1_A);
    M2_B = _mm_sha256msg2_epu32(M2_B, M1_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M0_A = _mm_sha256msg1_epu32(M0_A, M1_A);
    M0_B = _mm_sha256msg1_epu32(M0_B, M1_B);

    /* Rounds 24-27 */
    const __m128i K24 = _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL);
    MSG_A = _mm_add_epi32(M2_A, K24);
    MSG_B = _mm_add_epi32(M2_B, K24);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M2_A, M1_A, 4);
    TMP_B = _mm_alignr_epi8(M2_B, M1_B, 4);
    M3_A = _mm_add_epi32(M3_A, TMP_A);
    M3_B = _mm_add_epi32(M3_B, TMP_B);
    M3_A = _mm_sha256msg2_epu32(M3_A, M2_A);
    M3_B = _mm_sha256msg2_epu32(M3_B, M2_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M1_A = _mm_sha256msg1_epu32(M1_A, M2_A);
    M1_B = _mm_sha256msg1_epu32(M1_B, M2_B);

    /* Rounds 28-31 */
    const __m128i K28 = _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL);
    MSG_A = _mm_add_epi32(M3_A, K28);
    MSG_B = _mm_add_epi32(M3_B, K28);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M3_A, M2_A, 4);
    TMP_B = _mm_alignr_epi8(M3_B, M2_B, 4);
    M0_A = _mm_add_epi32(M0_A, TMP_A);
    M0_B = _mm_add_epi32(M0_B, TMP_B);
    M0_A = _mm_sha256msg2_epu32(M0_A, M3_A);
    M0_B = _mm_sha256msg2_epu32(M0_B, M3_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M2_A = _mm_sha256msg1_epu32(M2_A, M3_A);
    M2_B = _mm_sha256msg1_epu32(M2_B, M3_B);

    /* Rounds 32-35 */
    const __m128i K32 = _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL);
    MSG_A = _mm_add_epi32(M0_A, K32);
    MSG_B = _mm_add_epi32(M0_B, K32);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M0_A, M3_A, 4);
    TMP_B = _mm_alignr_epi8(M0_B, M3_B, 4);
    M1_A = _mm_add_epi32(M1_A, TMP_A);
    M1_B = _mm_add_epi32(M1_B, TMP_B);
    M1_A = _mm_sha256msg2_epu32(M1_A, M0_A);
    M1_B = _mm_sha256msg2_epu32(M1_B, M0_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M3_A = _mm_sha256msg1_epu32(M3_A, M0_A);
    M3_B = _mm_sha256msg1_epu32(M3_B, M0_B);

    /* Rounds 36-39 */
    const __m128i K36 = _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL);
    MSG_A = _mm_add_epi32(M1_A, K36);
    MSG_B = _mm_add_epi32(M1_B, K36);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M1_A, M0_A, 4);
    TMP_B = _mm_alignr_epi8(M1_B, M0_B, 4);
    M2_A = _mm_add_epi32(M2_A, TMP_A);
    M2_B = _mm_add_epi32(M2_B, TMP_B);
    M2_A = _mm_sha256msg2_epu32(M2_A, M1_A);
    M2_B = _mm_sha256msg2_epu32(M2_B, M1_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M0_A = _mm_sha256msg1_epu32(M0_A, M1_A);
    M0_B = _mm_sha256msg1_epu32(M0_B, M1_B);

    /* Rounds 40-43 */
    const __m128i K40 = _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL);
    MSG_A = _mm_add_epi32(M2_A, K40);
    MSG_B = _mm_add_epi32(M2_B, K40);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M2_A, M1_A, 4);
    TMP_B = _mm_alignr_epi8(M2_B, M1_B, 4);
    M3_A = _mm_add_epi32(M3_A, TMP_A);
    M3_B = _mm_add_epi32(M3_B, TMP_B);
    M3_A = _mm_sha256msg2_epu32(M3_A, M2_A);
    M3_B = _mm_sha256msg2_epu32(M3_B, M2_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M1_A = _mm_sha256msg1_epu32(M1_A, M2_A);
    M1_B = _mm_sha256msg1_epu32(M1_B, M2_B);

    /* Rounds 44-47 */
    const __m128i K44 = _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL);
    MSG_A = _mm_add_epi32(M3_A, K44);
    MSG_B = _mm_add_epi32(M3_B, K44);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M3_A, M2_A, 4);
    TMP_B = _mm_alignr_epi8(M3_B, M2_B, 4);
    M0_A = _mm_add_epi32(M0_A, TMP_A);
    M0_B = _mm_add_epi32(M0_B, TMP_B);
    M0_A = _mm_sha256msg2_epu32(M0_A, M3_A);
    M0_B = _mm_sha256msg2_epu32(M0_B, M3_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M2_A = _mm_sha256msg1_epu32(M2_A, M3_A);
    M2_B = _mm_sha256msg1_epu32(M2_B, M3_B);

    /* Rounds 48-51 */
    const __m128i K48 = _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL);
    MSG_A = _mm_add_epi32(M0_A, K48);
    MSG_B = _mm_add_epi32(M0_B, K48);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M0_A, M3_A, 4);
    TMP_B = _mm_alignr_epi8(M0_B, M3_B, 4);
    M1_A = _mm_add_epi32(M1_A, TMP_A);
    M1_B = _mm_add_epi32(M1_B, TMP_B);
    M1_A = _mm_sha256msg2_epu32(M1_A, M0_A);
    M1_B = _mm_sha256msg2_epu32(M1_B, M0_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);
    M3_A = _mm_sha256msg1_epu32(M3_A, M0_A);
    M3_B = _mm_sha256msg1_epu32(M3_B, M0_B);

    /* Rounds 52-55 */
    const __m128i K52 = _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL);
    MSG_A = _mm_add_epi32(M1_A, K52);
    MSG_B = _mm_add_epi32(M1_B, K52);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M1_A, M0_A, 4);
    TMP_B = _mm_alignr_epi8(M1_B, M0_B, 4);
    M2_A = _mm_add_epi32(M2_A, TMP_A);
    M2_B = _mm_add_epi32(M2_B, TMP_B);
    M2_A = _mm_sha256msg2_epu32(M2_A, M1_A);
    M2_B = _mm_sha256msg2_epu32(M2_B, M1_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Rounds 56-59 */
    const __m128i K56 = _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL);
    MSG_A = _mm_add_epi32(M2_A, K56);
    MSG_B = _mm_add_epi32(M2_B, K56);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    TMP_A = _mm_alignr_epi8(M2_A, M1_A, 4);
    TMP_B = _mm_alignr_epi8(M2_B, M1_B, 4);
    M3_A = _mm_add_epi32(M3_A, TMP_A);
    M3_B = _mm_add_epi32(M3_B, TMP_B);
    M3_A = _mm_sha256msg2_epu32(M3_A, M2_A);
    M3_B = _mm_sha256msg2_epu32(M3_B, M2_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Rounds 60-63 */
    const __m128i K60 = _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL);
    MSG_A = _mm_add_epi32(M3_A, K60);
    MSG_B = _mm_add_epi32(M3_B, K60);
    STATE1_A = _mm_sha256rnds2_epu32(STATE1_A, STATE0_A, MSG_A);
    STATE1_B = _mm_sha256rnds2_epu32(STATE1_B, STATE0_B, MSG_B);
    MSG_A = _mm_shuffle_epi32(MSG_A, 0x0E);
    MSG_B = _mm_shuffle_epi32(MSG_B, 0x0E);
    STATE0_A = _mm_sha256rnds2_epu32(STATE0_A, STATE1_A, MSG_A);
    STATE0_B = _mm_sha256rnds2_epu32(STATE0_B, STATE1_B, MSG_B);

    /* Combine state */
    STATE0_A = _mm_add_epi32(STATE0_A, ABEF_SAVE);
    STATE0_B = _mm_add_epi32(STATE0_B, ABEF_SAVE);
    out_a = static_cast<uint8_t>(_mm_extract_epi8(STATE0_A, 15));
    out_b = static_cast<uint8_t>(_mm_extract_epi8(STATE0_B, 15));
}

FORCE_INLINE uint8_t sha256_bip39_msg0_variable_shani_reg(
    __m128i MSG1, __m128i MSG2, __m128i MSG3,
    __m128i MSG0)
{
    uint8_t out_a, out_b;
    sha256_bip39_msg0_variable_shani_x2(MSG1, MSG2, MSG3, MSG0, MSG0, out_a, out_b);
    return out_a;
}

FORCE_INLINE uint8_t sha256_bip39_first_byte_shani(const uint8_t block64[64]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_process_x86(state, block64, 64);
    return static_cast<uint8_t>(state[0] >> 24);
}
#endif

} // namespace cryptowords::detail
