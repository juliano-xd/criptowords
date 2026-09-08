#pragma once
#include "sha512_simd.hpp"
#include <cstring>

__attribute__((always_inline))
inline void pbkdf2_hmac_sha512_4way_sse(
    const char* p1, size_t l1,     const char* p2, size_t l2,     const char* p3, size_t l3,     const char* p4, size_t l4, 
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64])
{
    uint64_t W1[16][2] = {0};
    uint64_t T1[8][2] = {0};
    uint64_t W2[16][2] = {0};
    uint64_t T2[8][2] = {0};

    auto populate_W = [&](const char* pass, size_t len, int lane, uint64_t W_ipad[16][2], uint64_t W_opad[16][2]) {
        uint8_t K[128] = {0};
        if (len > 128) { /* omitted for bip39 */ }
        else { memcpy(K, pass, len); }
        
        uint8_t k_ipad[128], k_opad[128];
        for (int i = 0; i < 128; i++) {
            k_ipad[i] = K[i] ^ 0x36;
            k_opad[i] = K[i] ^ 0x5c;
        }

        uint64_t blk[16];
        memcpy(blk, k_ipad, 128);
        for (int w = 0; w < 16; w++) W_ipad[w][lane] = __builtin_bswap64(blk[w]);

        memcpy(blk, k_opad, 128);
        for (int w = 0; w < 16; w++) W_opad[w][lane] = __builtin_bswap64(blk[w]);
    };
    SHA512_SSE_State ipad1, opad1;
    sha512_init_sse(&ipad1); sha512_init_sse(&opad1);
    SHA512_SSE_State ipad2, opad2;
    sha512_init_sse(&ipad2); sha512_init_sse(&opad2);
    uint64_t W_ipad1[16][2] = {0};
    uint64_t W_opad1[16][2] = {0};
    populate_W(p1, l1, 0, W_ipad1, W_opad1);
    populate_W(p2, l2, 1, W_ipad1, W_opad1);
    sha512_transform_sse(&ipad1, W_ipad1);
    sha512_transform_sse(&opad1, W_opad1);
    uint64_t W_ipad2[16][2] = {0};
    uint64_t W_opad2[16][2] = {0};
    populate_W(p3, l3, 0, W_ipad2, W_opad2);
    populate_W(p4, l4, 1, W_ipad2, W_opad2);
    sha512_transform_sse(&ipad2, W_ipad2);
    sha512_transform_sse(&opad2, W_opad2);

    uint64_t msg1[16][2] = {0};
    uint64_t msg2[16][2] = {0};

    uint8_t salt1[128] = {0};
    memcpy(salt1, salt, salt_len);
    salt1[salt_len] = 0; salt1[salt_len+1] = 0; salt1[salt_len+2] = 0; salt1[salt_len+3] = 1;
    salt1[salt_len+4] = 0x80;
    
    uint64_t s_blk[16]; memcpy(s_blk, salt1, 128);
    for(int w=0; w<15; w++) {
        uint64_t v_swp = __builtin_bswap64(s_blk[w]);
        for(int l=0; l<2; l++) msg1[w][l] = v_swp;
        for(int l=0; l<2; l++) msg2[w][l] = v_swp;
    }
    for(int l=0; l<2; l++) msg1[15][l] = (128 + salt_len + 4) * 8;
    for(int l=0; l<2; l++) msg2[15][l] = (128 + salt_len + 4) * 8;

    SHA512_SSE_State s1 = ipad1;
    sha512_transform_sse(&s1, msg1);
    SHA512_SSE_State s2 = ipad2;
    sha512_transform_sse(&s2, msg2);
    for(int w=0; w<16; w++) for(int l=0; l<2; l++) msg1[w][l] = 0;
    for(int l=0; l<2; l++) msg1[15][l] = (128 + 64) * 8;
    for(int i=0; i<8; i++) for(int l=0; l<2; l++) msg1[i][l] = s1.state[i][l];
    msg1[8][0] = 0x8000000000000000ULL;
    msg1[8][1] = msg1[8][0];
    for(int w=0; w<16; w++) for(int l=0; l<2; l++) msg2[w][l] = 0;
    for(int l=0; l<2; l++) msg2[15][l] = (128 + 64) * 8;
    for(int i=0; i<8; i++) for(int l=0; l<2; l++) msg2[i][l] = s2.state[i][l];
    msg2[8][0] = 0x8000000000000000ULL;
    msg2[8][1] = msg2[8][0];

    SHA512_SSE_State o1 = opad1;
    sha512_transform_sse(&o1, msg1);
    for(int i=0; i<8; i++) for(int l=0; l<2; l++) T1[i][l] = o1.state[i][l];
    SHA512_SSE_State o2 = opad2;
    sha512_transform_sse(&o2, msg2);
    for(int i=0; i<8; i++) for(int l=0; l<2; l++) T2[i][l] = o2.state[i][l];
    uint64_t U1[16][2] = {0};
    for(int l=0; l<2; l++) U1[15][l] = (128 + 64) * 8;
    U1[8][0] = 0x8000000000000000ULL;
    U1[8][1] = U1[8][0];
    uint64_t U2[16][2] = {0};
    for(int l=0; l<2; l++) U2[15][l] = (128 + 64) * 8;
    U2[8][0] = 0x8000000000000000ULL;
    U2[8][1] = U2[8][0];
    for(uint32_t iter = 1; iter < iterations; ++iter) {
        for(int i=0; i<8; i++) for(int l=0; l<2; l++) U1[i][l] = o1.state[i][l];
        s1 = ipad1;
        sha512_transform_sse(&s1, U1);
        for(int i=0; i<8; i++) for(int l=0; l<2; l++) U1[i][l] = s1.state[i][l];
        o1 = opad1;
        sha512_transform_sse(&o1, U1);
        for(int i=0; i<8; i++) for(int l=0; l<2; l++) T1[i][l] ^= o1.state[i][l];
        for(int i=0; i<8; i++) for(int l=0; l<2; l++) U2[i][l] = o2.state[i][l];
        s2 = ipad2;
        sha512_transform_sse(&s2, U2);
        for(int i=0; i<8; i++) for(int l=0; l<2; l++) U2[i][l] = s2.state[i][l];
        o2 = opad2;
        sha512_transform_sse(&o2, U2);
        for(int i=0; i<8; i++) for(int l=0; l<2; l++) T2[i][l] ^= o2.state[i][l];
    }

    for(int i = 0; i < 8; i++) {
        uint64_t b1 = __builtin_bswap64(T1[i][0]);
        memcpy(out1 + i*8, &b1, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b2 = __builtin_bswap64(T1[i][1]);
        memcpy(out2 + i*8, &b2, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b3 = __builtin_bswap64(T2[i][0]);
        memcpy(out3 + i*8, &b3, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b4 = __builtin_bswap64(T2[i][1]);
        memcpy(out4 + i*8, &b4, 8);
    }
}

__attribute__((always_inline))
inline void pbkdf2_hmac_sha512_8way_avx2(
    const char* p1, size_t l1,     const char* p2, size_t l2,     const char* p3, size_t l3,     const char* p4, size_t l4,     const char* p5, size_t l5,     const char* p6, size_t l6,     const char* p7, size_t l7,     const char* p8, size_t l8, 
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64], uint8_t out5[64], uint8_t out6[64], uint8_t out7[64], uint8_t out8[64])
{
    uint64_t W1[16][4] = {0};
    uint64_t T1[8][4] = {0};
    uint64_t W2[16][4] = {0};
    uint64_t T2[8][4] = {0};

    auto populate_W = [&](const char* pass, size_t len, int lane, uint64_t W_ipad[16][4], uint64_t W_opad[16][4]) {
        uint8_t K[128] = {0};
        if (len > 128) { /* omitted for bip39 */ }
        else { memcpy(K, pass, len); }
        
        uint8_t k_ipad[128], k_opad[128];
        for (int i = 0; i < 128; i++) {
            k_ipad[i] = K[i] ^ 0x36;
            k_opad[i] = K[i] ^ 0x5c;
        }

        uint64_t blk[16];
        memcpy(blk, k_ipad, 128);
        for (int w = 0; w < 16; w++) W_ipad[w][lane] = __builtin_bswap64(blk[w]);

        memcpy(blk, k_opad, 128);
        for (int w = 0; w < 16; w++) W_opad[w][lane] = __builtin_bswap64(blk[w]);
    };
    SHA512_AVX2_State ipad1, opad1;
    sha512_init_avx2(&ipad1); sha512_init_avx2(&opad1);
    SHA512_AVX2_State ipad2, opad2;
    sha512_init_avx2(&ipad2); sha512_init_avx2(&opad2);
    uint64_t W_ipad1[16][4] = {0};
    uint64_t W_opad1[16][4] = {0};
    populate_W(p1, l1, 0, W_ipad1, W_opad1);
    populate_W(p2, l2, 1, W_ipad1, W_opad1);
    populate_W(p3, l3, 2, W_ipad1, W_opad1);
    populate_W(p4, l4, 3, W_ipad1, W_opad1);
    sha512_transform_avx2(&ipad1, W_ipad1);
    sha512_transform_avx2(&opad1, W_opad1);
    uint64_t W_ipad2[16][4] = {0};
    uint64_t W_opad2[16][4] = {0};
    populate_W(p5, l5, 0, W_ipad2, W_opad2);
    populate_W(p6, l6, 1, W_ipad2, W_opad2);
    populate_W(p7, l7, 2, W_ipad2, W_opad2);
    populate_W(p8, l8, 3, W_ipad2, W_opad2);
    sha512_transform_avx2(&ipad2, W_ipad2);
    sha512_transform_avx2(&opad2, W_opad2);

    uint64_t msg1[16][4] = {0};
    uint64_t msg2[16][4] = {0};

    uint8_t salt1[128] = {0};
    memcpy(salt1, salt, salt_len);
    salt1[salt_len] = 0; salt1[salt_len+1] = 0; salt1[salt_len+2] = 0; salt1[salt_len+3] = 1;
    salt1[salt_len+4] = 0x80;
    
    uint64_t s_blk[16]; memcpy(s_blk, salt1, 128);
    for(int w=0; w<15; w++) {
        uint64_t v_swp = __builtin_bswap64(s_blk[w]);
        for(int l=0; l<4; l++) msg1[w][l] = v_swp;
        for(int l=0; l<4; l++) msg2[w][l] = v_swp;
    }
    for(int l=0; l<4; l++) msg1[15][l] = (128 + salt_len + 4) * 8;
    for(int l=0; l<4; l++) msg2[15][l] = (128 + salt_len + 4) * 8;

    SHA512_AVX2_State s1 = ipad1;
    sha512_transform_avx2(&s1, msg1);
    SHA512_AVX2_State s2 = ipad2;
    sha512_transform_avx2(&s2, msg2);
    for(int w=0; w<16; w++) for(int l=0; l<4; l++) msg1[w][l] = 0;
    for(int l=0; l<4; l++) msg1[15][l] = (128 + 64) * 8;
    for(int i=0; i<8; i++) for(int l=0; l<4; l++) msg1[i][l] = s1.state[i][l];
    msg1[8][0] = 0x8000000000000000ULL;
    msg1[8][1] = msg1[8][0];
    msg1[8][2] = msg1[8][0];
    msg1[8][3] = msg1[8][0];
    for(int w=0; w<16; w++) for(int l=0; l<4; l++) msg2[w][l] = 0;
    for(int l=0; l<4; l++) msg2[15][l] = (128 + 64) * 8;
    for(int i=0; i<8; i++) for(int l=0; l<4; l++) msg2[i][l] = s2.state[i][l];
    msg2[8][0] = 0x8000000000000000ULL;
    msg2[8][1] = msg2[8][0];
    msg2[8][2] = msg2[8][0];
    msg2[8][3] = msg2[8][0];

    SHA512_AVX2_State o1 = opad1;
    sha512_transform_avx2(&o1, msg1);
    for(int i=0; i<8; i++) for(int l=0; l<4; l++) T1[i][l] = o1.state[i][l];
    SHA512_AVX2_State o2 = opad2;
    sha512_transform_avx2(&o2, msg2);
    for(int i=0; i<8; i++) for(int l=0; l<4; l++) T2[i][l] = o2.state[i][l];
    uint64_t U1[16][4] = {0};
    for(int l=0; l<4; l++) U1[15][l] = (128 + 64) * 8;
    U1[8][0] = 0x8000000000000000ULL;
    U1[8][1] = U1[8][0];
    U1[8][2] = U1[8][0];
    U1[8][3] = U1[8][0];
    uint64_t U2[16][4] = {0};
    for(int l=0; l<4; l++) U2[15][l] = (128 + 64) * 8;
    U2[8][0] = 0x8000000000000000ULL;
    U2[8][1] = U2[8][0];
    U2[8][2] = U2[8][0];
    U2[8][3] = U2[8][0];
    for(uint32_t iter = 1; iter < iterations; ++iter) {
        for(int i=0; i<8; i++) for(int l=0; l<4; l++) U1[i][l] = o1.state[i][l];
        s1 = ipad1;
        sha512_transform_avx2(&s1, U1);
        for(int i=0; i<8; i++) for(int l=0; l<4; l++) U1[i][l] = s1.state[i][l];
        o1 = opad1;
        sha512_transform_avx2(&o1, U1);
        for(int i=0; i<8; i++) for(int l=0; l<4; l++) T1[i][l] ^= o1.state[i][l];
        for(int i=0; i<8; i++) for(int l=0; l<4; l++) U2[i][l] = o2.state[i][l];
        s2 = ipad2;
        sha512_transform_avx2(&s2, U2);
        for(int i=0; i<8; i++) for(int l=0; l<4; l++) U2[i][l] = s2.state[i][l];
        o2 = opad2;
        sha512_transform_avx2(&o2, U2);
        for(int i=0; i<8; i++) for(int l=0; l<4; l++) T2[i][l] ^= o2.state[i][l];
    }

    for(int i = 0; i < 8; i++) {
        uint64_t b1 = __builtin_bswap64(T1[i][0]);
        memcpy(out1 + i*8, &b1, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b2 = __builtin_bswap64(T1[i][1]);
        memcpy(out2 + i*8, &b2, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b3 = __builtin_bswap64(T1[i][2]);
        memcpy(out3 + i*8, &b3, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b4 = __builtin_bswap64(T1[i][3]);
        memcpy(out4 + i*8, &b4, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b5 = __builtin_bswap64(T2[i][0]);
        memcpy(out5 + i*8, &b5, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b6 = __builtin_bswap64(T2[i][1]);
        memcpy(out6 + i*8, &b6, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b7 = __builtin_bswap64(T2[i][2]);
        memcpy(out7 + i*8, &b7, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b8 = __builtin_bswap64(T2[i][3]);
        memcpy(out8 + i*8, &b8, 8);
    }
}

__attribute__((always_inline))
inline void pbkdf2_hmac_sha512_16way_avx512(
    const char* p1, size_t l1,     const char* p2, size_t l2,     const char* p3, size_t l3,     const char* p4, size_t l4,     const char* p5, size_t l5,     const char* p6, size_t l6,     const char* p7, size_t l7,     const char* p8, size_t l8,     const char* p9, size_t l9,     const char* p10, size_t l10,     const char* p11, size_t l11,     const char* p12, size_t l12,     const char* p13, size_t l13,     const char* p14, size_t l14,     const char* p15, size_t l15,     const char* p16, size_t l16, 
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out1[64], uint8_t out2[64], uint8_t out3[64], uint8_t out4[64], uint8_t out5[64], uint8_t out6[64], uint8_t out7[64], uint8_t out8[64], uint8_t out9[64], uint8_t out10[64], uint8_t out11[64], uint8_t out12[64], uint8_t out13[64], uint8_t out14[64], uint8_t out15[64], uint8_t out16[64])
{
    uint64_t W1[16][8] = {0};
    uint64_t T1[8][8] = {0};
    uint64_t W2[16][8] = {0};
    uint64_t T2[8][8] = {0};

    auto populate_W = [&](const char* pass, size_t len, int lane, uint64_t W_ipad[16][8], uint64_t W_opad[16][8]) {
        uint8_t K[128] = {0};
        if (len > 128) { /* omitted for bip39 */ }
        else { memcpy(K, pass, len); }
        
        uint8_t k_ipad[128], k_opad[128];
        for (int i = 0; i < 128; i++) {
            k_ipad[i] = K[i] ^ 0x36;
            k_opad[i] = K[i] ^ 0x5c;
        }

        uint64_t blk[16];
        memcpy(blk, k_ipad, 128);
        for (int w = 0; w < 16; w++) W_ipad[w][lane] = __builtin_bswap64(blk[w]);

        memcpy(blk, k_opad, 128);
        for (int w = 0; w < 16; w++) W_opad[w][lane] = __builtin_bswap64(blk[w]);
    };
    SHA512_AVX512_State ipad1, opad1;
    sha512_init_avx512(&ipad1); sha512_init_avx512(&opad1);
    SHA512_AVX512_State ipad2, opad2;
    sha512_init_avx512(&ipad2); sha512_init_avx512(&opad2);
    uint64_t W_ipad1[16][8] = {0};
    uint64_t W_opad1[16][8] = {0};
    populate_W(p1, l1, 0, W_ipad1, W_opad1);
    populate_W(p2, l2, 1, W_ipad1, W_opad1);
    populate_W(p3, l3, 2, W_ipad1, W_opad1);
    populate_W(p4, l4, 3, W_ipad1, W_opad1);
    populate_W(p5, l5, 4, W_ipad1, W_opad1);
    populate_W(p6, l6, 5, W_ipad1, W_opad1);
    populate_W(p7, l7, 6, W_ipad1, W_opad1);
    populate_W(p8, l8, 7, W_ipad1, W_opad1);
    sha512_transform_avx512(&ipad1, W_ipad1);
    sha512_transform_avx512(&opad1, W_opad1);
    uint64_t W_ipad2[16][8] = {0};
    uint64_t W_opad2[16][8] = {0};
    populate_W(p9, l9, 0, W_ipad2, W_opad2);
    populate_W(p10, l10, 1, W_ipad2, W_opad2);
    populate_W(p11, l11, 2, W_ipad2, W_opad2);
    populate_W(p12, l12, 3, W_ipad2, W_opad2);
    populate_W(p13, l13, 4, W_ipad2, W_opad2);
    populate_W(p14, l14, 5, W_ipad2, W_opad2);
    populate_W(p15, l15, 6, W_ipad2, W_opad2);
    populate_W(p16, l16, 7, W_ipad2, W_opad2);
    sha512_transform_avx512(&ipad2, W_ipad2);
    sha512_transform_avx512(&opad2, W_opad2);

    uint64_t msg1[16][8] = {0};
    uint64_t msg2[16][8] = {0};

    uint8_t salt1[128] = {0};
    memcpy(salt1, salt, salt_len);
    salt1[salt_len] = 0; salt1[salt_len+1] = 0; salt1[salt_len+2] = 0; salt1[salt_len+3] = 1;
    salt1[salt_len+4] = 0x80;
    
    uint64_t s_blk[16]; memcpy(s_blk, salt1, 128);
    for(int w=0; w<15; w++) {
        uint64_t v_swp = __builtin_bswap64(s_blk[w]);
        for(int l=0; l<8; l++) msg1[w][l] = v_swp;
        for(int l=0; l<8; l++) msg2[w][l] = v_swp;
    }
    for(int l=0; l<8; l++) msg1[15][l] = (128 + salt_len + 4) * 8;
    for(int l=0; l<8; l++) msg2[15][l] = (128 + salt_len + 4) * 8;

    SHA512_AVX512_State s1 = ipad1;
    sha512_transform_avx512(&s1, msg1);
    SHA512_AVX512_State s2 = ipad2;
    sha512_transform_avx512(&s2, msg2);
    for(int w=0; w<16; w++) for(int l=0; l<8; l++) msg1[w][l] = 0;
    for(int l=0; l<8; l++) msg1[15][l] = (128 + 64) * 8;
    for(int i=0; i<8; i++) for(int l=0; l<8; l++) msg1[i][l] = s1.state[i][l];
    msg1[8][0] = 0x8000000000000000ULL;
    msg1[8][1] = msg1[8][0];
    msg1[8][2] = msg1[8][0];
    msg1[8][3] = msg1[8][0];
    msg1[8][4] = msg1[8][0];
    msg1[8][5] = msg1[8][0];
    msg1[8][6] = msg1[8][0];
    msg1[8][7] = msg1[8][0];
    for(int w=0; w<16; w++) for(int l=0; l<8; l++) msg2[w][l] = 0;
    for(int l=0; l<8; l++) msg2[15][l] = (128 + 64) * 8;
    for(int i=0; i<8; i++) for(int l=0; l<8; l++) msg2[i][l] = s2.state[i][l];
    msg2[8][0] = 0x8000000000000000ULL;
    msg2[8][1] = msg2[8][0];
    msg2[8][2] = msg2[8][0];
    msg2[8][3] = msg2[8][0];
    msg2[8][4] = msg2[8][0];
    msg2[8][5] = msg2[8][0];
    msg2[8][6] = msg2[8][0];
    msg2[8][7] = msg2[8][0];

    SHA512_AVX512_State o1 = opad1;
    sha512_transform_avx512(&o1, msg1);
    for(int i=0; i<8; i++) for(int l=0; l<8; l++) T1[i][l] = o1.state[i][l];
    SHA512_AVX512_State o2 = opad2;
    sha512_transform_avx512(&o2, msg2);
    for(int i=0; i<8; i++) for(int l=0; l<8; l++) T2[i][l] = o2.state[i][l];
    uint64_t U1[16][8] = {0};
    for(int l=0; l<8; l++) U1[15][l] = (128 + 64) * 8;
    U1[8][0] = 0x8000000000000000ULL;
    U1[8][1] = U1[8][0];
    U1[8][2] = U1[8][0];
    U1[8][3] = U1[8][0];
    U1[8][4] = U1[8][0];
    U1[8][5] = U1[8][0];
    U1[8][6] = U1[8][0];
    U1[8][7] = U1[8][0];
    uint64_t U2[16][8] = {0};
    for(int l=0; l<8; l++) U2[15][l] = (128 + 64) * 8;
    U2[8][0] = 0x8000000000000000ULL;
    U2[8][1] = U2[8][0];
    U2[8][2] = U2[8][0];
    U2[8][3] = U2[8][0];
    U2[8][4] = U2[8][0];
    U2[8][5] = U2[8][0];
    U2[8][6] = U2[8][0];
    U2[8][7] = U2[8][0];
    for(uint32_t iter = 1; iter < iterations; ++iter) {
        for(int i=0; i<8; i++) for(int l=0; l<8; l++) U1[i][l] = o1.state[i][l];
        s1 = ipad1;
        sha512_transform_avx512(&s1, U1);
        for(int i=0; i<8; i++) for(int l=0; l<8; l++) U1[i][l] = s1.state[i][l];
        o1 = opad1;
        sha512_transform_avx512(&o1, U1);
        for(int i=0; i<8; i++) for(int l=0; l<8; l++) T1[i][l] ^= o1.state[i][l];
        for(int i=0; i<8; i++) for(int l=0; l<8; l++) U2[i][l] = o2.state[i][l];
        s2 = ipad2;
        sha512_transform_avx512(&s2, U2);
        for(int i=0; i<8; i++) for(int l=0; l<8; l++) U2[i][l] = s2.state[i][l];
        o2 = opad2;
        sha512_transform_avx512(&o2, U2);
        for(int i=0; i<8; i++) for(int l=0; l<8; l++) T2[i][l] ^= o2.state[i][l];
    }

    for(int i = 0; i < 8; i++) {
        uint64_t b1 = __builtin_bswap64(T1[i][0]);
        memcpy(out1 + i*8, &b1, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b2 = __builtin_bswap64(T1[i][1]);
        memcpy(out2 + i*8, &b2, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b3 = __builtin_bswap64(T1[i][2]);
        memcpy(out3 + i*8, &b3, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b4 = __builtin_bswap64(T1[i][3]);
        memcpy(out4 + i*8, &b4, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b5 = __builtin_bswap64(T1[i][4]);
        memcpy(out5 + i*8, &b5, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b6 = __builtin_bswap64(T1[i][5]);
        memcpy(out6 + i*8, &b6, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b7 = __builtin_bswap64(T1[i][6]);
        memcpy(out7 + i*8, &b7, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b8 = __builtin_bswap64(T1[i][7]);
        memcpy(out8 + i*8, &b8, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b9 = __builtin_bswap64(T2[i][0]);
        memcpy(out9 + i*8, &b9, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b10 = __builtin_bswap64(T2[i][1]);
        memcpy(out10 + i*8, &b10, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b11 = __builtin_bswap64(T2[i][2]);
        memcpy(out11 + i*8, &b11, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b12 = __builtin_bswap64(T2[i][3]);
        memcpy(out12 + i*8, &b12, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b13 = __builtin_bswap64(T2[i][4]);
        memcpy(out13 + i*8, &b13, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b14 = __builtin_bswap64(T2[i][5]);
        memcpy(out14 + i*8, &b14, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b15 = __builtin_bswap64(T2[i][6]);
        memcpy(out15 + i*8, &b15, 8);
    }
    for(int i = 0; i < 8; i++) {
        uint64_t b16 = __builtin_bswap64(T2[i][7]);
        memcpy(out16 + i*8, &b16, 8);
    }
}

