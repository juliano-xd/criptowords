#pragma once
#include "pbkdf2_sha512.cuh"

namespace cw_amd {

// HMAC-SHA512 genérico: key ≤ 64 B, msg ≤ 111 B (cabe em 1 bloco após ipad).
__device__ __forceinline__ void hmac_sha512_generic(const u8* __restrict__ key,
                                                    u32 key_len,
                                                    const u8* __restrict__ msg,
                                                    u32 msg_len,
                                                    u64 out[8]) {
    u8 kpad[64];
#pragma unroll
    for (int i = 0; i < 64; ++i) kpad[i] = 0;
    for (u32 i = 0; i < key_len; ++i) kpad[i] = key[i];

    u64 W[16];

    // ---- Inner: (kpad ^ 0x36) || msg || pad ----
    u64 inner[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) inner[i] = c_IV[i];

#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 w = 0;
#pragma unroll
        for (int j = 0; j < 8; ++j) {
            u8 b = kpad[i * 8 + j] ^ 0x36;
            w = (w << 8) | b;
        }
        W[i] = w;
    }
#pragma unroll
    for (int i = 8; i < 16; ++i) W[i] = 0x3636363636363636ULL;
    sha512_block(inner, W);

#pragma unroll
    for (int i = 0; i < 16; ++i) W[i] = 0;
    u32 full = msg_len / 8;
    u32 rem  = msg_len % 8;
#pragma unroll 8
    for (int i = 0; i < 14; ++i) {
        u64 w = 0;
        if ((u32)i < full) {
            const u8* p = msg + i * 8;
#pragma unroll
            for (int j = 0; j < 8; ++j) w = (w << 8) | p[j];
        } else if ((u32)i == full && rem > 0) {
            const u8* p = msg + i * 8;
#pragma unroll
            for (int j = 0; j < 8; ++j) {
                w = (w << 8) | ((u32)j < rem ? p[j] : (u8)0);
            }
        }
        W[i] = w;
    }
    W[msg_len / 8] |= (u64)0x80 << (56 - 8 * (msg_len % 8));
    W[14] = 0;
    W[15] = (u64)msg_len * 8;
    sha512_block(inner, W);

    // ---- Outer: (kpad ^ 0x5c) || inner_hash || pad ----
    u64 outer[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) outer[i] = c_IV[i];

#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 w = 0;
#pragma unroll
        for (int j = 0; j < 8; ++j) {
            u8 b = kpad[i * 8 + j] ^ 0x5c;
            w = (w << 8) | b;
        }
        W[i] = w;
    }
#pragma unroll
    for (int i = 8; i < 16; ++i) W[i] = 0x5c5c5c5c5c5c5c5cULL;
    sha512_block(outer, W);

#pragma unroll
    for (int i = 0; i < 8; ++i) W[i] = inner[i];
    W[8] = 0x8000000000000000ULL;
#pragma unroll
    for (int i = 9; i < 15; ++i) W[i] = 0;
    W[15] = 512ULL;
    sha512_block(outer, W);

#pragma unroll
    for (int i = 0; i < 8; ++i) out[i] = outer[i];
}

__device__ __forceinline__ void hmac_sha512_extract_be(const u64 st[8], u8 out[64]) {
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 v = st[i];
#pragma unroll
        for (int j = 0; j < 8; ++j) out[i * 8 + j] = (u8)(v >> (56 - 8 * j));
    }
}

// Serializa u32[8] LE para bytes BE (32).
__device__ __forceinline__ void u32le_to_be32(const u32 in[8], u8 out[32]) {
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u32 v = in[7 - i];
        out[i * 4 + 0] = (u8)(v >> 24);
        out[i * 4 + 1] = (u8)(v >> 16);
        out[i * 4 + 2] = (u8)(v >> 8);
        out[i * 4 + 3] = (u8)v;
    }
}

// Serializa bytes BE (32) para u32[8] LE.
__device__ __forceinline__ void be32_to_u32le(const u8 in[32], u32 out[8]) {
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u32 v = ((u32)in[i * 4 + 0] << 24) | ((u32)in[i * 4 + 1] << 16)
              | ((u32)in[i * 4 + 2] << 8)  | (u32)in[i * 4 + 3];
        out[7 - i] = v;
    }
}

}  // namespace cw_amd
