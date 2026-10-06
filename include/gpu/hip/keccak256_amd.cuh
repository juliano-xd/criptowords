#pragma once
// Keccak-256 (variante Ethereum, padding 0x01) — HIP/AMD.
//
// Estado: 25 words de 64 bits (200 bytes).
// Rate: 136 bytes (1088 bits) para Keccak-256.
// Capacity: 64 bytes (512 bits).
//
// Suporta mensagens de até 135 bytes em um único bloco (suficiente para
// Keccak(64B pubkey) usado em Ethereum). Para mensagens maiores, seria
// preciso um estado persistente multi-bloco.

#include <cstdint>
#include <hip/hip_runtime.h>

namespace cw_amd {

using u64 = uint64_t;
using u32 = uint32_t;
using u8  = uint8_t;

__device__ __forceinline__ u64 keccak_rotl64(u64 x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Constantes de round (24 rodadas)
__constant__ u64 c_keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// Permutação Keccak-f1600 (24 rounds de θ, ρ, π, χ, ι).
__device__ __forceinline__ void keccak_f1600(u64 A[25]) {
    constexpr int R[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                           25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};

#pragma unroll 1  // 24 rounds, evitar explosão de registradores
    for (int round = 0; round < 24; ++round) {
        // θ
        u64 C[5];
#pragma unroll
        for (int x = 0; x < 5; ++x) {
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        }
        u64 D[5];
#pragma unroll
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ keccak_rotl64(C[(x + 1) % 5], 1);
        }
#pragma unroll
        for (int x = 0; x < 5; ++x) {
#pragma unroll
            for (int y = 0; y < 5; ++y) {
                A[x + y * 5] ^= D[x];
            }
        }

        // ρ + π
        u64 B[25];
#pragma unroll
        for (int x = 0; x < 5; ++x) {
#pragma unroll
            for (int y = 0; y < 5; ++y) {
                B[y + ((2 * x + 3 * y) % 5) * 5] = keccak_rotl64(A[x + y * 5], R[x + y * 5]);
            }
        }

        // χ
#pragma unroll
        for (int x = 0; x < 5; ++x) {
#pragma unroll
            for (int y = 0; y < 5; ++y) {
                A[x + y * 5] = B[x + y * 5] ^ ((~B[((x + 1) % 5) + y * 5]) & B[((x + 2) % 5) + y * 5]);
            }
        }

        // ι
        A[0] ^= c_keccak_rc[round];
    }
}

// Keccak-256 (Ethereum) de uma mensagem curta (até 135 bytes).
// Sem multi-bloco — suficiente para hashear pubkey de 64 bytes.
__device__ __forceinline__ void keccak256_eth_short(const u8* __restrict__ data,
                                                    u32 len,
                                                    u8 out[32]) {
    constexpr u32 RATE = 136;
    // assert(len <= 135);

    u64 A[25];
#pragma unroll
    for (int i = 0; i < 25; ++i) A[i] = 0;

    // Absorve bytes em big-endian dentro de cada word (ordem Keccak)
    // Nota: Keccak usa LITTLE-endian no load dos bytes para o estado.
    // Cada word u64 = bytes[i*8..i*8+7] do buffer, byte 0 no LSB.
    u32 full_words = len / 8;
    u32 rem        = len % 8;

#pragma unroll 8
    for (u32 i = 0; i < 17; ++i) {
        u64 w = 0;
        if (i < full_words) {
            const u8* p = data + i * 8;
            w = (u64)p[0] | ((u64)p[1] << 8) | ((u64)p[2] << 16) | ((u64)p[3] << 24)
              | ((u64)p[4] << 32) | ((u64)p[5] << 40) | ((u64)p[6] << 48) | ((u64)p[7] << 56);
        } else if (i == full_words && rem > 0) {
            const u8* p = data + i * 8;
            for (u32 k = 0; k < rem; ++k) w |= (u64)p[k] << (8 * k);
        }
        A[i] ^= w;
    }

    // Padding Ethereum: 0x01 no byte len, 0x80 no byte 135.
    // Equivalente a: A[len/8] ^= 0x01 << (8*(len%8));
    //                A[16]  ^= 0x80 << 56;
    A[len / 8] ^= (u64)0x01 << (8 * (len % 8));
    A[16]      ^= (u64)0x80 << 56;

    keccak_f1600(A);

    // Extrai 32 bytes little-endian
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        u64 v = A[i];
#pragma unroll
        for (int j = 0; j < 8; ++j) {
            out[i * 8 + j] = (u8)(v >> (8 * j));
        }
    }
}

}  // namespace cw_amd
