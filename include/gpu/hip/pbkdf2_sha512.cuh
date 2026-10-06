#pragma once
// Kernel PBKDF2-HMAC-SHA512 (BIP-39) — AMD ROCm/HIP.

#include <cstdint>
#include <hip/hip_runtime.h>

namespace cw_amd {

using u64 = uint64_t;
using u32 = uint32_t;
using u8  = uint8_t;

__constant__ u64 c_K[80] = {
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

__constant__ u64 c_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

// Salt block pré-computado pela host (W[16] = 128 bytes com padding).
// Em __constant__ para acesso via cache de constante (broadcast, ~5 ns).
// __constant__ u64 c_salt_block[16];

// Primitivas SHA-512
__device__ __forceinline__ u64 rotr64(u64 x, int n) {
    return (x >> n) | (x << (64 - n));
}
__device__ __forceinline__ u64 ch64(u64 x, u64 y, u64 z) {
    return (x & y) ^ (~x & z);
}
__device__ __forceinline__ u64 maj64(u64 x, u64 y, u64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
__device__ __forceinline__ u64 ep0_64(u64 x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}
__device__ __forceinline__ u64 ep1_64(u64 x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}
__device__ __forceinline__ u64 sig0_64(u64 x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}
__device__ __forceinline__ u64 sig1_64(u64 x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

#define AMD_SHA512_STEP(KVAL)                                                  \
    do {                                                                       \
        u64 h_kw    = h + (KVAL);                                              \
        u64 e_terms = ep1_64(e) + ch64(e, f, g);                               \
        u64 T1      = h_kw + e_terms;                                          \
        u64 T2      = ep0_64(a) + maj64(a, b, c);                              \
        h = g; g = f; f = e; e = d + T1;                                       \
        d = c; c = b; b = a; a = T1 + T2;                                      \
    } while (0)

__device__ __forceinline__ void sha512_block(u64* __restrict__ H,
                                              u64* __restrict__ W) {
    u64 a = H[0], b = H[1], c = H[2], d = H[3];
    u64 e = H[4], f = H[5], g = H[6], h = H[7];

#pragma unroll 16
    for (int j = 0; j < 16; ++j) AMD_SHA512_STEP(c_K[j] + W[j]);

#pragma unroll 4
    for (int chunk = 1; chunk < 5; ++chunk) {
#pragma unroll 16
        for (int j = 0; j < 16; ++j) {
            W[j] += sig1_64(W[(j + 14) & 15]) + W[(j + 9) & 15] + sig0_64(W[(j + 1) & 15]);
            AMD_SHA512_STEP(c_K[chunk * 16 + j] + W[j]);
        }
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

__device__ __forceinline__ void sha512_block_padded_64(u64* __restrict__ H,
                                                       u64* __restrict__ W) {
    W[8]  = 0x8000000000000000ULL;
    W[9]  = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 1024ULL;

    u64 a = H[0], b = H[1], c = H[2], d = H[3];
    u64 e = H[4], f = H[5], g = H[6], h = H[7];

#define AMD_STEP(KVAL)                                                         \
    do {                                                                       \
        u64 h_kw    = h + (KVAL);                                              \
        u64 e_terms = ep1_64(e) + ch64(e, f, g);                               \
        u64 T1      = h_kw + e_terms;                                          \
        u64 T2      = ep0_64(a) + maj64(a, b, c);                              \
        h = g; g = f; f = e; e = d + T1;                                       \
        d = c; c = b; b = a; a = T1 + T2;                                      \
    } while (0)

#pragma unroll 16
    for (int j = 0; j < 16; ++j) AMD_STEP(c_K[j] + W[j]);
#pragma unroll 4
    for (int chunk = 1; chunk < 5; ++chunk) {
#pragma unroll 16
        for (int j = 0; j < 16; ++j) {
            W[j] += sig1_64(W[(j + 14) & 15]) + W[(j + 9) & 15] + sig0_64(W[(j + 1) & 15]);
            AMD_STEP(c_K[chunk * 16 + j] + W[j]);
        }
    }
#undef AMD_STEP

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

#undef AMD_SHA512_STEP

// Kernel principal
//
// `salt_block` foi REMOVIDO da assinatura — agora é lido de c_salt_block
// (constant memory, broadcast). `pass_lens` continua para senhas de
// comprimentos variáveis.
extern "C" __global__ __launch_bounds__(64)
void pbkdf2_batch_amd(const u8*  __restrict__ passwords,
                      const u32* __restrict__ pass_lens,
                      u32        num_hashes,
                      u8*        __restrict__ outputs,
                      const u64* __restrict__ salt_block,
                      u32        slot_size,
                      u32        uniform_len)
{
    const u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= num_hashes) return;

    const u32 pwd_len = (uniform_len > 0) ? uniform_len : pass_lens[gid];
    const u32 offset  = gid * slot_size;

    u64 W[16];
    u64 ipad_state[8];
    u64 opad_state[8];
    u64 H_work[8];
    u64 U[8];
    u64 F[8];

#pragma unroll 8
    for (int i = 0; i < 8; ++i) { ipad_state[i] = c_IV[i]; opad_state[i] = c_IV[i]; }

        // HMAC setup
        if (__builtin_expect(pwd_len <= 128, 1)) {
        const u32 full_words = pwd_len >> 3;
        const u32 rem        = pwd_len & 7;

        // ---- IPAD ----
#pragma unroll 16
        for (int i = 0; i < 16; ++i) {
            u64 word = 0;
            if ((u32)i < full_words) {
                const u8* p = passwords + offset + i * 8;
                word = ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) | ((u64)p[3] << 32)
                     | ((u64)p[4] << 24) | ((u64)p[5] << 16) | ((u64)p[6] <<  8) | (u64)p[7];
            } else if ((u32)i == full_words && rem > 0) {
                u8 b[8] = {0, 0, 0, 0, 0, 0, 0, 0};
                for (u32 k = 0; k < rem; ++k) b[k] = passwords[offset + i * 8 + k];
                word = ((u64)b[0] << 56) | ((u64)b[1] << 48) | ((u64)b[2] << 40) | ((u64)b[3] << 32)
                     | ((u64)b[4] << 24) | ((u64)b[5] << 16) | ((u64)b[6] <<  8) | (u64)b[7];
            }
            W[i] = word ^ 0x3636363636363636ULL;
        }
        sha512_block(ipad_state, W);

        // ---- OPAD ----
#pragma unroll 16
        for (int i = 0; i < 16; ++i) {
            u64 word = 0;
            if ((u32)i < full_words) {
                const u8* p = passwords + offset + i * 8;
                word = ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) | ((u64)p[3] << 32)
                     | ((u64)p[4] << 24) | ((u64)p[5] << 16) | ((u64)p[6] <<  8) | (u64)p[7];
            } else if ((u32)i == full_words && rem > 0) {
                u8 b[8] = {0, 0, 0, 0, 0, 0, 0, 0};
                for (u32 k = 0; k < rem; ++k) b[k] = passwords[offset + i * 8 + k];
                word = ((u64)b[0] << 56) | ((u64)b[1] << 48) | ((u64)b[2] << 40) | ((u64)b[3] << 32)
                     | ((u64)b[4] << 24) | ((u64)b[5] << 16) | ((u64)b[6] <<  8) | (u64)b[7];
            }
            W[i] = word ^ 0x5c5c5c5c5c5c5c5cULL;
        }
        sha512_block(opad_state, W);
    } else {
        u64 H_key[8];
#pragma unroll 8
        for (int i = 0; i < 8; ++i) H_key[i] = c_IV[i];

        const u32 full_blocks = pwd_len / 128;
        for (u32 blk = 0; blk < full_blocks; ++blk) {
            const u32 blk_off = offset + blk * 128;
            for (int i = 0; i < 16; ++i) {
                u64 word = 0;
#pragma unroll 8
                for (int j = 0; j < 8; ++j) word = (word << 8) | passwords[blk_off + i * 8 + j];
                W[i] = word;
            }
            sha512_block(H_key, W);
        }

        const u32 rem_start = full_blocks * 128;
        const u32 rem_len   = pwd_len - rem_start;

        if (rem_len < 112) {
            for (int i = 0; i < 14; ++i) {
                u64 word = 0;
#pragma unroll 8
                for (int j = 0; j < 8; ++j) {
                    u32 pos = i * 8 + j;
                    u8 b = (pos < rem_len) ? passwords[offset + rem_start + pos]
                                           : (pos == rem_len ? 0x80 : 0);
                    word = (word << 8) | b;
                }
                W[i] = word;
            }
            W[14] = 0;
            W[15] = ((u64)pwd_len) * 8;
            sha512_block(H_key, W);
        } else {
            for (int i = 0; i < 16; ++i) {
                u64 word = 0;
#pragma unroll 8
                for (int j = 0; j < 8; ++j) {
                    u32 pos = i * 8 + j;
                    u8 b = (pos < rem_len) ? passwords[offset + rem_start + pos]
                                           : (pos == rem_len ? 0x80 : 0);
                    word = (word << 8) | b;
                }
                W[i] = word;
            }
            sha512_block(H_key, W);
#pragma unroll 14
            for (int i = 0; i < 14; ++i) W[i] = 0;
            W[15] = ((u64)pwd_len) * 8;
            sha512_block(H_key, W);
        }

#pragma unroll 16
        for (int i = 0; i < 16; ++i) {
            const u64 k = (i < 8) ? H_key[i] : 0ULL;
            W[i] = k ^ 0x3636363636363636ULL;
        }
        sha512_block(ipad_state, W);

#pragma unroll 16
        for (int i = 0; i < 16; ++i) {
            const u64 k = (i < 8) ? H_key[i] : 0ULL;
            W[i] = k ^ 0x5c5c5c5c5c5c5c5cULL;
        }
        sha512_block(opad_state, W);
    }

        // U_1 = HMAC(senha, salt || BE32(1)) — salt em constant memory
    #pragma unroll 8
    for (int i = 0; i < 8; ++i) H_work[i] = ipad_state[i];
#pragma unroll 16
    for (int i = 0; i < 16; ++i) W[i] = salt_block[i];
    sha512_block(H_work, W);

#pragma unroll 8
    for (int i = 0; i < 8; ++i) U[i] = opad_state[i];
#pragma unroll 8
    for (int i = 0; i < 8; ++i) W[i] = H_work[i];
    sha512_block_padded_64(U, W);

#pragma unroll 8
    for (int i = 0; i < 8; ++i) F[i] = U[i];

        // U_2..U_2048, XOR acumulado em F
        for (u32 iter = 1; iter < 2048; ++iter) {
#pragma unroll 8
        for (int i = 0; i < 8; ++i) H_work[i] = ipad_state[i];
#pragma unroll 8
        for (int i = 0; i < 8; ++i) W[i] = U[i];
        sha512_block_padded_64(H_work, W);

#pragma unroll 8
        for (int i = 0; i < 8; ++i) U[i] = opad_state[i];
#pragma unroll 8
        for (int i = 0; i < 8; ++i) W[i] = H_work[i];
        sha512_block_padded_64(U, W);

#pragma unroll 8
        for (int i = 0; i < 8; ++i) F[i] ^= U[i];
    }

    u64* out64 = reinterpret_cast<u64*>(outputs + gid * 64);
#pragma unroll 8
    for (int i = 0; i < 8; ++i) {
        u64 v = F[i];
        out64[i] = ((v & 0x00000000000000FFULL) << 56) |
                   ((v & 0x000000000000FF00ULL) << 40) |
                   ((v & 0x0000000000FF0000ULL) << 24) |
                   ((v & 0x00000000FF000000ULL) <<  8) |
                   ((v & 0x000000FF00000000ULL) >>  8) |
                   ((v & 0x0000FF0000000000ULL) >> 24) |
                   ((v & 0x00FF000000000000ULL) >> 40) |
                   ((v & 0xFF00000000000000ULL) >> 56);
    }
}

}  // namespace cw_amd
