#pragma once
#include <string_view>

namespace cryptowords::gpu {

inline constexpr std::string_view PBKDF2_GPU_KERNEL_SRC = R"OPENCL(
#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define ROTR64(x, n) rotate((ulong)(x), 64UL - (ulong)(n))
#define CH64(x, y, z) bitselect((ulong)(z), (ulong)(y), (ulong)(x))
#define MAJ64(x, y, z) bitselect((ulong)(x), (ulong)(y), (ulong)((x) ^ (z)))
#define EP0_64(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_64(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_64(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_64(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

__constant ulong K[80] = {
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

__constant ulong IV[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

inline void sha512_block_fast(ulong* H, ulong* W) {
    ulong a = H[0], b = H[1], c = H[2], d = H[3];
    ulong e = H[4], f = H[5], g = H[6], h = H[7];
    ulong T1, T2;

    #pragma unroll 16
    for (int j = 0; j < 16; ++j) {
        T1 = h + EP1_64(e) + CH64(e, f, g) + K[j] + W[j];
        T2 = EP0_64(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    for (int chunk = 1; chunk < 5; ++chunk) {
        #pragma unroll 16
        for (int j = 0; j < 16; ++j) {
            W[j] += SIG1_64(W[(j+14)&15]) + W[(j+9)&15] + SIG0_64(W[(j+1)&15]);
            T1 = h + EP1_64(e) + CH64(e, f, g) + K[chunk*16 + j] + W[j];
            T2 = EP0_64(a) + MAJ64(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

inline void sha512_block_fast_padded(ulong* H, const ulong* in8) {
    ulong W[16];
    #pragma unroll 8
    for (int i = 0; i < 8; ++i) W[i] = in8[i];
    W[8] = 0x8000000000000000UL;
    W[9] = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 1536;

    ulong a = H[0], b = H[1], c = H[2], d = H[3];
    ulong e = H[4], f = H[5], g = H[6], h = H[7];
    ulong T1, T2;

    #pragma unroll 16
    for (int j = 0; j < 16; ++j) {
        T1 = h + EP1_64(e) + CH64(e, f, g) + K[j] + W[j];
        T2 = EP0_64(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    for (int chunk = 1; chunk < 5; ++chunk) {
        #pragma unroll 16
        for (int j = 0; j < 16; ++j) {
            W[j] += SIG1_64(W[(j+14)&15]) + W[(j+9)&15] + SIG0_64(W[(j+1)&15]);
            T1 = h + EP1_64(e) + CH64(e, f, g) + K[chunk*16 + j] + W[j];
            T2 = EP0_64(a) + MAJ64(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

__kernel void pbkdf2_batch(
    __global const uchar* passwords, 
    __global const uint* pass_lens, 
    const uint num_hashes, 
    __global uchar* outputs,
    __constant ulong* salt_block,
    const uint slot_size) 
{
    uint gid = get_global_id(0);
    if (gid >= num_hashes) return;
    
    uint pwd_len = pass_lens[gid];
    uint offset = gid * slot_size;
    
    ulong W[16]; 
    ulong ipad_state[8];
    ulong opad_state[8];
    
    #pragma unroll 8
    for(int i=0; i<8; i++) {
        ipad_state[i] = IV[i];
        opad_state[i] = IV[i];
    }
    
    if (pwd_len <= 128) {
        for(int i=0; i<16; i++) {
            ulong word = 0;
            #pragma unroll 8
            for(int j=0; j<8; j++) {
                uint idx = i*8 + j;
                uchar b = (idx < pwd_len) ? passwords[offset + idx] : 0;
                word = (word << 8) | (b ^ 0x36);
            }
            W[i] = word;
        }
        sha512_block_fast(ipad_state, W);
        
        for(int i=0; i<16; i++) {
            ulong word = 0;
            #pragma unroll 8
            for(int j=0; j<8; j++) {
                uint idx = i*8 + j;
                uchar b = (idx < pwd_len) ? passwords[offset + idx] : 0;
                word = (word << 8) | (b ^ 0x5c);
            }
            W[i] = word;
        }
        sha512_block_fast(opad_state, W);
    } else {
        ulong H_key[8];
        #pragma unroll 8
        for(int i=0; i<8; i++) H_key[i] = IV[i];

        uint full_blocks = pwd_len / 128;
        for(uint blk = 0; blk < full_blocks; blk++) {
            uint blk_off = offset + blk * 128;
            for(int i=0; i<16; i++) {
                ulong word = 0;
                #pragma unroll 8
                for(int j=0; j<8; j++) {
                    word = (word << 8) | passwords[blk_off + i*8 + j];
                }
                W[i] = word;
            }
            sha512_block_fast(H_key, W);
        }

        uint rem_start = full_blocks * 128;
        uint rem_len = pwd_len - rem_start;

        if (rem_len < 112) {
            for(int i=0; i<14; i++) {
                ulong word = 0;
                #pragma unroll 8
                for(int j=0; j<8; j++) {
                    uint pos = i*8 + j;
                    uchar b = 0;
                    if (pos < rem_len) {
                        b = passwords[offset + rem_start + pos];
                    } else if (pos == rem_len) {
                        b = 0x80;
                    }
                    word = (word << 8) | b;
                }
                W[i] = word;
            }
            W[14] = 0;
            W[15] = ((ulong)pwd_len) * 8;
            sha512_block_fast(H_key, W);
        } else {
            for(int i=0; i<16; i++) {
                ulong word = 0;
                #pragma unroll 8
                for(int j=0; j<8; j++) {
                    uint pos = i*8 + j;
                    uchar b = 0;
                    if (pos < rem_len) {
                        b = passwords[offset + rem_start + pos];
                    } else if (pos == rem_len) {
                        b = 0x80;
                    }
                    word = (word << 8) | b;
                }
                W[i] = word;
            }
            sha512_block_fast(H_key, W);

            #pragma unroll 14
            for(int i=0; i<14; i++) W[i] = 0;
            W[14] = 0;
            W[15] = ((ulong)pwd_len) * 8;
            sha512_block_fast(H_key, W);
        }

        for(int i=0; i<8; i++) {
            W[i] = H_key[i] ^ 0x3636363636363636UL;
        }
        for(int i=8; i<16; i++) {
            W[i] = 0x3636363636363636UL;
        }
        sha512_block_fast(ipad_state, W);

        for(int i=0; i<8; i++) {
            W[i] = H_key[i] ^ 0x5c5c5c5c5c5c5c5cUL;
        }
        for(int i=8; i<16; i++) {
            W[i] = 0x5c5c5c5c5c5c5c5cUL;
        }
        sha512_block_fast(opad_state, W);
    }
    
    ulong H_work[8];
    #pragma unroll 8
    for(int i=0; i<8; i++) H_work[i] = ipad_state[i];
    
    #pragma unroll 16
    for(int i=0; i<16; i++) W[i] = salt_block[i];
    sha512_block_fast(H_work, W);
    
    ulong U[8];
    #pragma unroll 8
    for(int i=0; i<8; i++) U[i] = opad_state[i];
    
    #pragma unroll 8
    for(int i=0; i<8; i++) W[i] = H_work[i];
    W[8] = 0x8000000000000000UL;
    W[9] = 0; W[10] = 0; W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 1536;
    sha512_block_fast(U, W);
    
    ulong F[8];
    #pragma unroll 8
    for(int i=0; i<8; i++) F[i] = U[i];
    
    for(int iter=1; iter<2048; iter++) {
        #pragma unroll 8
        for(int i=0; i<8; i++) H_work[i] = ipad_state[i];
        sha512_block_fast_padded(H_work, U);
        
        #pragma unroll 8
        for(int i=0; i<8; i++) U[i] = opad_state[i];
        sha512_block_fast_padded(U, H_work);
        
        #pragma unroll 8
        for(int i=0; i<8; i++) F[i] ^= U[i];
    }
    
    uint out_off = gid * 64;
    #pragma unroll 8
    for(int i=0; i<8; i++) {
        outputs[out_off + i*8 + 0] = (F[i] >> 56) & 0xFF;
        outputs[out_off + i*8 + 1] = (F[i] >> 48) & 0xFF;
        outputs[out_off + i*8 + 2] = (F[i] >> 40) & 0xFF;
        outputs[out_off + i*8 + 3] = (F[i] >> 32) & 0xFF;
        outputs[out_off + i*8 + 4] = (F[i] >> 24) & 0xFF;
        outputs[out_off + i*8 + 5] = (F[i] >> 16) & 0xFF;
        outputs[out_off + i*8 + 6] = (F[i] >> 8)  & 0xFF;
        outputs[out_off + i*8 + 7] = (F[i]      ) & 0xFF;
    }
}
)OPENCL";

} // namespace cryptowords::gpu
