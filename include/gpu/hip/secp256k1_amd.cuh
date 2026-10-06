#pragma once
// secp256k1 em HIP/AMD — aritmética de campo, escalar e ponto.
//
// Representações:
//   - Field element (mod p): 8 × u32 (256 bits, little-endian word order)
//   - Scalar (mod n): 8 × u32
//   - Point: Jacobian (X, Y, Z), cada coordenada um field element
//   - Affine: Z = 1
//
// Baseado no secp256k1_gpu.cl do projeto keyhunt, portado para HIP.
// A tabela de 2^i · G (256 pontos afins) é gerada pelo caller no host
// e passada como ponteiro de device (não hardcoded — evita 16 KB de
// constantes no binário e permite regeneração em runtime).

#include <cstdint>
#include <hip/hip_runtime.h>

namespace cw_amd {

using u32 = uint32_t;
using u64 = uint64_t;
using u8  = uint8_t;

// Constantes

// p = 2^256 - 2^32 - 977
__constant__ u32 c_P[8] = {
    0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

// p - 2 (expoente para inverso via Fermat)
__constant__ u32 c_P_MINUS_2[8] = {
    0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

// n = ordem do subgrupo de secp256k1
__constant__ u32 c_N[8] = {
    0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
    0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
};

// Field arithmetic (mod p)

// R = A - B mod p
__device__ __forceinline__ void fp_sub(u32 R[8], const u32 A[8], const u32 B[8]) {
    u64 borrow = 0;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 sub = (u64)A[i] - B[i] - borrow;
        R[i] = (u32)sub;
        borrow = (sub >> 32) & 1ULL;
    }
    if (borrow) {
        u64 c = 0;
#pragma unroll
        for (int i = 0; i < 8; ++i) {
            u64 sum = (u64)R[i] + c_P[i] + c;
            R[i] = (u32)sum;
            c = sum >> 32;
        }
    }
}

// R = A * B mod p (portado do keyhunt/OpenCL).
//
// Redução pseudo-Mersenne: 2^256 ≡ 2^32 + 0x3D1 (mod p).
__device__ __forceinline__ void fp_mul(u32 R[8], const u32 A[8], const u32 B[8]) {
    u64 C[16];
#pragma unroll
    for (int i = 0; i < 16; ++i) C[i] = 0;

    // Schoolbook 8×8 → 16 words
#pragma unroll 4
    for (int i = 0; i < 8; ++i) {
        u64 carry = 0;
#pragma unroll 8
        for (int j = 0; j < 8; ++j) {
            u64 prod = (u64)A[i] * B[j] + C[i + j] + carry;
            C[i + j] = (u32)prod;
            carry = prod >> 32;
        }
        C[i + 8] += carry;
    }

    // Passo 1: C_lo + C_hi · (2^32 + 0x3D1)
    u64 carry = 0;
    u32 R_tmp[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 term1 = C[i];
        u64 term2 = (u64)C[i + 8] * 0x3D1ULL;      // ×0x3D1
        u64 term3 = (i > 0) ? (u64)C[i + 7] : 0ULL; // ×2^32 (shift 1 word)
        u64 sum = term1 + term2 + term3 + carry;
        R_tmp[i] = (u32)sum;
        carry = sum >> 32;
    }
    carry += C[15];

    // Passo 2: dobra o carry residual
    u64 c2 = 0;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 term2 = (i == 0) ? (carry * 0x3D1ULL) : 0ULL;
        u64 term3 = (i == 1) ? carry : 0ULL;
        u64 sum = (u64)R_tmp[i] + term2 + term3 + c2;
        R_tmp[i] = (u32)sum;
        c2 = sum >> 32;
    }

    // Passo 3: último fold (c2 tipicamente ≤ 2)
    if (c2 > 0) {
        u64 c3 = 0;
        u64 sum = (u64)R_tmp[0] + (c2 * 0x3D1ULL);
        R_tmp[0] = (u32)sum;
        c3 = sum >> 32;
        sum = (u64)R_tmp[1] + c2 + c3;
        R_tmp[1] = (u32)sum;
        c3 = sum >> 32;
#pragma unroll
        for (int i = 2; i < 8 && c3; ++i) {
            sum = (u64)R_tmp[i] + c3;
            R_tmp[i] = (u32)sum;
            c3 = sum >> 32;
        }
    }

    // Subtração condicional de p (garante < p)
    bool gte = true;
#pragma unroll
    for (int i = 7; i >= 0; --i) {
        if (R_tmp[i] > c_P[i]) break;
        if (R_tmp[i] < c_P[i]) { gte = false; break; }
    }
    if (gte) {
        u64 br = 0;
#pragma unroll
        for (int i = 0; i < 8; ++i) {
            u64 sub = (u64)R_tmp[i] - c_P[i] - br;
            R_tmp[i] = (u32)sub;
            br = (sub >> 32) & 1ULL;
        }
    }

#pragma unroll
    for (int i = 0; i < 8; ++i) R[i] = R_tmp[i];
}

// R = A^(-1) mod p via Fermat: A^(p-2)
__device__ __forceinline__ void fp_inv(u32 R[8], const u32 A[8]) {
    u32 res[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    u32 base[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) base[i] = A[i];

#pragma unroll 1
    for (int i = 0; i < 256; ++i) {
        int word = i / 32;
        int bit  = i % 32;
        if ((c_P_MINUS_2[word] >> bit) & 1) {
            fp_mul(res, res, base);
        }
        fp_mul(base, base, base);
    }
#pragma unroll
    for (int i = 0; i < 8; ++i) R[i] = res[i];
}

// Scalar arithmetic (mod n)

// R = (A + B) mod n
__device__ __forceinline__ void sc_add_n(u32 R[8], const u32 A[8], const u32 B[8]) {
    u64 carry = 0;
    u32 T[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u64 sum = (u64)A[i] + B[i] + carry;
        T[i] = (u32)sum;
        carry = sum >> 32;
    }

    bool gte = (carry > 0);
    if (!gte) {
        gte = true;
#pragma unroll
        for (int i = 7; i >= 0; --i) {
            if (T[i] > c_N[i]) break;
            if (T[i] < c_N[i]) { gte = false; break; }
        }
    }

    if (gte) {
        u64 br = 0;
#pragma unroll
        for (int i = 0; i < 8; ++i) {
            u64 sub = (u64)T[i] - c_N[i] - br;
            T[i] = (u32)sub;
            br = (sub >> 32) & 1ULL;
        }
    }

#pragma unroll
    for (int i = 0; i < 8; ++i) R[i] = T[i];
}

// Point arithmetic (Jacobian)

// (X1, Y1, Z1) += (X2, Y2) [X2, Y2 afins]
// Formula madd-2007-bl adaptada do keyhunt.
__device__ __forceinline__ void point_add_mixed(u32 X1[8], u32 Y1[8], u32 Z1[8],
                                                 const u32 X2[8], const u32 Y2[8]) {
    // Z1 == 0 (infinito) → copia (X2, Y2, 1)
    bool z1_zero = true;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        if (Z1[i] != 0) { z1_zero = false; break; }
    }
    if (z1_zero) {
#pragma unroll
        for (int i = 0; i < 8; ++i) {
            X1[i] = X2[i];
            Y1[i] = Y2[i];
            Z1[i] = (i == 0) ? 1 : 0;
        }
        return;
    }

    bool z1_is_one = (Z1[0] == 1);
#pragma unroll
    for (int i = 1; i < 8; ++i) if (Z1[i] != 0) z1_is_one = false;

    u32 H[8], R[8], T1[8], T2[8], T3[8], T4[8];

    if (z1_is_one) {
        fp_sub(H, X2, X1);         // H = X2 - X1
        fp_sub(R, Y2, Y1);         // R = Y2 - Y1
#pragma unroll
        for (int i = 0; i < 8; ++i) Z1[i] = H[i];
    } else {
        fp_mul(T1, Z1, Z1);        // T1 = Z1²
        fp_mul(T2, X2, T1);        // T2 = X2·Z1²
        fp_mul(T3, T1, Z1);        // T3 = Z1³
        fp_mul(T4, Y2, T3);        // T4 = Y2·Z1³
        fp_sub(H, T2, X1);         // H = X2·Z1² - X1
        fp_sub(R, T4, Y1);         // R = Y2·Z1³ - Y1
        fp_mul(Z1, H, Z1);         // Z3 = Z1·H
    }

    fp_mul(T1, H, H);              // T1 = H²
    fp_mul(T2, T1, H);             // T2 = H³
    fp_mul(T3, X1, T1);            // T3 = X1·H²

    fp_mul(X1, R, R);              // X1 = R²
    fp_sub(X1, X1, T2);            // X1 = R² - H³
    fp_sub(X1, X1, T3);            // X1 -= X1·H²
    fp_sub(X1, X1, T3);            // X1 -= X1·H²  → R² - H³ - 2·X1·H²

    fp_sub(T4, T3, X1);            // T4 = X1·H² - X3
    fp_mul(T4, R, T4);             // T4 = R·(X1·H² - X3)
    fp_mul(T3, Y1, T2);            // T3 = Y1·H³
    fp_sub(Y1, T4, T3);            // Y1 = T4 - Y1·H³
}

// (X, Y, Z) → afim (in-place)
__device__ __forceinline__ void point_to_affine(u32 X[8], u32 Y[8], const u32 Z[8]) {
    u32 Zinv[8], Z2[8], Z3[8];
    fp_inv(Zinv, Z);
    fp_mul(Z2, Zinv, Zinv);
    fp_mul(Z3, Z2, Zinv);
    fp_mul(X, X, Z2);
    fp_mul(Y, Y, Z3);
}

// Public API: k · G

// Escalar `k` (32 bytes big-endian) → ponto k·G em afim (out_x, out_y).
//
//   g_table: buffer com 256 × 16 u32. Layout:
//              g_table[i*16 + 0..7]  = X de 2^i · G (afim)
//              g_table[i*16 + 8..15] = Y de 2^i · G (afim)
__device__ __forceinline__ void scalar_mul_g(const u8 k_be[32],
                                              const u32* __restrict__ g_table,
                                              u32 out_x[8],
                                              u32 out_y[8]) {
    u32 X[8] = {0}, Y[8] = {0}, Z[8] = {0};

#pragma unroll 1
    for (int i = 0; i < 256; ++i) {
        // Bit i do escalar (k_be[0] = MSB, k_be[31] = LSB)
        int byte_idx = 31 - (i / 8);
        int bit_idx  = i % 8;
        bool bit_set = (k_be[byte_idx] >> bit_idx) & 1;

        if (bit_set) {
            const u32* Xi = g_table + i * 16;
            const u32* Yi = g_table + i * 16 + 8;
            point_add_mixed(X, Y, Z, Xi, Yi);
        }
    }

    bool z_zero = true;
#pragma unroll
    for (int i = 0; i < 8; ++i) if (Z[i] != 0) z_zero = false;

    if (z_zero) {
#pragma unroll
        for (int i = 0; i < 8; ++i) { out_x[i] = 0; out_y[i] = 0; }
        return;
    }

    point_to_affine(X, Y, Z);
#pragma unroll
    for (int i = 0; i < 8; ++i) { out_x[i] = X[i]; out_y[i] = Y[i]; }
}

// Serialização de pubkey

// 0x02/0x03 (paridade de Y) || X (32 bytes BE)
__device__ __forceinline__ void export_pubkey_compressed(const u32 X[8],
                                                          const u32 Y[8],
                                                          u8 out[33]) {
    out[0] = (Y[0] & 1) ? 0x03 : 0x02;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u32 v = X[7 - i];
        out[1 + i * 4 + 0] = (u8)(v >> 24);
        out[1 + i * 4 + 1] = (u8)(v >> 16);
        out[1 + i * 4 + 2] = (u8)(v >> 8);
        out[1 + i * 4 + 3] = (u8)v;
    }
}

// 0x04 || X (32 BE) || Y (32 BE)
__device__ __forceinline__ void export_pubkey_uncompressed(const u32 X[8],
                                                            const u32 Y[8],
                                                            u8 out[65]) {
    out[0] = 0x04;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u32 v = X[7 - i];
        out[1 + i * 4 + 0] = (u8)(v >> 24);
        out[1 + i * 4 + 1] = (u8)(v >> 16);
        out[1 + i * 4 + 2] = (u8)(v >> 8);
        out[1 + i * 4 + 3] = (u8)v;
    }
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        u32 v = Y[7 - i];
        out[33 + i * 4 + 0] = (u8)(v >> 24);
        out[33 + i * 4 + 1] = (u8)(v >> 16);
        out[33 + i * 4 + 2] = (u8)(v >> 8);
        out[33 + i * 4 + 3] = (u8)v;
    }
}

}  // namespace cw_amd
