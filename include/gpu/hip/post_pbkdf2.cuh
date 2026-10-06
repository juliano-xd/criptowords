#pragma once
#include "keccak256_amd.cuh"
#include "sha512_hmac_amd.cuh"
#include "secp256k1_amd.cuh"

namespace cw_amd {

// Deriva filho BIP-32 hardened ou normal.
__device__ __forceinline__ void bip32_derive_child(u8 priv_key[32],
                                                    u8 chain_code[32],
                                                    u32 index,
                                                    bool hardened,
                                                    const u32* __restrict__ g_table) {
    u8 data[37];
    if (hardened) {
        data[0] = 0x00;
#pragma unroll
        for (int i = 0; i < 32; ++i) data[1 + i] = priv_key[i];
    } else {
        u32 px[8], py[8];
        scalar_mul_g(priv_key, g_table, px, py);
        u8 pub33[33];
        export_pubkey_compressed(px, py, pub33);
#pragma unroll
        for (int i = 0; i < 33; ++i) data[i] = pub33[i];
    }
    data[33] = (u8)(index >> 24);
    data[34] = (u8)(index >> 16);
    data[35] = (u8)(index >> 8);
    data[36] = (u8)(index);

    u64 I[8];
    hmac_sha512_generic(chain_code, 32, data, 37, I);
    u8 Ib[64];
    hmac_sha512_extract_be(I, Ib);

    u32 IL_le[8], pk_le[8], new_le[8];
    be32_to_u32le(Ib, IL_le);
    be32_to_u32le(priv_key, pk_le);
    sc_add_n(new_le, pk_le, IL_le);
    u32le_to_be32(new_le, priv_key);

#pragma unroll
    for (int i = 0; i < 32; ++i) chain_code[i] = Ib[32 + i];
}

// Kernel post-PBKDF2 para ETH.
//
// Recebe N seeds de 64 bytes (produzidas pelo PBKDF2 SIMD da CPU) e devolve
// o índice do primeiro seed cujo endereço ETH bate com o alvo, ou 0xFFFFFFFF.
//
//   seeds       : N × 64 B (raw BIP-39 seed, output do PBKDF2)
//   target      : 20 B do endereço ETH
//   target_fast : primeiros 8 B do alvo, u64 native
//   g_table     : 256 × 16 u32 (256 pontos afins 2^i · G)
//   result_idx  : 1 u32 — 0xFFFFFFFF se ninguém bateu
extern "C" __global__ __launch_bounds__(64)
void post_pbkdf2_eth_batch(const u8*  __restrict__ seeds,
                            u32        num_seeds,
                            const u8*  __restrict__ target,
                            u64        target_fast,
                            const u32* __restrict__ g_table,
                            u32*       __restrict__ result_idx)
{
    u32 gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= num_seeds) return;

    u8 seed[64];
#pragma unroll
    for (int i = 0; i < 64; ++i) seed[i] = seeds[gid * 64 + i];

    // ---- BIP-32 master ----
    u64 I_m[8];
    hmac_sha512_generic((const u8*)"Bitcoin seed", 12, seed, 64, I_m);
    u8 Ib[64];
    hmac_sha512_extract_be(I_m, Ib);

    u8 priv_key[32], chain_code[32];
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        priv_key[i]   = Ib[i];
        chain_code[i] = Ib[32 + i];
    }

    // ---- BIP-44: m/44'/60'/0'/0/0 ----
    constexpr u32 H = 0x80000000u;
    bip32_derive_child(priv_key, chain_code, 44u | H, true,  g_table);
    bip32_derive_child(priv_key, chain_code, 60u | H, true,  g_table);
    bip32_derive_child(priv_key, chain_code,  0u | H, true,  g_table);
    bip32_derive_child(priv_key, chain_code,  0u,     false, g_table);
    bip32_derive_child(priv_key, chain_code,  0u,     false, g_table);

    // ---- Pubkey ----
    u32 px[8], py[8];
    scalar_mul_g(priv_key, g_table, px, py);
    u8 pub65[65];
    export_pubkey_uncompressed(px, py, pub65);

    // ---- Keccak256(pubkey[1..64]) ----
    u8 hash[32];
    keccak256_eth_short(pub65 + 1, 64, hash);

    // Endereço = bytes 12..31 do hash
    u64 addr_fast;
    u8* afb = (u8*)&addr_fast;
#pragma unroll
    for (int i = 0; i < 8; ++i) afb[i] = hash[12 + i];

    if (addr_fast != target_fast) return;

#pragma unroll
    for (int i = 0; i < 12; ++i) {
        if (hash[20 + i] != target[8 + i]) return;
    }

    atomicCAS(result_idx, 0xFFFFFFFFu, gid);
}

}  // namespace cw_amd
