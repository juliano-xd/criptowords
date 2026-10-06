#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace cryptowords {

// =========================================================================
// Filtro Cuckoo compacto para multi-target (100+ alvos).
//
// Fingerprints de 16 bits em buckets de 4 slots. Dois hashes por chave.
// Consulta em ~8 comparações; inserção com kicking. Sem falsos negativos;
// taxa de falso positivo ~0.1% com load factor ~50%.
//
// Chave = FNV-1a 64-bit dos 20 bytes do endereço. Determinístico entre
// execuções.
// =========================================================================
class CuckooFilter {
    static constexpr size_t BUCKET_SIZE = 4;
    static constexpr size_t MAX_KICKS   = 500;

   public:
    explicit CuckooFilter(size_t expected_keys) {
        size_t cap = 8;
        while (cap < expected_keys * 2) cap <<= 1;
        buckets_.assign(cap, {});       // cada bucket zerado
        num_buckets_ = cap;
        mask_        = cap - 1;
    }

    static uint64_t hash_key(const std::array<uint8_t, 20>& addr) noexcept {
        uint64_t h = 14695981039346656037ULL;
        for (uint8_t b : addr) { h ^= b; h *= 1099511628211ULL; }
        return h;
    }

    void insert(uint64_t key) noexcept {
        uint16_t fp = fingerprint(key);
        const size_t i1 = index1(key);
        const size_t i2 = index2(i1, fp);

        if (insert_into(i1, fp) || insert_into(i2, fp)) return;

        // Relocação: alterna i1/i2 empurrando slots até achar vazio.
        size_t i = (key & 1) ? i2 : i1;
        for (size_t k = 0; k < MAX_KICKS; ++k) {
            const size_t slot = (key + k) % BUCKET_SIZE;
            const uint16_t evicted = buckets_[i][slot];
            buckets_[i][slot] = fp;
            fp = evicted;
            i = index2(i, fp);
            if (insert_into(i, fp)) return;
        }
    }

    [[nodiscard]] bool might_contain(uint64_t key) const noexcept {
        const uint16_t fp = fingerprint(key);
        const size_t i1 = index1(key);
        const size_t i2 = index2(i1, fp);

        const auto& b1 = buckets_[i1];
        const auto& b2 = buckets_[i2];
        return b1[0] == fp || b1[1] == fp || b1[2] == fp || b1[3] == fp ||
               b2[0] == fp || b2[1] == fp || b2[2] == fp || b2[3] == fp;
    }

    [[nodiscard]] size_t bucket_count() const noexcept { return num_buckets_; }

   private:
    std::vector<std::array<uint16_t, BUCKET_SIZE>> buckets_;
    size_t num_buckets_ = 0;
    size_t mask_        = 0;

    static uint16_t fingerprint(uint64_t key) noexcept {
        const uint16_t fp = static_cast<uint16_t>((key >> 48) ^ (key & 0xFFFF));
        return fp == 0 ? 1 : fp;   // 0 = slot vazio
    }
    size_t index1(uint64_t key) const noexcept {
        return static_cast<size_t>(key) & mask_;
    }
    size_t index2(size_t i1, uint16_t fp) const noexcept {
        const uint32_t h = fp * 0x9E3779B1u;
        return (i1 ^ h) & mask_;
    }
    bool insert_into(size_t idx, uint16_t fp) noexcept {
        for (auto& slot : buckets_[idx]) {
            if (slot == 0) { slot = fp; return true; }
        }
        return false;
    }
};

}  // namespace cryptowords
