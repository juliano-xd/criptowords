#include "../../include/search/checkpoint.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <vector>

#include "../../include/config.hpp"
#include "../../include/search/plan.hpp"

namespace cryptowords {

// =========================================================================
// Total space — deve casar com IOdometer::total_space.
// =========================================================================
uint64_t search_total_space(const OptimizedMnemonics& opt) noexcept {
    switch (opt.mode) {
        case SearchMode::Triplets:
            return opt.valid_triplets.size();
        case SearchMode::Pairs:
            return opt.valid_pairs.size();
        case SearchMode::Streaming: {
            const size_t M = opt.unknown_positions.size() - 1;
            uint64_t prod = 1;
            for (size_t i = 0; i < M; ++i) prod *= opt.wheels[i].size();
            return prod;
        }
        case SearchMode::Mixed: {
            uint64_t prod = 1;
            for (const auto& w : opt.wheels) prod *= w.size();
            return prod;
        }
    }
    return 0;
}

// =========================================================================
// Hash FNV-1a 64-bit — determinístico, sem dependência de ordem de vetores.
// =========================================================================
namespace {
    constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
    constexpr uint64_t FNV_PRIME  = 1099511628211ULL;

    inline void fnv1a_64(uint64_t& h, const void* data, size_t len) noexcept {
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i) {
            h ^= p[i];
            h *= FNV_PRIME;
        }
    }
}  // namespace

uint64_t compute_config_hash(const OptimizedMnemonics& opt, const AppConfig& cfg) noexcept {
    uint64_t h = FNV_OFFSET;
    fnv1a_64(h, opt.base_mnemonic.data(), opt.base_mnemonic.size() * sizeof(uint16_t));
    fnv1a_64(h, cfg.target.data(), cfg.target.size());
    fnv1a_64(h, cfg.passphrase.data(), cfg.passphrase.size());

    for (const auto& w : opt.wheels) {
        const uint32_t sz = static_cast<uint32_t>(w.size());
        fnv1a_64(h, &sz, sizeof(sz));
        fnv1a_64(h, w.words.data(), w.words.size() * sizeof(uint16_t));
    }
    for (auto [id, n] : opt.repeat_ids_exact) {
        const uint32_t packed = (static_cast<uint32_t>(id) << 8) | n;
        fnv1a_64(h, &packed, sizeof(packed));
    }

    // Modo, filtro de checksum e seed de random: qualquer mudança invalida
    // resume (a ordem de enumeração seria diferente).
    const uint32_t mode32 = static_cast<uint32_t>(opt.mode);
    const uint32_t cmode  = static_cast<uint32_t>(opt.checksum_mode);
    const uint8_t  r8     = opt.random ? 1 : 0;
    fnv1a_64(h, &mode32, sizeof(mode32));
    fnv1a_64(h, &cmode, sizeof(cmode));
    fnv1a_64(h, &r8, sizeof(r8));
    fnv1a_64(h, &opt.random_seed, sizeof(opt.random_seed));

    return h;
}

// =========================================================================
// CoverageSnapshot
//
// Usa `opt.original_wheels` (pré-entropy-trick) para descrever o espaço
// original — sem isso, uma execução futura poderia pular candidatos nunca
// testados (o wheel pós-trick tem apenas {e<<C}, não o wheel completo).
// =========================================================================
CoverageSnapshot make_coverage_snapshot(const OptimizedMnemonics& opt,
                                        const AppConfig& cfg) noexcept {
    CoverageSnapshot s;
    s.base_mnemonic = opt.base_mnemonic;
    s.distinct      = cfg.distinct;
    s.exact_counts  = cfg.repeat_ids;

    const auto& src_wheels = opt.original_wheels.empty() ? opt.wheels
                                                         : opt.original_wheels;
    s.allowed_at_position.reserve(src_wheels.size());
    for (const auto& w : src_wheels) {
        WordBitset bs{};
        for (uint16_t id : w) bitset_set(bs, id);
        s.allowed_at_position.push_back(bs);
    }

    uint64_t h = FNV_OFFSET;
    fnv1a_64(h, s.base_mnemonic.data(), s.base_mnemonic.size() * sizeof(uint16_t));
    for (const auto& bs : s.allowed_at_position)
        fnv1a_64(h, bs.data(), bs.size() * sizeof(uint64_t));
    for (auto [id, n] : s.exact_counts) {
        const uint32_t packed = (static_cast<uint32_t>(id) << 8) | n;
        fnv1a_64(h, &packed, sizeof(packed));
    }
    const uint8_t d8 = s.distinct ? 1 : 0;
    fnv1a_64(h, &d8, sizeof(d8));
    s.hash = h;

    return s;
}

bool snapshot_covers(const CoverageSnapshot& s,
                     const std::vector<uint16_t>& mn) noexcept {
    if (mn.size() != s.base_mnemonic.size()) return false;

    size_t var_idx = 0;
    for (size_t i = 0; i < mn.size(); ++i) {
        const uint16_t want = s.base_mnemonic[i];
        if (want != AppConfig::UNKNOWN_WORD) {
            if (mn[i] != want) return false;
        } else {
            if (var_idx >= s.allowed_at_position.size()) return false;
            if (!bitset_test(s.allowed_at_position[var_idx], mn[i])) return false;
            ++var_idx;
        }
    }

    for (auto [id, n] : s.exact_counts) {
        size_t cnt = 0;
        for (uint16_t v : mn) if (v == id) ++cnt;
        if (cnt != static_cast<size_t>(n)) return false;
    }

    if (s.distinct) {
        WordBitset seen{};
        for (uint16_t v : mn) {
            if (bitset_test(seen, v)) return false;
            bitset_set(seen, v);
        }
    }
    return true;
}

bool covered_by_any(const std::vector<CoverageSnapshot>& snaps,
                    const std::vector<uint16_t>& mn) noexcept {
    for (const auto& s : snaps)
        if (snapshot_covers(s, mn)) return true;
    return false;
}

// =========================================================================
// Serialização — buffer única, escrita/leitura em um fwrite/fread.
//
// Formato:
//   CheckpointHeader (48 B)
//   [Snapshot] × n_snapshots
//     u32 base_len | u32 n_pos | u32 n_rep | u8 distinct | u8 pad[3]
//     u64 hash
//     u16 base_mnemonic[base_len]
//     u64 bitset[32] × n_pos
//     u32 packed × n_rep
//   CheckpointThread × n_threads  (u64 linear_index, u64 processed)
// =========================================================================
namespace {

inline void append(std::vector<uint8_t>& buf, const void* p, size_t n) {
    const auto* b = static_cast<const uint8_t*>(p);
    buf.insert(buf.end(), b, b + n);
}

void write_snapshot(std::vector<uint8_t>& buf, const CoverageSnapshot& s) {
    const uint32_t base_len = static_cast<uint32_t>(s.base_mnemonic.size());
    const uint32_t n_pos    = static_cast<uint32_t>(s.allowed_at_position.size());
    const uint32_t n_rep    = static_cast<uint32_t>(s.exact_counts.size());
    const uint8_t  distinct = s.distinct ? 1 : 0;
    const uint8_t  pad[3]   = {};

    append(buf, &base_len, 4);
    append(buf, &n_pos,    4);
    append(buf, &n_rep,    4);
    append(buf, &distinct, 1);
    append(buf, pad,       3);
    append(buf, &s.hash,   8);

    if (base_len > 0)
        append(buf, s.base_mnemonic.data(), base_len * sizeof(uint16_t));

    for (const auto& bs : s.allowed_at_position)
        append(buf, bs.data(), bs.size() * sizeof(uint64_t));

    for (auto [id, n] : s.exact_counts) {
        const uint32_t packed = (static_cast<uint32_t>(id) << 8) | n;
        append(buf, &packed, 4);
    }
}

struct Reader {
    const uint8_t* p;
    const uint8_t* end;

    bool take(void* out, size_t n) noexcept {
        if (static_cast<size_t>(end - p) < n) return false;
        std::memcpy(out, p, n);
        p += n;
        return true;
    }
};

bool read_snapshot(Reader& r, CoverageSnapshot& s) {
    uint32_t base_len, n_pos, n_rep;
    uint8_t  distinct, pad[3];

    if (!r.take(&base_len, 4)) return false;
    if (!r.take(&n_pos,    4)) return false;
    if (!r.take(&n_rep,    4)) return false;
    if (!r.take(&distinct, 1)) return false;
    if (!r.take(pad,       3)) return false;
    if (!r.take(&s.hash,   8)) return false;

    if (base_len > 24 || n_pos > 24 || n_rep > 64) return false;

    s.base_mnemonic.resize(base_len);
    if (base_len > 0 && !r.take(s.base_mnemonic.data(),
                                base_len * sizeof(uint16_t))) return false;

    s.allowed_at_position.resize(n_pos);
    for (uint32_t i = 0; i < n_pos; ++i) {
        if (!r.take(s.allowed_at_position[i].data(),
                    s.allowed_at_position[i].size() * sizeof(uint64_t)))
            return false;
    }

    s.exact_counts.resize(n_rep);
    for (uint32_t i = 0; i < n_rep; ++i) {
        uint32_t packed;
        if (!r.take(&packed, 4)) return false;
        s.exact_counts[i] = {
            static_cast<uint16_t>((packed >> 8) & 0xFFFF),
            static_cast<uint8_t>(packed & 0xFF)
        };
    }

    s.distinct = (distinct != 0);
    return true;
}

}  // namespace

// =========================================================================
// Save
// =========================================================================
bool save_checkpoint(const std::string& path,
                     const OptimizedMnemonics& opt,
                     const AppConfig& cfg,
                     const std::vector<uint64_t>& linear_indices,
                     const std::vector<uint64_t>& processed,
                     const std::vector<CoverageSnapshot>& snapshots) noexcept {
    if (path.empty()) return false;
    if (linear_indices.size() != processed.size()) return false;

    CheckpointHeader hdr{};
    hdr.mode            = static_cast<uint32_t>(opt.mode);
    hdr.n_threads       = static_cast<uint32_t>(linear_indices.size());
    hdr.total_space     = search_total_space(opt);
    hdr.total_processed = 0;
    for (uint64_t p : processed) hdr.total_processed += p;
    hdr.save_timestamp  = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    hdr.checksum_bits   = static_cast<uint32_t>(opt.checksum_bits);
    hdr.n_snapshots     = static_cast<uint32_t>(snapshots.size());
    hdr.config_hash     = compute_config_hash(opt, cfg);

    // Serializa tudo em memória; uma única fwrite no final.
    std::vector<uint8_t> buf;
    buf.reserve(sizeof(hdr) + snapshots.size() * 320 +
                linear_indices.size() * sizeof(CheckpointThread));

    append(buf, &hdr, sizeof(hdr));
    for (const auto& s : snapshots) write_snapshot(buf, s);
    for (size_t t = 0; t < linear_indices.size(); ++t) {
        CheckpointThread ts{};
        ts.linear_index = linear_indices[t];
        ts.processed    = processed[t];
        append(buf, &ts, sizeof(ts));
    }

    const std::string tmp = path + ".tmp";
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) return false;

    const bool ok = (std::fwrite(buf.data(), 1, buf.size(), f) == buf.size());
    std::fclose(f);

    if (!ok) { std::remove(tmp.c_str()); return false; }

    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) { std::remove(tmp.c_str()); return false; }
    return true;
}

// =========================================================================
// Load
// =========================================================================
bool load_checkpoint(const std::string& path,
                     Checkpoint& out,
                     const OptimizedMnemonics& opt,
                     const AppConfig& cfg) noexcept {
    if (path.empty()) return false;

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    std::fseek(f, 0, SEEK_END);
    const long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) { std::fclose(f); return false; }

    std::vector<uint8_t> data(static_cast<size_t>(sz));
    const bool read_ok = (std::fread(data.data(), 1, data.size(), f) == data.size());
    std::fclose(f);
    if (!read_ok) return false;

    Reader r{data.data(), data.data() + data.size()};

    CheckpointHeader hdr{};
    if (!r.take(&hdr, sizeof(hdr))) return false;
    if (hdr.magic != CKPT_MAGIC || hdr.version != CKPT_VERSION) return false;

    out = Checkpoint{};
    out.header = hdr;

    out.snapshots.resize(hdr.n_snapshots);
    for (uint32_t i = 0; i < hdr.n_snapshots; ++i)
        if (!read_snapshot(r, out.snapshots[i])) return false;

    const uint64_t expected = compute_config_hash(opt, cfg);
    out.config_compatible = (expected == hdr.config_hash);

    if (out.config_compatible) {
        out.threads.resize(hdr.n_threads);
        for (uint32_t t = 0; t < hdr.n_threads; ++t) {
            if (!r.take(&out.threads[t], sizeof(CheckpointThread))) {
                out.threads.clear();
                out.config_compatible = false;
                break;
            }
        }
    }

    return true;
}

}  // namespace cryptowords
