#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <random>
#include <cassert>
#include <bit>

#include "../include/crypto/sha512.hpp"

namespace {

using Clock = std::chrono::high_resolution_clock;

// =========================================================================
// SHA512_Baseline: Implementação de referência histórica (feed-forward escalar)
// Usada para comparar permanentemente contra a versão oficial crypto::SHA512 (UInt SIMD)
// =========================================================================
class SHA512_Baseline {
public:
    static constexpr size_t DIGEST_SIZE = 64;
    static constexpr size_t BLOCK_SIZE  = 128;

    SHA512_Baseline() noexcept { reset(); }

    void reset() noexcept {
        h_[0] = 0x6a09e667f3bcc908ULL;
        h_[1] = 0xbb67ae8584caa73bULL;
        h_[2] = 0x3c6ef372fe94f82bULL;
        h_[3] = 0xa54ff53a5f1d36f1ULL;
        h_[4] = 0x510e527fade682d1ULL;
        h_[5] = 0x9b05688c2b3e6c1fULL;
        h_[6] = 0x1f83d9abfb41bd6bULL;
        h_[7] = 0x5be0cd19137e2179ULL;
        total_len_ = 0;
        buf_len_   = 0;
    }

    void process_block(const uint8_t block[BLOCK_SIZE]) noexcept {
        static constexpr uint64_t K512[80] = {
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

        auto Ch  = [](uint64_t x, uint64_t y, uint64_t z) noexcept { return z ^ (x & (y ^ z)); };
        auto Maj = [](uint64_t x, uint64_t y, uint64_t z) noexcept { return (x & y) | (z & (x | y)); };
        auto BSig0 = [](uint64_t x) noexcept { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); };
        auto BSig1 = [](uint64_t x) noexcept { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); };
        auto SSig0 = [](uint64_t x) noexcept { return std::rotr(x, 1) ^ std::rotr(x, 8) ^ (x >> 7); };
        auto SSig1 = [](uint64_t x) noexcept { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); };

        uint64_t W[16];
        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            uint64_t v;
            std::memcpy(&v, block + i * 8, 8);
            W[i] = __builtin_bswap64(v);
        }

        uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

        #pragma GCC unroll 16
        for (int i = 0; i < 16; ++i) {
            const uint64_t t1 = h + BSig1(e) + Ch(e, f, g) + K512[i] + W[i];
            const uint64_t t2 = BSig0(a) + Maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        for (int r = 1; r < 5; ++r) {
            #pragma GCC unroll 16
            for (int i = 0; i < 16; ++i) {
                W[i] += SSig0(W[(i + 1) & 15]) + W[(i + 9) & 15] + SSig1(W[(i + 14) & 15]);
                const uint64_t t1 = h + BSig1(e) + Ch(e, f, g) + K512[r * 16 + i] + W[i];
                const uint64_t t2 = BSig0(a) + Maj(a, b, c);
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
            }
        }

        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }

    void update(const void* data, size_t len) noexcept {
        if (len == 0) return;
        const auto* p = static_cast<const uint8_t*>(data);
        total_len_ += len;

        if (buf_len_ > 0) {
            const size_t needed = BLOCK_SIZE - buf_len_;
            if (len < needed) {
                std::memcpy(buf_ + buf_len_, p, len);
                buf_len_ += len;
                return;
            }
            std::memcpy(buf_ + buf_len_, p, needed);
            process_block(buf_);
            p += needed;
            len -= needed;
            buf_len_ = 0;
        }

        while (len >= BLOCK_SIZE) {
            process_block(p);
            p += BLOCK_SIZE;
            len -= BLOCK_SIZE;
        }

        if (len > 0) {
            std::memcpy(buf_, p, len);
            buf_len_ = len;
        }
    }

    void finalize(uint8_t out[DIGEST_SIZE]) noexcept {
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 112) {
            std::memset(buf_ + buf_len_, 0, BLOCK_SIZE - buf_len_);
            process_block(buf_);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, 112 - buf_len_);

        const uint64_t bit_len_hi = __builtin_bswap64(total_len_ >> 61);
        const uint64_t bit_len_lo = __builtin_bswap64(total_len_ << 3);
        std::memcpy(buf_ + 112, &bit_len_hi, 8);
        std::memcpy(buf_ + 120, &bit_len_lo, 8);
        process_block(buf_);

        for (int i = 0; i < 8; ++i) {
            const uint64_t be = __builtin_bswap64(h_[i]);
            std::memcpy(out + i * 8, &be, 8);
        }
    }

    static void hash(const void* data, size_t len, uint8_t out[DIGEST_SIZE]) noexcept {
        SHA512_Baseline ctx;
        ctx.update(data, len);
        ctx.finalize(out);
    }

private:
    uint64_t h_[8];
    uint8_t  buf_[BLOCK_SIZE];
    uint64_t total_len_ = 0;
    size_t   buf_len_   = 0;
};

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return oss.str();
}

void print_banner(const std::string& title) {
    std::cout << "\n======================================================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "======================================================================\n";
}

} // namespace

int main() {
    print_banner("BATERIA 1: VETORES OFICIAIS NIST FIPS 180-4");
    std::cout << "  Comparando: [Baseline Escalar] vs [crypto::SHA512 Otimizado]\n\n";

    struct TestCase {
        std::string name;
        std::string input;
        std::string expected_hex;
        bool is_repeated_a = false;
        size_t repeat_count = 0;
    };

    std::vector<TestCase> nist_vectors = {
        {
            "NIST Vector 1: Mensagem Vazia (0 bytes)", "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            false, 0
        },
        {
            "NIST Vector 2: String 'abc'", "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            false, 0
        },
        {
            "NIST Vector 3: String de 112 bytes (fronteira exata de padding)",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            false, 0
        },
        {
            "NIST Vector 4: 1.000.000 de 'a's (Multi-bloco massivo)", "",
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
            true, 1000000
        }
    };

    int nist_fails = 0;
    for (const auto& tc : nist_vectors) {
        uint8_t out_base[64];
        uint8_t out_current[64];

        if (tc.is_repeated_a) {
            std::vector<uint8_t> block_a(65536, 'a');
            SHA512_Baseline ctx_base;
            crypto::SHA512 ctx_current;
            size_t remaining = tc.repeat_count;
            while (remaining > 0) {
                size_t chunk = std::min(remaining, block_a.size());
                ctx_base.update(block_a.data(), chunk);
                ctx_current.update(block_a.data(), chunk);
                remaining -= chunk;
            }
            ctx_base.finalize(out_base);
            ctx_current.finalize(out_current);
        } else {
            SHA512_Baseline::hash(tc.input.data(), tc.input.size(), out_base);
            crypto::SHA512::hash(tc.input.data(), tc.input.size(), out_current);
        }

        std::string hex_base    = to_hex(out_base, 64);
        std::string hex_current = to_hex(out_current, 64);

        if (hex_base != tc.expected_hex) {
            std::cerr << "  [FALHA] " << tc.name << " (Baseline diverge do NIST!)\n";
            ++nist_fails;
        } else if (hex_current != tc.expected_hex) {
            std::cerr << "  [FALHA] " << tc.name << " (crypto::SHA512 diverge do NIST!)\n";
            std::cerr << "          Esperado: " << tc.expected_hex << "\n";
            std::cerr << "          Obtido:   " << hex_current << "\n";
            ++nist_fails;
        } else {
            std::cout << "  [PASS] " << tc.name << "\n";
            std::cout << "         Digest: " << hex_current.substr(0, 32) << "...\n";
        }
    }
    if (nist_fails > 0) return 1;

    print_banner("BATERIA 2: TESTES DIFERENCIAIS FUZZING (10.000+ MENSAGENS ALEATÓRIAS)");
    std::cout << "  Executando 10.000 amostras com tamanhos dinâmicos e de fronteira crítica...\n";

    std::mt19937_64 rng(0x1337BEEFCAFEULL);
    std::vector<size_t> boundary_sizes = {
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 65, 111, 112, 113,
        127, 128, 129, 239, 240, 255, 256, 257, 511, 512, 1023, 1024, 4096, 65536
    };

    for (size_t sz : boundary_sizes) {
        std::vector<uint8_t> buf(sz);
        for (size_t i = 0; i < sz; ++i) buf[i] = static_cast<uint8_t>(rng());
        uint8_t out_base[64], out_current[64];
        SHA512_Baseline::hash(buf.data(), buf.size(), out_base);
        crypto::SHA512::hash(buf.data(), buf.size(), out_current);
        if (std::memcmp(out_base, out_current, 64) != 0) {
            std::cerr << "  [FALHA] Discrepância na fronteira de tamanho " << sz << " bytes!\n";
            return 1;
        }
    }
    std::cout << "  [PASS] 30 tamanhos críticos de fronteira validados com 100% de coincidência.\n";

    constexpr size_t FUZZ_ITERS = 10000;
    std::uniform_int_distribution<size_t> len_dist(0, 4096);
    for (size_t iter = 0; iter < FUZZ_ITERS; ++iter) {
        size_t sz = len_dist(rng);
        std::vector<uint8_t> buf(sz);
        for (size_t i = 0; i < sz; ++i) buf[i] = static_cast<uint8_t>(rng());
        uint8_t out_base[64], out_current[64];
        SHA512_Baseline::hash(buf.data(), buf.size(), out_base);
        crypto::SHA512::hash(buf.data(), buf.size(), out_current);
        if (std::memcmp(out_base, out_current, 64) != 0) {
            std::cerr << "  [FALHA] Discrepância na iteração " << iter << " (tamanho " << sz << ")!\n";
            return 1;
        }
    }
    std::cout << "  [PASS] " << FUZZ_ITERS << " casos de fuzzing estocástico aprovados (0 divergências)!\n";

    print_banner("BATERIA 3: TESTES DE STREAMING / ATUALIZAÇÃO FRACIONADA");
    {
        std::vector<uint8_t> test_stream(12345);
        for (size_t i = 0; i < test_stream.size(); ++i) test_stream[i] = static_cast<uint8_t>(i ^ 0xA5);

        uint8_t one_shot[64];
        crypto::SHA512::hash(test_stream.data(), test_stream.size(), one_shot);

        crypto::SHA512 streamed_current;
        size_t offset = 0;
        std::uniform_int_distribution<size_t> chunk_dist(1, 250);
        while (offset < test_stream.size()) {
            size_t chunk = std::min(test_stream.size() - offset, chunk_dist(rng));
            streamed_current.update(test_stream.data() + offset, chunk);
            offset += chunk;
        }
        uint8_t streamed_out[64];
        streamed_current.finalize(streamed_out);

        if (std::memcmp(one_shot, streamed_out, 64) != 0) {
            std::cerr << "  [FALHA] Atualização fracionada diverge do digest one-shot!\n";
            return 1;
        }
        std::cout << "  [PASS] Digest fracionado em múltiplos pedaços aleatórios idêntico ao one-shot.\n";
    }

    // =========================================================================
    // BATERIA 4: MICROBENCHMARK 3 COLUNAS
    //   Baseline Escalar | crypto::SHA512 Atual | 2-Block Interleaved
    // A coluna "2x-Interl" chama dois crypto::SHA512::hash() consecutivos com
    // dados independentes (A e B) — o CPU OOO sobrepõe as cadeias aritméticas.
    // O throughput reportado é: total de bytes / tempo (como se fossem 1 hash/chamada).
    // =========================================================================
    print_banner("BATERIA 4: MICROBENCHMARK DE PERFORMANCE — 3 COLUNAS");
    std::cout << "  [Baseline]  = SHA512 escalar clássico\n";
    std::cout << "  [Atual]     = crypto::SHA512 otimizado (feed-forward direto, sem UInt spill)\n";
    std::cout << "  [2x-Interl] = 2 hashes independentes alternados (ILP máximo via OOO)\n\n";

    struct BenchPayload { std::string label; size_t size; size_t iters; };
    std::vector<BenchPayload> payloads = {
        {"64B   (PBKDF2 inner/outer block)",   64,    500000},
        {"128B  (1 Bloco completo SHA-512)",   128,   400000},
        {"1KB   (8 Blocos de compressão)",    1024,   100000},
        {"64KB  (512 Blocos de compressão)", 65536,     2000},
        {"1MB   (8192 Blocos massivos)",    1048576,     150}
    };

    std::cout << "  +-----------------------------------+----------------+----------------+----------------+----------+\n";
    std::cout << "  | Carga / Tamanho                   | Baseline (MB/s)| Atual    (MB/s)| 2x-Interl(MB/s)| vs Base  |\n";
    std::cout << "  +-----------------------------------+----------------+----------------+----------------+----------+\n";

    for (const auto& bp : payloads) {
        std::vector<uint8_t> dataA(bp.size, 0x5A);
        std::vector<uint8_t> dataB(bp.size, 0xA5);
        uint8_t dA[64], dB[64];

        // Baseline
        auto t0 = Clock::now();
        for (size_t i = 0; i < bp.iters; ++i)
            SHA512_Baseline::hash(dataA.data(), dataA.size(), dA);
        double sec_base = std::chrono::duration<double>(Clock::now() - t0).count();
        double mb_base = (double(bp.size * bp.iters) / (1024.0 * 1024.0)) / sec_base;

        // Atual (otimizado)
        auto t2 = Clock::now();
        for (size_t i = 0; i < bp.iters; ++i)
            crypto::SHA512::hash(dataA.data(), dataA.size(), dA);
        double sec_curr = std::chrono::duration<double>(Clock::now() - t2).count();
        double mb_curr = (double(bp.size * bp.iters) / (1024.0 * 1024.0)) / sec_curr;

        // 2-Block Interleaved: N/2 chamadas de 2 hashes independentes cada
        size_t half = (bp.iters + 1) / 2;
        auto t4 = Clock::now();
        for (size_t i = 0; i < half; ++i) {
            crypto::SHA512::hash(dataA.data(), dataA.size(), dA);
            crypto::SHA512::hash(dataB.data(), dataB.size(), dB);
        }
        double sec_ilv = std::chrono::duration<double>(Clock::now() - t4).count();
        // Throughput = (2 * half * bp.size) bytes processados / sec
        double mb_ilv = (double(2 * half * bp.size) / (1024.0 * 1024.0)) / sec_ilv;

        double sp_curr = mb_curr / mb_base;
        double sp_ilv  = mb_ilv  / mb_base;

        auto fmt_sp = [](double sp) -> std::string {
            std::ostringstream ss;
            if (sp >= 1.0) ss << "+" << std::fixed << std::setprecision(1) << ((sp-1.0)*100.0) << "%";
            else           ss << "-" << std::fixed << std::setprecision(1) << ((1.0-sp)*100.0) << "%";
            return ss.str();
        };

        (void)sp_curr; // coluna variação da coluna "atual" removida para simplificar
        std::cout << "  | " << std::left  << std::setw(33) << bp.label
                  << " | " << std::right << std::setw(12) << std::fixed << std::setprecision(2) << mb_base << " MB/s"
                  << " | " << std::right << std::setw(12) << std::fixed << std::setprecision(2) << mb_curr << " MB/s"
                  << " | " << std::right << std::setw(12) << std::fixed << std::setprecision(2) << mb_ilv  << " MB/s"
                  << " | " << std::right << std::setw(8)  << fmt_sp(sp_ilv) << " |\n";
    }
    std::cout << "  +-----------------------------------+----------------+----------------+----------------+----------+\n\n";
    std::cout << "  'vs Base' = throughput 2x-Interl vs Baseline (medida do ganho real de ILP).\n\n";

    std::cout << "======================================================================\n";
    std::cout << "  SUCESSO TOTAL: Todos os testes de exatidão e benchmarks concluídos!\n";
    std::cout << "======================================================================\n";
    return 0;
}
