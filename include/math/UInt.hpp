#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <endian.h>
#include <iterator>
#include <format>
#include <immintrin.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <cassert>
#include <vector>

#include "Division.hpp"
#include "Multiplication.hpp"

using u8  = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using u128 = unsigned __int128;

#define FORCE_INLINE inline __attribute__((always_inline))
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

enum class Backend : bool {
    Scalar = false,
    SIMD   = true
};

enum class Endianness : int {
    little = __ORDER_LITTLE_ENDIAN__,
    big    = __ORDER_BIG_ENDIAN__
};

enum class BitOrder : int {
    LSB = 0,
    MSB = 1
};

template <u8 N>
class alignas(64) UInt {
    static_assert(N > 0 && N <= 255, "Lane count must be in [1, 255]");

private:
    Backend mode_ = Backend::Scalar;
    Endianness endian_ = static_cast<Endianness>(__BYTE_ORDER__);

    FORCE_INLINE constexpr u64 rand(u64& state) const noexcept {
        state += 0x9e3779b97f4a7c15ULL;
        u64 result = state;
        result = (result ^ (result >> 30)) * 0xbf58476d1ce4e5b9ULL;
        result = (result ^ (result >> 27)) * 0x94d049bb133111ebULL;
        return result ^ (result >> 31);
    }

    template <std::unsigned_integral T, std::size_t M>
    FORCE_INLINE void load_array_impl(const T (&values)[M], BitOrder order) noexcept {
        constexpr std::size_t W = std::numeric_limits<T>::digits;
        constexpr u16 CAPACITY = N * 64;
        static_assert(W > 0 && W <= 64, "Array element type must contain at most 64 bits");
        static_assert(M <= (CAPACITY + W - 1) / W, "Array contains more bits than UInt capacity");

        bits.fill(0);

        for (std::size_t i = 0; i < M; ++i) {
            const std::size_t bit_offset = (order == BitOrder::LSB)
                ? i * W
                : CAPACITY - ((i + 1) * W);

            const std::size_t limb = bit_offset >> 6;
            if (limb >= N) continue;
            const unsigned shift = static_cast<unsigned>(bit_offset & 63);
            const u64 value = static_cast<u64>(values[i]);

            bits[limb] |= value << shift;
            if (shift + W > 64 && limb + 1 < N) {
                bits[limb + 1] |= value >> (64 - shift);
            }
        }
    }

    template <std::unsigned_integral T, u16 M>
    FORCE_INLINE void load_array_impl(const std::array<T, M>& values, BitOrder order) noexcept {
        load_array_impl(values.data(), order);
    }

    FORCE_INLINE void reverse_endianness_internal() noexcept {
        for (u8 i = 0; i < N / 2; ++i) {
            const u8 j = static_cast<u8>(N - 1 - i);
            std::swap(bits[i], bits[j]);
        }
    }

public:

    std::array<u64, N> bits{};

    constexpr UInt() noexcept = default;
    constexpr UInt(const UInt& o) noexcept = default;
    constexpr UInt(UInt&& o) noexcept = default;
    constexpr UInt& operator=(const UInt& o) noexcept = default;
    constexpr UInt& operator=(UInt&& o) noexcept = default;

    constexpr UInt(u64 v) noexcept {
        bits.fill(0);
        bits[0] = v;
    }

    explicit operator u64() const {
        if constexpr (N > 1) {
            for (u8 i = 1; i < N; ++i) {
                if (bits[i] != 0) throw std::overflow_error("UInt overflows u64");
            }
        }
        return bits[0];
    }

    explicit operator bool() const noexcept {
        return !this->eqz();
    }

    explicit operator std::string() const {
        return this->to_string();
    }

    UInt(std::initializer_list<u64> il) {
        bits.fill(0);
        u8 count = static_cast<u8>(il.size());
        if (count > N) throw std::out_of_range("Initializer list too long");
        u8 i = 0;
        for (u64 v : il) {
            bits[i++] = v;
        }
    }

    explicit UInt(const u8* ptr, size_t len, BitOrder order = BitOrder::LSB) noexcept {
        bits.fill(0);
        if (ptr == nullptr || len == 0) return;
        if (order == BitOrder::LSB) {
            const size_t full_words = std::min(len >> 3, static_cast<size_t>(N));
            for (size_t w = 0; w < full_words; ++w) {
                u64 v;
                std::memcpy(&v, ptr + (w << 3), 8);
                bits[w] = v;
            }
            const size_t rem = len - (full_words << 3);
            if (rem > 0 && full_words < N) {
                u64 v = 0;
                std::memcpy(&v, ptr + (full_words << 3), rem);
                bits[full_words] = v;
            }
        } else {
            if (len == N * 8) {
                #pragma GCC unroll 8
                for (size_t w = 0; w < N; ++w) {
                    u64 v;
                    std::memcpy(&v, ptr + (w << 3), 8);
                    bits[N - 1 - w] = __builtin_bswap64(v);
                }
            } else {
                for (size_t i = 0; i < len && i < N * 8; ++i) {
                    const size_t byte_pos = N * 8 - 1 - i;
                    const size_t limb_idx = byte_pos >> 3;
                    const size_t bit_idx = byte_pos & 7;
                    bits[limb_idx] |= static_cast<u64>(ptr[i]) << (bit_idx << 3);
                }
            }
        }
    }

    template<typename InputIt>
        requires std::input_or_output_iterator<InputIt>
    explicit UInt(InputIt first, InputIt last, BitOrder order = BitOrder::LSB) {
        bits.fill(0);
        std::vector<u8> bytes(first, last);
        if (bytes.empty()) return;
        *this = UInt<N>(bytes.data(), bytes.size(), order);
    }

    template <u8 M>
    UInt(const UInt<M>& other) noexcept {
        bits.fill(0);
        constexpr u8 count = (M < N) ? M : N;
        for (u8 i = 0; i < count; ++i) {
            bits[i] = other.bits[i];
        }
    }

    template <u8 M>
    UInt& operator=(const UInt<M>& other) noexcept {
        bits.fill(0);
        constexpr u8 count = (M < N) ? M : N;
        for (u8 i = 0; i < count; ++i) {
            bits[i] = other.bits[i];
        }
        return *this;
    }

    template <std::convertible_to<u64>... Args>
        requires (sizeof...(Args) > 1 && sizeof...(Args) <= N)
    constexpr explicit UInt(Args... args) noexcept {
        bits.fill(0);
        u8 idx = 0;
        ((bits[idx++] = static_cast<u64>(args)), ...);
    }

    template <std::unsigned_integral T, std::size_t M>
    explicit UInt(const T (&values)[M], BitOrder order = BitOrder::LSB) noexcept {
        load_array_impl<T, M>(values, order);
    }

    template <std::unsigned_integral T, u16 M>
    explicit UInt(const std::array<T, M>& values, BitOrder order = BitOrder::LSB) noexcept {
        load_array_impl<T, M>(values, order);
    }

    constexpr explicit UInt(std::string_view sv) {
        if (sv.empty()) return;
        if (sv.front() == '-') throw std::invalid_argument("Negative values not supported");
        if (sv.front() == '+') sv.remove_prefix(1);

        if (sv.starts_with("0x") || sv.starts_with("0X")) {
            sv.remove_prefix(2);
            if (sv.empty()) return;
            if (sv.size() > (N * 16)) throw std::out_of_range("Hex string too long");

            size_t len = sv.size();
            for (u8 i = 0; i < N && len > 0; ++i) {
                const size_t chunk_sz = std::min<size_t>(16, len);
                const size_t start = len - chunk_sz;
                u64 chunk_val = 0;
                auto res = std::from_chars(sv.data() + start, sv.data() + start + chunk_sz, chunk_val, 16);
                if (res.ec != std::errc{}) throw std::invalid_argument("Invalid hex character");
                bits[i] = chunk_val;
                len -= chunk_sz;
            }
        } else {
            constexpr u64 CHUNK_POW = 1'000'000'000'000'000'000ull;
            constexpr int CHUNK_SIZE = 18;
            size_t remaining = sv.size() % CHUNK_SIZE;
            if (remaining == 0 && !sv.empty()) remaining = CHUNK_SIZE;
            u64 chunk_val = 0;
            auto res = std::from_chars(sv.data(), sv.data() + remaining, chunk_val, 10);
            if (res.ec != std::errc{}) throw std::invalid_argument("Invalid decimal character");
            bits[0] = chunk_val;
            for (size_t i = remaining; i < sv.size(); i += CHUNK_SIZE) {
                std::from_chars(sv.data() + i, sv.data() + i + CHUNK_SIZE, chunk_val, 10);
                *this *= UInt<N>(CHUNK_POW);
                *this += UInt<N>(chunk_val);
            }
        }
    }

    void set_mode(Backend m) noexcept { mode_ = m; }
    void set_endianness(Endianness e) noexcept {
        if (endian_ != e) {
            endian_ = e;
            reverse_endianness_internal();
        }
    }

    [[nodiscard]] Backend mode() const noexcept { return mode_; }
    [[nodiscard]] Endianness endianness() const noexcept { return endian_; }

    [[nodiscard]] bool is_scalar() const noexcept { return mode_ == Backend::Scalar; }
    [[nodiscard]] bool is_simd()   const noexcept { return mode_ == Backend::SIMD; }

    template <u8 M>
    [[nodiscard]] UInt<M> truncate() const noexcept {
        UInt<M> result;
        constexpr u8 count = (M < N) ? M : N;
        for (u8 i = 0; i < count; ++i) {
            result.bits[i] = bits[i];
        }
        return result;
    }

    [[nodiscard]] u8 num_limbs() const noexcept {
        for (u8 i = N; i-- > 0;) {
            if (bits[i] != 0) return i + 1;
        }
        return 0;
    }

    [[nodiscard]] u16 bit_length() const noexcept {
        for (u8 i = N; i-- > 0;) {
            if (bits[i] != 0) {
                return static_cast<u16>(i * 64 + 64 - std::countl_zero(bits[i]));
            }
        }
        return 0;
    }

    template <Backend TargetMode>
    [[nodiscard]] FORCE_INLINE UInt<N>& as() noexcept {
        static_assert(sizeof(UInt<N>) == sizeof(UInt<N>), "Memory layout mismatch");
        return *this;
    }

    template <Backend TargetMode>
    [[nodiscard]] FORCE_INLINE const UInt<N>& as() const noexcept {
        return *this;
    }

    [[nodiscard]] FORCE_INLINE constexpr bool operator==(const UInt& other) const noexcept {
        if consteval {
            for (u8 i = 0; i < N; ++i) {
                if (bits[i] != other.bits[i]) return false;
            }
            return true;
        } else {
            size_t i = 0;
#if defined(__AVX512F__)
            for (; i + 8 <= N; i += 8) {
                __m512i a = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
                __m512i b = _mm512_loadu_si512(reinterpret_cast<const void*>(other.bits.data() + i));
                if (_mm512_cmpeq_epi64_mask(a, b) != 0xFF) return false;
            }
#endif
#if defined(__AVX2__)
            for (; i + 4 <= N; i += 4) {
                __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
                __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(other.bits.data() + i));
                __m256i x = _mm256_xor_si256(a, b);
                if (!_mm256_testz_si256(x, x)) return false;
            }
#elif defined(__SSE2__)
            for (; i + 2 <= N; i += 2) {
                __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
                __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(other.bits.data() + i));
                __m128i eq = _mm_cmpeq_epi32(a, b);
                if (_mm_movemask_epi8(eq) != 0xFFFF) return false;
            }
#endif
            for (; i < N; ++i) {
                if (bits[i] != other.bits[i]) return false;
            }
            return true;
        }
    }

    [[nodiscard]] FORCE_INLINE constexpr auto operator<=>(const UInt& other) const noexcept {
        for (int i = N - 1; i >= 0; --i) {
            if (bits[i] != other.bits[i]) {
                return bits[i] <=> other.bits[i];
            }
        }
        return std::strong_ordering::equal;
    }

    FORCE_INLINE UInt& operator+=(const UInt& other) noexcept {
        if (mode_ == Backend::SIMD) {
            size_t i = 0;
#if defined(__AVX512F__)
            for (; i + 8 <= N; i += 8) {
                __m512i a = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
                __m512i b = _mm512_loadu_si512(reinterpret_cast<const void*>(other.bits.data() + i));
                _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_add_epi64(a, b));
            }
#endif
#if defined(__AVX2__)
            for (; i + 4 <= N; i += 4) {
                __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
                __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(other.bits.data() + i));
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_add_epi64(a, b));
            }
#elif defined(__SSE2__)
            for (; i + 2 <= N; i += 2) {
                __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
                __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(other.bits.data() + i));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_add_epi64(a, b));
            }
#endif
            for (; i < N; ++i) bits[i] += other.bits[i];
        } else {
            if consteval {
                u64 carry = 0;
                for (u8 i = 0; i < N; ++i) {
                    u128 sum = static_cast<u128>(bits[i]) + other.bits[i] + carry;
                    bits[i] = static_cast<u64>(sum);
                    carry = static_cast<u64>(sum >> 64);
                }
            } else {
                asm volatile(R"(
                    .set offset, 0
                    movq offset(%[src]), %%rax
                    addq %%rax, offset(%[dst])
                    .set offset, offset+8
                    .rept %c[count]
                        movq offset(%[src]), %%rax
                        adcq %%rax, offset(%[dst])
                        .set offset, offset+8
                    .endr
                )"
                    : "+m"(bits)
                    : [dst] "r"(bits.data()), [src] "r"(other.bits.data()),
                      [count] "n"(N - 1), "m"(other.bits)
                    : "rax", "cc"
                );
            }
        }
        return *this;
    }

    FORCE_INLINE uint8_t add_carry(const UInt& other) noexcept {
        if (mode_ == Backend::SIMD) {
            *this += other;
            return 0;
        }
        if consteval {
            u64 carry = 0;
            for (u8 i = 0; i < N; ++i) {
                u128 sum = static_cast<u128>(bits[i]) + other.bits[i] + carry;
                bits[i] = static_cast<u64>(sum);
                carry = static_cast<u64>(sum >> 64);
            }
            return static_cast<uint8_t>(carry);
        } else {
            unsigned char c = 0;
            for (u8 i = 0; i < N; ++i) {
                c = _addcarry_u64(c, bits[i], other.bits[i], reinterpret_cast<unsigned long long*>(&bits[i]));
            }
            return c;
        }
    }

    FORCE_INLINE uint8_t sub_borrow(const UInt& other) noexcept {
        if (mode_ == Backend::SIMD) {
            *this -= other;
            return 0;
        }
        if consteval {
            u64 borrow = 0;
            for (u8 i = 0; i < N; ++i) {
                u128 sub = static_cast<u128>(bits[i]) - other.bits[i] - borrow;
                bits[i] = static_cast<u64>(sub);
                borrow = static_cast<u64>((sub >> 64) & 1);
            }
            return static_cast<uint8_t>(borrow);
        } else {
            unsigned char b = 0;
            for (u8 i = 0; i < N; ++i) {
                b = _subborrow_u64(b, bits[i], other.bits[i], reinterpret_cast<unsigned long long*>(&bits[i]));
            }
            return b;
        }
    }

    FORCE_INLINE UInt& operator-=(const UInt& other) noexcept {
        if (mode_ == Backend::SIMD) {
            size_t i = 0;
#if defined(__AVX512F__)
            for (; i + 8 <= N; i += 8) {
                __m512i a = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
                __m512i b = _mm512_loadu_si512(reinterpret_cast<const void*>(other.bits.data() + i));
                _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_sub_epi64(a, b));
            }
#endif
#if defined(__AVX2__)
            for (; i + 4 <= N; i += 4) {
                __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
                __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(other.bits.data() + i));
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_sub_epi64(a, b));
            }
#elif defined(__SSE2__)
            for (; i + 2 <= N; i += 2) {
                __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
                __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(other.bits.data() + i));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_sub_epi64(a, b));
            }
#endif
            for (; i < N; ++i) bits[i] -= other.bits[i];
        } else {
            if consteval {
                u64 borrow = 0;
                for (u8 i = 0; i < N; ++i) {
                    u128 sub = static_cast<u128>(bits[i]) - other.bits[i] - borrow;
                    bits[i] = static_cast<u64>(sub);
                    borrow = static_cast<u64>((sub >> 64) & 1);
                }
            } else {
                asm volatile(R"(
                    .set offset, 0
                    movq offset(%[src]), %%rax
                    subq %%rax, offset(%[dst])
                    .set offset, offset+8
                    .rept %c[count]
                        movq offset(%[src]), %%rax
                        sbbq %%rax, offset(%[dst])
                        .set offset, offset+8
                    .endr
                )"
                    : "+m"(bits)
                    : [dst] "r"(bits.data()), [src] "r"(other.bits.data()),
                      [count] "n"(N - 1), "m"(other.bits)
                    : "rax", "cc"
                );
            }
        }
        return *this;
    }

    UInt& mul_consteval(const UInt& other) noexcept {
        UInt<N> self_copy = *this;
        bits.fill(0);
        for (u8 i = 0; i < N; ++i) {
            const u64 y = self_copy.bits[i];
            if (y == 0) continue;
            u128 carry = 0;
            for (u8 j = 0; j < N - i; ++j) {
                u128 temp = static_cast<u128>(other.bits[j]) * y + bits[i + j] + carry;
                bits[i + j] = static_cast<u64>(temp);
                carry = temp >> 64;
            }
        }
        return *this;
    }

    FORCE_INLINE UInt& mul_runtime(const UInt& other) noexcept {
        if constexpr (N == 1) {
            bits[0] *= other.bits[0];
        } else if constexpr (N <= 8) {
            u64 p_res[N];
            if constexpr (N == 2) {
                u64 a0 = bits[0], a1 = bits[1];
                u64 b0 = other.bits[0], b1 = other.bits[1];
                u128 prod = static_cast<u128>(a0) * b0;
                u64 lo_ab = static_cast<u64>(prod);
                u64 hi_ab = static_cast<u64>(prod >> 64);
                u64 t1 = a0 * b1;
                u64 t2 = a1 * b0;
                bits[0] = lo_ab;
                bits[1] = t1 + hi_ab + t2;
            } else if constexpr (N == 3) {
                u64 a0 = bits[0], a1 = bits[1], a2 = bits[2];
                u64 b0 = other.bits[0], b1 = other.bits[1], b2 = other.bits[2];
                u64 r0, r1, r2;
                __asm__ volatile(R"(
                    movq   %[b0], %%rdx
                    mulxq  %[a0], %[r0], %[r1]
                    xorl   %k[r2], %k[r2]
                    movq   %[b2], %%r10
                    imulq  %[a0], %%r10
                    movq   %[b1], %%rdx
                    mulxq  %[a0], %%r11, %%rcx
                    addq   %%r11, %[r1]
                    adcq   %%rcx, %[r2]
                    movq   %[a2], %%rcx
                    movq   %[a1], %%rdx
                    mulxq  %[b0], %%r11, %%r9
                    imulq  %[b0], %%rcx
                    addq   %%r11, %[r1]
                    adcq   %%r9, %[r2]
                    imulq  %[b1], %%rdx
                    addq   %%rdx, %%r10
                    addq   %%rcx, %%r10
                    addq   %%r10, %[r2]
                )"
                    : [r0] "=&r"(r0), [r1] "=&r"(r1), [r2] "=&r"(r2)
                    : [a0] "rm"(a0), [a1] "rm"(a1), [a2] "rm"(a2),
                      [b0] "rm"(b0), [b1] "rm"(b1), [b2] "rm"(b2)
                    : "rdx", "r9", "r10", "r11", "rcx", "cc"
                );
                bits[0] = r0; bits[1] = r1; bits[2] = r2;
            } else if constexpr (N == 4) {
                __asm__ volatile(R"(
                    xorl   %%r9d, %%r9d
                    xorl   %%eax, %%eax
                    xorl   %%r10d, %%r10d
                    xorl   %%r8d, %%r8d
                    movq   %[a0], %%rdx
                    mulxq  %[b0], %%rcx, %%rsi
                    addq   %%rcx, %%r9
                    adcq   %%rsi, %%rax
                    mulxq  %[b1], %%rcx, %%rsi
                    addq   %%rcx, %%rax
                    adcq   %%rsi, %%r10
                    adcq   $0, %%r8
                    mulxq  %[b2], %%rcx, %%rsi
                    addq   %%rcx, %%r10
                    adcq   %%rsi, %%r8
                    imulq  %[b3], %%rdx
                    addq   %%rdx, %%r8
                    movq   %[a1], %%rdx
                    mulxq  %[b0], %%rcx, %%rsi
                    addq   %%rcx, %%rax
                    adcq   %%rsi, %%r10
                    adcq   $0, %%r8
                    mulxq  %[b1], %%rcx, %%rsi
                    addq   %%rcx, %%r10
                    adcq   %%rsi, %%r8
                    imulq  %[b2], %%rdx
                    addq   %%rdx, %%r8
                    movq   %[a2], %%rdx
                    mulxq  %[b0], %%rcx, %%rsi
                    addq   %%rcx, %%r10
                    adcq   %%rsi, %%r8
                    imulq  %[b1], %%rdx
                    addq   %%rdx, %%r8
                    movq   %[a3], %%rdx
                    imulq  %[b0], %%rdx
                    addq   %%rdx, %%r8
                    movq   %%r9,  %[a0]
                    movq   %%rax, %[a1]
                    movq   %%r10, %[a2]
                    movq   %%r8,  %[a3]
                )"
                    : [a0] "+m"(bits[0]), [a1] "+m"(bits[1]), [a2] "+m"(bits[2]), [a3] "+m"(bits[3])
                    : [b0] "m"(other.bits[0]), [b1] "m"(other.bits[1]),
                      [b2] "m"(other.bits[2]), [b3] "m"(other.bits[3])
                    : "rax", "rcx", "rdx", "rsi", "r8", "r9", "r10", "cc"
                );
            } else if constexpr (N == 8) {
                if (this == &other) {
                    Multiplication::square_schoolbook_truncated_fixed<8>(p_res, &bits[0]);
                } else {
                    Multiplication::mul_split_truncated_fixed_8(p_res, &bits[0], &other.bits[0]);
                }
                std::copy_n(p_res, N, &bits[0]);
            } else {
                if (this == &other) {
                    Multiplication::square_schoolbook_truncated_fixed<N>(p_res, &bits[0]);
                } else {
                    Multiplication::mul_schoolbook_truncated_fixed<N>(p_res, &bits[0], &other.bits[0]);
                }
                std::copy_n(p_res, N, &bits[0]);
            }
        } else {
            alignas(64) u64 tmp[8 * N + 1000];
            alignas(64) u64 buf[N];
            if (this == &other) {
                Multiplication::square_truncated_fixed<N>(buf, &bits[0], tmp);
            } else {
                Multiplication::mul_truncated_fixed<N>(buf, &bits[0], &other.bits[0], tmp);
            }
            std::copy_n(buf, N, &bits[0]);
        }
        return *this;
    }

    FORCE_INLINE UInt& operator*=(const UInt& other) noexcept {
        if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) bits[i] *= other.bits[i];
        } else {
            if consteval {
                return mul_consteval(other);
            }
            return mul_runtime(other);
        }
        return *this;
    }

    std::pair<UInt<N>, UInt<N>> divmod(UInt<N> v) const {
        if (mode_ == Backend::SIMD) {
            UInt<N> q{};
            UInt<N> r{};
            for (u8 i = 0; i < N; ++i) {
                if (v.bits[i] == 0) throw std::domain_error("Division by zero");
                q.bits[i] = bits[i] / v.bits[i];
                r.bits[i] = bits[i] % v.bits[i];
            }
            return {q, r};
        }

        if (v.eqz()) throw std::domain_error("Division by zero");

        if consteval {
            if (*this < v) return {UInt<N>(0), *this};
            UInt<N> q(0);
            UInt<N> r(0);
            for (int i = N * 64 - 1; i >= 0; --i) {
                r <<= 1;
                if ((bits[i / 64] >> (i % 64)) & 1) r.bits[0] |= 1;
                if (r >= v) { r -= v; q.bits[i / 64] |= (1ULL << (i % 64)); }
            }
            return {q, r};
        }

        if (*this < v) return {UInt<N>(0), *this};
        if (*this == v) return {UInt<N>(1), UInt<N>(0)};

        if constexpr (N > 1) {
            bool single_limb = true;
            for (u8 i = 1; i < N; ++i) {
                if (v.bits[i] != 0) { single_limb = false; break; }
            }
            if (single_limb) {
                auto [q, r_u64] = divmod(v.bits[0]);
                return {q, UInt<N>(r_u64)};
            }
        }

        UInt<N> q{};
        UInt<N> r{};
        if constexpr (N <= 16) {
            Division::DivisionFixed<N>::div(q.bits.data(), r.bits.data(), bits.data(), v.bits.data());
        } else {
            Division::div_knuth_impl<N>(q.bits.data(), r.bits.data(), bits.data(), num_limbs(), v.bits.data(), v.num_limbs());
        }
        return {q, r};
    }

    [[nodiscard]] std::pair<UInt<N>, u64> divmod(u64 v) const {
        if (v == 0) throw std::domain_error("Division by zero");
        if (mode_ == Backend::SIMD) {
            UInt<N> q{};
            for (u8 i = 0; i < N; ++i) {
                q.bits[i] = bits[i] / v;
            }
            return {q, bits[0] % v};
        }
        UInt<N> q{};
        q.set_mode(mode_);
        q.set_endianness(endian_);
        u64 rem = 0;
        for (int i = N - 1; i >= 0; --i) {
            u128 cur = (static_cast<u128>(rem) << 64) | bits[i];
            q.bits[i] = static_cast<u64>(cur / v);
            rem = static_cast<u64>(cur % v);
        }
        return {q, rem};
    }

    FORCE_INLINE UInt& operator/=(const UInt& other) {
        if (other.eqz()) throw std::domain_error("Division by zero");
        if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) {
                if (other.bits[i] == 0) throw std::domain_error("Division by zero");
                bits[i] /= other.bits[i];
            }
        } else {
            *this = divmod(other).first;
        }
        return *this;
    }

    FORCE_INLINE constexpr UInt& operator%=(const UInt& other) {
        if (other.eqz()) throw std::domain_error("Division by zero");
        if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) {
                if (other.bits[i] == 0) throw std::domain_error("Division by zero");
                bits[i] %= other.bits[i];
            }
        } else {
            *this = divmod(other).second;
        }
        return *this;
    }

    FORCE_INLINE UInt& operator<<=(const u16 n) noexcept {
        if constexpr (N == 1) {
            bits[0] <<= n;
        } else {
            if (mode_ == Backend::SIMD) {
                size_t i = 0;
#if defined(__AVX512F__)
                for (; i + 8 <= N; i += 8) {
                    __m512i v = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
                    _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_slli_epi64(v, n));
                }
#endif
#if defined(__AVX2__)
                for (; i + 4 <= N; i += 4) {
                    __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
                    _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_slli_epi64(v, n));
                }
#elif defined(__SSE2__)
                for (; i + 2 <= N; i += 2) {
                    __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_slli_epi64(v, n));
                }
#endif
                for (; i < N; ++i) bits[i] <<= n;
            } else {
                if (n >= N * 64) { bits.fill(0ULL); return *this; }
                const u16 block_shift = n >> 6;
                const u16 bit_shift = n & 63;
                if (bit_shift == 0) {
                    if (block_shift > 0) {
                        for (int i = N - 1; i >= (int)block_shift; --i) bits[i] = bits[i - block_shift];
                        std::fill_n(bits.begin(), block_shift, 0ULL);
                    }
                } else {
                    for (int i = N - 1; i >= 0; --i) {
                        int src = i - (int)block_shift;
                        u64 hi = (src >= 0) ? bits[src] : 0ULL;
                        u64 lo = (src - 1 >= 0) ? bits[src - 1] : 0ULL;
                        bits[i] = (hi << bit_shift) | (lo >> (64 - bit_shift));
                    }
                }
            }
        }
        return *this;
    }

    FORCE_INLINE UInt& operator>>=(const u16 n) noexcept {
        if constexpr (N == 1) {
            bits[0] >>= n;
        } else {
            if (mode_ == Backend::SIMD) {
                size_t i = 0;
#if defined(__AVX512F__)
                for (; i + 8 <= N; i += 8) {
                    __m512i v = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
                    _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_srli_epi64(v, n));
                }
#endif
#if defined(__AVX2__)
                for (; i + 4 <= N; i += 4) {
                    __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
                    _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_srli_epi64(v, n));
                }
#elif defined(__SSE2__)
                for (; i + 2 <= N; i += 2) {
                    __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_srli_epi64(v, n));
                }
#endif
                for (; i < N; ++i) bits[i] >>= n;
            } else {
                if (n >= N * 64) { bits.fill(0ULL); return *this; }
                const u16 block_shift = n >> 6;
                const u16 bit_shift = n & 63;
                if (bit_shift == 0) {
                    if (block_shift > 0) {
                        for (size_t i = 0; i < N - block_shift; ++i) bits[i] = bits[i + block_shift];
                        std::fill_n(bits.begin() + N - block_shift, block_shift, 0ULL);
                    }
                } else {
                    for (size_t i = 0; i < N; ++i) {
                        size_t src = i + block_shift;
                        u64 lo = (src < N) ? bits[src] : 0ULL;
                        u64 hi = (src + 1 < N) ? bits[src + 1] : 0ULL;
                        bits[i] = (lo >> bit_shift) | (hi << (64 - bit_shift));
                    }
                }
            }
        }
        return *this;
    }

    FORCE_INLINE UInt& operator&=(const UInt& other) noexcept {
        size_t i = 0;
#if defined(__AVX512F__)
        for (; i + 8 <= N; i += 8) {
            __m512i a = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
            __m512i b = _mm512_loadu_si512(reinterpret_cast<const void*>(other.bits.data() + i));
            _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_and_si512(a, b));
        }
#endif
#if defined(__AVX2__)
        for (; i + 4 <= N; i += 4) {
            __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
            __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(other.bits.data() + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_and_si256(a, b));
        }
#elif defined(__SSE2__)
        for (; i + 2 <= N; i += 2) {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
            __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(other.bits.data() + i));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_and_si128(a, b));
        }
#endif
        for (; i < N; ++i) bits[i] &= other.bits[i];
        return *this;
    }

    FORCE_INLINE UInt& operator|=(const UInt& other) noexcept {
        size_t i = 0;
#if defined(__AVX512F__)
        for (; i + 8 <= N; i += 8) {
            __m512i a = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
            __m512i b = _mm512_loadu_si512(reinterpret_cast<const void*>(other.bits.data() + i));
            _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_or_si512(a, b));
        }
#endif
#if defined(__AVX2__)
        for (; i + 4 <= N; i += 4) {
            __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
            __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(other.bits.data() + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_or_si256(a, b));
        }
#elif defined(__SSE2__)
        for (; i + 2 <= N; i += 2) {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
            __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(other.bits.data() + i));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_or_si128(a, b));
        }
#endif
        for (; i < N; ++i) bits[i] |= other.bits[i];
        return *this;
    }

    FORCE_INLINE UInt& operator^=(const UInt& other) noexcept {
        size_t i = 0;
#if defined(__AVX512F__)
        for (; i + 8 <= N; i += 8) {
            __m512i a = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
            __m512i b = _mm512_loadu_si512(reinterpret_cast<const void*>(other.bits.data() + i));
            _mm512_storeu_si512(reinterpret_cast<void*>(bits.data() + i), _mm512_xor_si512(a, b));
        }
#endif
#if defined(__AVX2__)
        for (; i + 4 <= N; i += 4) {
            __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
            __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(other.bits.data() + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bits.data() + i), _mm256_xor_si256(a, b));
        }
#elif defined(__SSE2__)
        for (; i + 2 <= N; i += 2) {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
            __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(other.bits.data() + i));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(bits.data() + i), _mm_xor_si128(a, b));
        }
#endif
        for (; i < N; ++i) bits[i] ^= other.bits[i];
        return *this;
    }

    [[nodiscard]] FORCE_INLINE constexpr UInt operator~() const noexcept {
        UInt res = *this;
        for (u8 i = 0; i < N; ++i) res.bits[i] = ~res.bits[i];
        return res;
    }

    FORCE_INLINE UInt& operator++() noexcept { return *this += UInt(1); }
    FORCE_INLINE UInt& operator--() noexcept { return *this -= UInt(1); }
    FORCE_INLINE UInt operator++(int) noexcept { UInt t = *this; ++*this; return t; }
    FORCE_INLINE UInt operator--(int) noexcept { UInt t = *this; --*this; return t; }

    [[nodiscard]] FORCE_INLINE bool bt(const u16 index) const noexcept {
        if (UNLIKELY(index >= N * 64)) return false;
        return (bits[index / 64] >> (index % 64)) & 1;
    }

    FORCE_INLINE void bts(const u16 index) noexcept {
        if (LIKELY(index < N * 64)) bits[index / 64] |= (1ULL << (index % 64));
    }

    [[nodiscard]] FORCE_INLINE constexpr bool eqz() const noexcept {
        if consteval {
            u64 acc = 0;
            for (u8 i = 0; i < N; ++i) acc |= bits[i];
            return acc == 0;
        } else {
            size_t i = 0;
#if defined(__AVX512F__)
            for (; i + 8 <= N; i += 8) {
                __m512i v = _mm512_loadu_si512(reinterpret_cast<const void*>(bits.data() + i));
                if (_mm512_test_epi64_mask(v, v) != 0) return false;
            }
#endif
#if defined(__AVX2__)
            for (; i + 4 <= N; i += 4) {
                __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(bits.data() + i));
                if (!_mm256_testz_si256(v, v)) return false;
            }
#elif defined(__SSE2__)
            for (; i + 2 <= N; i += 2) {
                __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bits.data() + i));
                __m128i zero = _mm_setzero_si128();
                if (_mm_movemask_epi8(_mm_cmpeq_epi32(v, zero)) != 0xFFFF) return false;
            }
#endif
            u64 acc = 0;
            for (; i < N; ++i) acc |= bits[i];
            return acc == 0;
        }
    }

    [[nodiscard]] FORCE_INLINE UInt<N> square() const noexcept {
        UInt<N> res;
        res.set_mode(mode_);
        res.set_endianness(endian_);
        Multiplication::sqr_schoolbook_truncated_fixed<N>(res.bits.data(), bits.data());
        return res;
    }

    template <u8 OutN = 2 * N>
    [[nodiscard]] FORCE_INLINE UInt<OutN> square_wide() const noexcept {
        static_assert(OutN >= 2 * N, "OutN must be at least 2*N for square_wide");
        UInt<OutN> res;
        res.set_mode(mode_);
        res.set_endianness(endian_);
        Multiplication::sqr_schoolbook_fixed<N>(res.bits.data(), bits.data());
        return res;
    }

    [[nodiscard]] FORCE_INLINE u16 lzc() const noexcept {
        for (int i = N - 1; i >= 0; --i) {
            if (bits[i] != 0) {
                return static_cast<u16>(std::countl_zero(bits[i]) + (N - 1 - i) * 64);
            }
        }
        return static_cast<u16>(N * 64);
    }

    [[nodiscard]] FORCE_INLINE UInt& byteswap() noexcept {
        for (u8 i = 0; i < N / 2; ++i) {
            const u8 j = static_cast<u8>(N - 1 - i);
            const u64 lo = bits[i];
            const u64 hi = bits[j];
            bits[i] = std::byteswap(hi);
            bits[j] = std::byteswap(lo);
        }
        if constexpr ((N & 1) != 0) {
            bits[N / 2] = std::byteswap(bits[N / 2]);
        }
        return *this;
    }

    [[nodiscard]] FORCE_INLINE UInt& rotl(const u16 n) noexcept {
        if constexpr (N == 1) {
            bits[0] = std::rotl(bits[0], static_cast<int>(n));
        } else if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) bits[i] = std::rotl(bits[i], static_cast<int>(n));
        } else {
            const u16 r = n % static_cast<u16>(N * 64);
            if (r == 0) [[unlikely]] return *this;
            const u8 limb_shift = static_cast<u8>(r >> 6);
            const u8 bit_shift = static_cast<u8>(r & 63);
            UInt tmp{};
            if (bit_shift == 0) {
                for (u8 i = 0; i < N; ++i) {
                    const u8 src = static_cast<u8>((i + N - limb_shift) % N);
                    tmp.bits[i] = bits[src];
                }
            } else {
                const u8 inv = static_cast<u8>(64 - bit_shift);
                for (u8 i = 0; i < N; ++i) {
                    const u8 src = static_cast<u8>((i + N - limb_shift) % N);
                    const u8 prev = static_cast<u8>((src + N - 1) % N);
                    tmp.bits[i] = (bits[src] << bit_shift) | (bits[prev] >> inv);
                }
            }
            *this = tmp;
        }
        return *this;
    }

    [[nodiscard]] FORCE_INLINE UInt& rotl(const UInt& shift) noexcept {
        if constexpr (N == 1) {
            bits[0] = std::rotl(bits[0], static_cast<int>(shift.bits[0] & 63));
        } else if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) bits[i] = std::rotl(bits[i], static_cast<int>(shift.bits[i] & 63));
        } else {
            constexpr u16 W = static_cast<u16>(N * 64);
            u16 r = 0;
            if constexpr ((W & (W - 1)) == 0) {
                r = static_cast<u16>(shift.bits[0] & (W - 1));
            } else {
                u64 rem = 0;
                for (int i = N - 1; i >= 0; --i) {
                    const u64 current = shift.bits[i];
                    for (int bit = 63; bit >= 0; --bit) {
                        rem = (rem << 1) | ((current >> bit) & 1);
                        if (rem >= W) rem -= W;
                    }
                }
                r = static_cast<u16>(rem);
            }
            if (r != 0) *this = rotl(r);
        }
        return *this;
    }

    [[nodiscard]] FORCE_INLINE UInt& rotr(const u16 n) noexcept {
        if constexpr (N == 1) {
            bits[0] = std::rotr(bits[0], static_cast<int>(n));
        } else if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) bits[i] = std::rotr(bits[i], static_cast<int>(n));
        } else {
            const u16 r = n % static_cast<u16>(N * 64);
            if (r == 0) [[unlikely]] return *this;
            const u8 limb_shift = static_cast<u8>(r >> 6);
            const u8 bit_shift = static_cast<u8>(r & 63);
            UInt tmp{};
            if (bit_shift == 0) {
                for (u8 i = 0; i < N; ++i) {
                    const u8 src = static_cast<u8>((i + limb_shift) % N);
                    tmp.bits[i] = bits[src];
                }
            } else {
                const u8 inv = static_cast<u8>(64 - bit_shift);
                for (u8 i = 0; i < N; ++i) {
                    const u8 src = static_cast<u8>((i + limb_shift) % N);
                    const u8 next = static_cast<u8>((src + 1) % N);
                    tmp.bits[i] = (bits[src] >> bit_shift) | (bits[next] << inv);
                }
            }
            *this = tmp;
        }
        return *this;
    }

    [[nodiscard]] FORCE_INLINE UInt& rotr(const UInt& shift) noexcept {
        if constexpr (N == 1) {
            bits[0] = std::rotr(bits[0], static_cast<int>(shift.bits[0] & 63));
        } else if (mode_ == Backend::SIMD) {
            for (u8 i = 0; i < N; ++i) bits[i] = std::rotr(bits[i], static_cast<int>(shift.bits[i] & 63));
        } else {
            constexpr u16 W = static_cast<u16>(N * 64);
            u16 r = 0;
            if constexpr ((W & (W - 1)) == 0) {
                r = static_cast<u16>(shift.bits[0] & (W - 1));
            } else {
                u64 rem = 0;
                for (int i = N - 1; i >= 0; --i) {
                    const u64 current = shift.bits[i];
                    for (int bit = 63; bit >= 0; --bit) {
                        rem = (rem << 1) | ((current >> bit) & 1);
                        if (rem >= W) rem -= W;
                    }
                }
                r = static_cast<u16>(rem);
            }
            if (r != 0) *this = rotr(r);
        }
        return *this;
    }

    [[nodiscard]] std::string to_hex_string() const {
        if (eqz()) return "0x0";
        UInt<N> temp(*this);
        temp.set_endianness(Endianness::little);
        int msb_limb = N - 1;
        for (int i = N - 1; i >= 0; --i) {
            if (temp.bits[i] != 0) { msb_limb = i; break; }
        }
        std::string res;
        res.reserve(2 + static_cast<size_t>(msb_limb + 1) * 16);
        res = "0x";
        res += std::format("{:x}", temp.bits[msb_limb]);
        for (int i = msb_limb - 1; i >= 0; --i) {
            res += std::format("{:016x}", temp.bits[i]);
        }
        return res;
    }

    [[nodiscard]] std::string to_string() const {
        if (eqz()) return "0";
        UInt<N> temp(*this);
        temp.set_mode(Backend::Scalar);
        temp.set_endianness(Endianness::little);
        constexpr u64 CHUNK_POW = 1'000'000'000'000'000'000ull;
        u64 chunks[300];
        int chunk_count = 0;
        while (!temp.eqz()) {
            auto [quotient, remainder] = temp.divmod(CHUNK_POW);
            chunks[chunk_count++] = remainder;
            temp = std::move(quotient);
        }
        std::string res = std::format("{}", chunks[chunk_count - 1]);
        for (int i = chunk_count - 2; i >= 0; --i) {
            res += std::format("{:018d}", chunks[i]);
        }
        return res;
    }

    [[nodiscard]] static UInt<N> random(const u64 seed) noexcept {
        UInt<N> number;
        u64 state = (seed != 0) ? seed : (0xCAFEBABEULL + N);
        for (u64& block : number.bits) block = number.rand(state);
        return number;
    }

    struct MontgomeryCtx {
        UInt p_inv{};
        UInt r2{};
    };

    void to_mont(UInt& x, const UInt& p, const MontgomeryCtx& ctx) {
        mul_mod_mont(x, ctx.r2, p, ctx);
    }

    void from_mont(UInt& x, const UInt& p, const MontgomeryCtx& ctx) {
        UInt one = 1;
        mul_mod_mont(x, one, p, ctx);
    }

    void mul_mod_mont(UInt& x, const UInt& y, const UInt& p, const MontgomeryCtx& ctx) {
        alignas(u64) u64 t[2 * N + 2]{};
        alignas(u64) u64 xbuf[N];
        alignas(u64) u64 ybuf[N];
        for (u8 i = 0; i < N; ++i) {
            xbuf[i] = x.bits[i];
            ybuf[i] = y.bits[i];
        }
        Multiplication::mul_montgomery_cios<N>(t, xbuf, ybuf, p.bits.data(), ctx.p_inv.bits[0], 64 * N);
        for (u8 i = 0; i < N; ++i) x.bits[i] = t[i];
    }

    MontgomeryCtx montgomery_precompute(const UInt& p) {
        MontgomeryCtx ctx;
        ctx.p_inv.bits[0] = Multiplication::montgomery_p_inv(p.bits[0]);
        alignas(u64) u64 big[2 * N + 1]{};
        big[2 * N] = 1;
        const int n_v = p.num_limbs();
        if (n_v == 1) {
            u64 rem = 0;
            for (int i = 2 * N; i >= 0; --i) {
                u128 cur = (static_cast<u128>(rem) << 64) | big[i];
                rem = static_cast<u64>(cur % p.bits[0]);
            }
            ctx.r2.bits[0] = rem;
        } else {
            u64 qq[2 * N + 4]{};
            u64 rr[N]{};
            Division::div_knuth_impl<2 * N + 4>(qq, rr, big, 2 * N + 1, p.bits.data(), n_v);
            for (u8 i = 0; i < N; ++i) ctx.r2.bits[i] = rr[i];
        }
        return ctx;
    }

    UInt& invMod(const UInt& p) {
        UInt base = *this % p;
        UInt result = 1;
        UInt exp = p;
        --exp; --exp;
        const bool mont = (p.bits[0] & 1) != 0 && p.bits[N - 1] != 0;
        MontgomeryCtx ctx;
        if (mont) {
            ctx = montgomery_precompute(p);
            to_mont(base, p, ctx);
            to_mont(result, p, ctx);
        }
        while (!exp.eqz()) {
            if (exp.bt(0)) {
                if (mont) mul_mod_mont(result, base, p, ctx);
                else mul_mod(result, base, p);
            }
            exp >>= 1;
            if (!exp.eqz()) {
                if (mont) mul_mod_mont(base, base, p, ctx);
                else mul_mod(base, base, p);
            }
        }
        if (mont) from_mont(result, p, ctx);
        return *this = result;
    }

    void mul_mod(UInt& x, const UInt& y, const UInt& p) {
        u64 prod[2 * N];
        Multiplication::mul_schoolbook_full(prod, x.bits.data(), y.bits.data(), N);
        const int n_v = p.num_limbs();
        if (n_v == 1) {
            u64 rem = 0;
            for (int i = 2 * N - 1; i >= 0; --i) {
                u128 cur = (static_cast<u128>(rem) << 64) | prod[i];
                rem = static_cast<u64>(cur % p.bits[0]);
            }
            x.bits.fill(0);
            x.bits[0] = rem;
        } else {
            u64 qq[2 * N + 2];
            u64 rr[N];
            Division::div_knuth_impl<2 * N + 4>(qq, rr, prod, 2 * N, p.bits.data(), n_v);
            x.bits.fill(0);
            for (int i = 0; i < n_v; ++i) x.bits[i] = rr[i];
        }
    }
};

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator+(UInt<N> lhs, const UInt<N>& rhs) noexcept { return lhs += rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator-(UInt<N> lhs, const UInt<N>& rhs) noexcept { return lhs -= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator*(UInt<N> lhs, const UInt<N>& rhs) noexcept { return lhs *= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator/(UInt<N> lhs, const UInt<N>& rhs) { return lhs /= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator%(UInt<N> lhs, const UInt<N>& rhs) { return lhs %= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator&(UInt<N> lhs, const UInt<N>& rhs) noexcept { return lhs &= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator|(UInt<N> lhs, const UInt<N>& rhs) noexcept { return lhs |= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator^(UInt<N> lhs, const UInt<N>& rhs) noexcept { return lhs ^= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator<<(UInt<N> lhs, u16 rhs) noexcept { return lhs <<= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator>>(UInt<N> lhs, u16 rhs) noexcept { return lhs >>= rhs; }

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator==(const UInt<N>& lhs, u64 rhs) noexcept {
    return N == 1 ? lhs.bits[0] == rhs : (lhs.bits[0] == rhs && (N <= 1 || std::ranges::all_of(lhs.bits.begin() + 1, lhs.bits.end(), [](u64 v) { return v == 0; })));
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator==(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs == lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator!=(const UInt<N>& lhs, u64 rhs) noexcept {
    return !(lhs == rhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator!=(u64 lhs, const UInt<N>& rhs) noexcept {
    return !(rhs == lhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator<(const UInt<N>& lhs, u64 rhs) noexcept {
    for (u8 i = 1; i < N; ++i) {
        if (lhs.bits[i] != 0) return false;
    }
    return lhs.bits[0] < rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator>(const UInt<N>& lhs, u64 rhs) noexcept {
    for (u8 i = 1; i < N; ++i) {
        if (lhs.bits[i] != 0) return true;
    }
    return lhs.bits[0] > rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator<=(const UInt<N>& lhs, u64 rhs) noexcept {
    return !(lhs > rhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator>=(const UInt<N>& lhs, u64 rhs) noexcept {
    return !(lhs < rhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator<(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs > lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator>(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs < lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator<=(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs >= lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE constexpr bool operator>=(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs <= lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator+(const UInt<N>& lhs, u64 rhs) noexcept {
    UInt<N> result = lhs;
    result += UInt<N>(rhs);
    return result;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator+(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs + lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator-(const UInt<N>& lhs, u64 rhs) noexcept {
    UInt<N> result = lhs;
    result -= UInt<N>(rhs);
    return result;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator-(u64 lhs, const UInt<N>& rhs) noexcept {
    return UInt<N>(lhs) - rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator*(const UInt<N>& lhs, u64 rhs) noexcept {
    UInt<N> result = lhs;
    result *= UInt<N>(rhs);
    return result;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator*(u64 lhs, const UInt<N>& rhs) noexcept {
    return rhs * lhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator/(const UInt<N>& lhs, u64 rhs) {
    UInt<N> result = lhs;
    result /= UInt<N>(rhs);
    return result;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator/(u64 lhs, const UInt<N>& rhs) {
    return UInt<N>(lhs) / rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator%(const UInt<N>& lhs, u64 rhs) {
    UInt<N> result = lhs;
    result %= UInt<N>(rhs);
    return result;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator%(u64 lhs, const UInt<N>& rhs) {
    return UInt<N>(lhs) % rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator&(const UInt<N>& lhs, u64 rhs) noexcept {
    return lhs & UInt<N>(rhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator&(u64 lhs, const UInt<N>& rhs) noexcept {
    return UInt<N>(lhs) & rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator|(const UInt<N>& lhs, u64 rhs) noexcept {
    return lhs | UInt<N>(rhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator|(u64 lhs, const UInt<N>& rhs) noexcept {
    return UInt<N>(lhs) | rhs;
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator^(const UInt<N>& lhs, u64 rhs) noexcept {
    return lhs ^ UInt<N>(rhs);
}

template <u8 N>
[[nodiscard]] FORCE_INLINE UInt<N> operator^(u64 lhs, const UInt<N>& rhs) noexcept {
    return UInt<N>(lhs) ^ rhs;
}

namespace UIntLiteral {
    [[nodiscard]] inline constexpr UInt<1> operator""_u1(unsigned long long v) noexcept { return UInt<1>(v); }
    [[nodiscard]] inline constexpr UInt<2> operator""_u2(unsigned long long v) noexcept { return UInt<2>(v); }
    [[nodiscard]] inline constexpr UInt<4> operator""_u4(unsigned long long v) noexcept { return UInt<4>(v); }
    [[nodiscard]] inline constexpr UInt<8> operator""_u8(unsigned long long v) noexcept { return UInt<8>(v); }
    [[nodiscard]] inline constexpr UInt<16> operator""_u16(unsigned long long v) noexcept { return UInt<16>(v); }
    [[nodiscard]] inline constexpr UInt<32> operator""_u32(unsigned long long v) noexcept { return UInt<32>(v); }
}
