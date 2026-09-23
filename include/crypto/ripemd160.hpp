#pragma once
#include "crypto/bip39.hpp"
#include "math/UInt.hpp"
#include <array>
#include <cstdint>
#include <cstddef>

namespace crypto {
    class RIPEMD160 {
        public:
            RIPEMD160();
            void reset();
            void update(const void* data, size_t len);
            void finalize(uint8_t out[20]);
            static void hash(const void* data, size_t len, uint8_t out[20]);
            static void hash32(const std::array<u8, 32> &in, array<u8, 20> &out) noexcept;

        private:
            array<u32, 5> h_;
            array<u8, 64> buf_;
            size_t buf_len_;
            uint64_t total_len_;

            void process_block(const uint8_t block[64]);
    };
} // namespace crypto
