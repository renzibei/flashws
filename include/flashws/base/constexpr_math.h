#pragma once
#include <cstdint>
#include <type_traits>
#include <limits>

namespace fws {

    constexpr uint64_t RoundUpLog2(uint64_t x) {
        if (x <= 1UL) {
            return 0;
        }
        return 64 - __builtin_clzll(x - 1UL);
    }

    static_assert(RoundUpLog2(1) == 0);
    static_assert(RoundUpLog2(2) == 1);
    static_assert(RoundUpLog2(16) == 4);
    static_assert(RoundUpLog2(30) == 5);

    constexpr uint64_t RoundDownLog2(uint64_t x) {
        if (x == 0) {
            return 0;
        }
        return 64ULL - __builtin_clzll(x);
    }

    static_assert(RoundDownLog2(2) == 2);
    static_assert(RoundDownLog2(3) == 2);
    static_assert(RoundDownLog2(1) == 1);
    static_assert(RoundDownLog2(4) == 3);

    constexpr uint64_t RoundUpPow2(uint64_t x) {
        if (x <= 1UL) {
            return x;
        }
        return 1ULL << (64 - __builtin_clzll(x - 1UL));
    }

    static_assert(RoundUpPow2(1) == 1);
    static_assert(RoundUpPow2(15) == 16);
    static_assert(RoundUpPow2(1024) == 1024);

    constexpr uint64_t RoundDownPow2(uint64_t x) {
        if (x == 0) {
            return 0;
        }
        return 1ULL << (RoundDownLog2(x) - 1U);
    }

    static_assert(RoundDownPow2(1) == 1);
    static_assert(RoundDownPow2(2) == 2);
    static_assert(RoundDownPow2(3) == 2);
    static_assert(RoundDownPow2(510) == 256);

    constexpr uint64_t DivPow2(uint64_t x, uint64_t d) {
        auto log2 = RoundUpLog2(d);
        return x >> log2;
    }

    static_assert(DivPow2(256, 16) == 16);
    static_assert(DivPow2(512, 1) == 512);
    static_assert(DivPow2(1024, 8) == 128);
    static_assert(DivPow2(4096, 4096) == 1);
    static_assert(DivPow2(13, 8) == 1);
    static_assert(DivPow2(510, 32) == 15);

    template <typename T, typename U>
    constexpr T RotateR (T v, U b)
    {
        static_assert(std::is_integral<T>::value, "rotate of non-integral type");
        static_assert(! std::is_signed<T>::value, "rotate of signed type");
        static_assert(std::is_integral<U>::value, "rotate of non-integral type");
        constexpr unsigned num_bits {std::numeric_limits<T>::digits};
        static_assert(0 == (num_bits & (num_bits - 1)), "rotate value bit length not power of two");
        constexpr U count_mask {num_bits - 1};
        // to make sure mb < num_bits
        const auto mb {b & count_mask};
        using promoted_type = typename std::common_type<int, T>::type;
        using unsigned_promoted_type = typename std::make_unsigned<promoted_type>::type;
        return ((unsigned_promoted_type{v} >> mb)
                | (unsigned_promoted_type{v} << (-mb & count_mask)));
    }

    static_assert(RotateR(0xf0000000U, 4) == 0x0f000000U);
    static_assert(RotateR(0xf0000000U, 32U) == 0xf0000000U);
    static_assert(RotateR(0xf0000000U, 8U) == 0x00f00000U);
    static_assert(RotateR(0xf0000000U, 36) == 0x0f000000U);

} // namespace fws
