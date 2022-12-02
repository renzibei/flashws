#pragma once

#include "flashws/base/basic_macros.h"

#ifdef FWS_MSC
#include <stdlib.h>
#endif

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
    defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || \
    defined(__THUMBEB__) || \
    defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)

#define FWS_BIG_ENDIAN

#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || \
    defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)

#define FWS_LITTLE_ENDIAN

#else
static_assert(false, "Unknown endian");
#endif

namespace fws {

    FWS_ALWAYS_INLINE constexpr uint16_t ByteSwap16(uint16_t x) {
#ifdef FWS_MSC
        return _byteswap_ushort(x);
#elif defined(__GNUC__)
        return __builtin_bswap16(x);
#else
        static_assert(false, "Not implemented for this compiler\n");
#endif
    }
    static_assert(ByteSwap16(0x1234U) == 0x3412U);

    FWS_ALWAYS_INLINE constexpr uint32_t ByteSwap32(uint32_t x) {
#ifdef FWS_MSC
        return _byteswap_ulong(x);
#elif defined(__GNUC__)
        return __builtin_bswap32(x);
#else
        static_assert(false, "Not implemented for this compiler\n");
#endif
    }
    static_assert(ByteSwap32(0x12345678U) == 0x78563412U);

    FWS_ALWAYS_INLINE constexpr uint64_t ByteSwap64(uint64_t x) {
#ifdef FWS_MSC
        return _byteswap_uint64(x);
#elif defined(__GNUC__)
        return __builtin_bswap64(x);
#else
        static_assert(false, "Not implemented for this compiler\n");
#endif
    }
    static_assert(ByteSwap64(0x1234567876543210ULL) == 0x1032547678563412ULL);

    FWS_ALWAYS_INLINE constexpr uint16_t Net2Host16(uint16_t x) {
#ifdef FWS_LITTLE_ENDIAN
        return ByteSwap16(x);
#else
        return x;
#endif
    }

    FWS_ALWAYS_INLINE constexpr uint16_t Host2Net16(uint16_t x) {
#ifdef FWS_LITTLE_ENDIAN
        return ByteSwap16(x);
#else
        return x;
#endif
    }

    FWS_ALWAYS_INLINE constexpr uint32_t Net2Host32(uint32_t x) {
#ifdef FWS_LITTLE_ENDIAN
        return ByteSwap32(x);
#else
        return x;
#endif
    }

    FWS_ALWAYS_INLINE constexpr uint32_t Host2Net32(uint32_t x) {
#ifdef FWS_LITTLE_ENDIAN
        return ByteSwap32(x);
#else
        return x;
#endif
    }

    FWS_ALWAYS_INLINE constexpr uint64_t Net2Host64(uint64_t x) {
#ifdef FWS_LITTLE_ENDIAN
            return ByteSwap64(x);
#else
            return x;
#endif
        }

    FWS_ALWAYS_INLINE constexpr uint64_t Host2Net64(uint64_t x) {
#ifdef FWS_LITTLE_ENDIAN
            return ByteSwap64(x);
#else
            return x;
#endif
    }



} // namespace fws