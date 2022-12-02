#pragma once


#include "flashws/base/constexpr_math.h"
#include "flashws/base/basic_macros.h"
#include <cstring>
#include <algorithm>

#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace fws {

    inline void WSMaskBytes(uint8_t * FWS_RESTRICT src, size_t size,
                     uint32_t mask) {
        uint64_t mask64 = ((uint64_t)mask << 32U) | mask;
        uint8_t mask_arr[4];

        memcpy(mask_arr, &mask, 4);
        size_t size_div_8 = size / sizeof(uint64_t);
        uint64_t * FWS_RESTRICT  u64_src = (uint64_t* FWS_RESTRICT )src;
        for (size_t i = 0; i < size_div_8; ++i) {
            u64_src[i] = u64_src[i] ^ mask64;
        }
        for (size_t i = size_div_8 * sizeof(uint64_t); i < size; ++i) {
            src[i] = src[i] ^ mask_arr[i & 3UL];
        }
    }

    namespace detail {
        inline void Mask1(uint8_t *__restrict src, size_t size,
                          uint32_t mask) {
            uint8_t mask_arr[4];
            memcpy(mask_arr, &mask, 4);
            uint32_t mask32_arr[4];
            for (size_t i = 0; i < 4; ++i) {
                mask32_arr[i] = mask_arr[i];
            }
            for (size_t i = 0; i < size; ++i) {
                src[i] = src[i] ^ mask32_arr[i & 3UL];
            }
        }
    }




#ifdef __AVX2__
    // Use unaligned SIMD load
    FWS_NO_LOOP_VEC_IN_FUNC
    inline void MaskAVX2(uint8_t * FWS_RESTRICT src, size_t size,
                           uint32_t mask) {
        uint8_t* FWS_RESTRICT data = src;
        uint8_t* FWS_RESTRICT data_end = src + size;


        uint8_t mask_arr[4];
        memcpy(mask_arr, &mask, 4);


        __m256i w_mask = _mm256_set1_epi32(mask);

        uint8_t *should_stop_32 = data_end - 32;
        FWS_UNROLL_CNT(2)
        while (data <= should_stop_32)            // note that N must be multiple of 32
        {
            // We use unaligned load here
            __m256i w = _mm256_loadu_si256((const __m256i *)data);
            w = _mm256_xor_si256(w, w_mask);       // XOR with mask
            _mm256_storeu_si256((__m256i*)data, w);
            data += 32;
        }
        uint8_t *should_stop_8 = data_end - 8;
        uint64_t mask64 = ((uint64_t)mask << 32U) | mask;

        FWS_NO_LOOP_VEC
        FWS_UNROLL_CNT(2)
        while (data <= should_stop_8) {
            uint64_t* FWS_RESTRICT u64_data = (uint64_t*)data;
            *u64_data = *u64_data ^ mask64;
            data += 8;
        }

        FWS_NO_LOOP_VEC
        FWS_UNROLL_CNT(4)
        while (data < data_end) {
            *data = *data ^ mask_arr[(data - src) & 3];
            ++data;
        }
    }

    // Use aligned SIMD load, this function is faster than MaskAVX2 when size is
    // large compiled with GCC. In Clang this is not as fast as MaskAVX2
    FWS_NO_LOOP_VEC_IN_FUNC
    inline void MaskLargeChunkAVX2(uint8_t * FWS_RESTRICT src, size_t size,
                                     uint32_t mask) {

        uint8_t* FWS_RESTRICT data_end = src + size;

        uint32_t mask_copy = mask;

        uint8_t mask_arr[4];
        memcpy(mask_arr, &mask, 4);

        uint8_t* FWS_RESTRICT aligned_data = (uint8_t* FWS_RESTRICT)((uint64_t(src) + 31ULL) / 32ULL * 32ULL);
        if (aligned_data != src) {
            uint8_t* FWS_RESTRICT da = src;
            uint64_t mask64 = ((uint64_t)mask_copy << 32U) | mask_copy;
            uint8_t *should_stop = std::min(aligned_data, data_end) - 8L;

            FWS_NO_LOOP_VEC
//            FWS_UNROLL_CNT(2)
            while (bool(uint64_t(da) & uint64_t(31U)) & (da <= should_stop)) {
                uint64_t *FWS_RESTRICT u64_data = (uint64_t *) da;
                *u64_data = *u64_data ^ mask64;
                da += 8;
            }

            FWS_NO_LOOP_VEC
//            FWS_UNROLL_CNT(4)
            while (bool(uint64_t(da) & uint64_t(31U)) & (da < data_end)) {
                *da = *da ^ mask_arr[(da - src) & 3];
                ++da;
            }
        }
        if (data_end <= aligned_data) {
            return;
        }


        uint8_t* FWS_RESTRICT data = aligned_data;
        mask = RotateR(mask, 8U * ((uint64_t(data - src) & 3UL)));

        __m256i w_mask = _mm256_set1_epi32(mask);

        // preferably 32 byte aligned
        uint8_t *should_stop_32 = data_end - 32;
        FWS_NO_LOOP_VEC
        FWS_UNROLL_CNT(2)
        while (data <= should_stop_32)
        {
            // aligned 32 bytes load
            __m256i w = _mm256_load_si256(reinterpret_cast<const __m256i *>(data));
            w = _mm256_xor_si256(w, w_mask);       // XOR with mask
            _mm256_store_si256((__m256i*)data, w);   // store 32 masked bytes
            data += 32;
        }
        uint8_t *should_stop_8 = data_end - 8;
        uint64_t mask64 = ((uint64_t)mask << 32U) | mask;

        FWS_NO_LOOP_VEC
//        FWS_UNROLL_CNT(2)
        while (data <= should_stop_8) {
            uint64_t* FWS_RESTRICT u64_data = (uint64_t*)data;
            *u64_data = *u64_data ^ mask64;
            data += 8;
        }

        FWS_NO_LOOP_VEC
//        FWS_UNROLL_CNT(4)
        while (data < data_end) {
            *data = *data ^ mask_arr[(data - src) & 3];
            ++data;
        }
    }
#endif

/**
 * Choose the fast mask method based on length
 * @param src
 * @param size
 * @param mask
 */
    FWS_ALWAYS_INLINE void WSMaskBytesFast(uint8_t * FWS_RESTRICT src, size_t size,
                                 uint32_t mask) {
#ifdef __AVX2__
        if (size < 256U) {
//            detail::Mask1(src, size, mask);
            WSMaskBytes(src, size, mask);
        }
#   if defined(__clang__)
        else {
            MaskAVX2(src, size, mask);
        }
#   else
        else if (size <= 2048U){
            MaskAVX2(src, size, mask);
        }
        else {
            MaskLargeChunkAVX2(src, size, mask);
        }
#   endif
#else
        WSMaskBytes(src, size, mask);
#endif
    }

} // namespace fws