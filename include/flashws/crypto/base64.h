#pragma once

#include <openssl/evp.h>
#include "flashws/base/basic_macros.h"

namespace fws {

/**
 *
 * @param src_len
 * @return The length of base64 encode string, including a null terminator
 */
    FWS_ALWAYS_INLINE constexpr size_t GetBase64EncodeLength(size_t src_len) {
        return (src_len + 2U) / 3U * 4U + 1U;
    }


    namespace detail {

        template<size_t N>
        static void Fix20Base64Encode(const char* FWS_RESTRICT data, char* FWS_RESTRICT ret) {
            static constexpr char sEncodingTable[] = {
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

            constexpr size_t in_len = N;
            static_assert(in_len == 20);
            char* FWS_RESTRICT p  = const_cast<char *>(ret);

            for (size_t i = 0; i < in_len - 2; i += 3) {
                *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
                *p++ = sEncodingTable[((data[i] & 0x3) << 4) |
                                      ((int)(data[i + 1] & 0xF0) >> 4)];
                *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2) |
                                      ((int)(data[i + 2] & 0xC0) >> 6)];
                *p++ = sEncodingTable[data[i + 2] & 0x3F];
            }
            constexpr size_t last = in_len - 2;
            ret[24] = sEncodingTable[(data[last] >> 2) & 0x3F];
            ret[25] = sEncodingTable[((data[last] & 0x3) << 4) |
                                     ((int)(data[last + 1] & 0xF0) >> 4)];
            ret[26] = sEncodingTable[((data[last + 1] & 0xF) << 2)];
            ret[27] = '=';
        }

        template<size_t N>
        static void FixBase64Encode(const char* FWS_RESTRICT data, char* FWS_RESTRICT ret) {
            static constexpr char sEncodingTable[] = {
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

            constexpr size_t in_len = N;
            size_t i = 0;
            char* FWS_RESTRICT p  = const_cast<char *>(ret);

            for (i = 0; in_len > 2 && i < in_len - 2; i += 3) {
                *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
                *p++ = sEncodingTable[((data[i] & 0x3) << 4) |
                                      ((int)(data[i + 1] & 0xF0) >> 4)];
                *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2) |
                                      ((int)(data[i + 2] & 0xC0) >> 6)];
                *p++ = sEncodingTable[data[i + 2] & 0x3F];
            }
            if (i < in_len) {
                *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
                if (i == (in_len - 1)) {
                    *p++ = sEncodingTable[((data[i] & 0x3) << 4)];
                    *p++ = '=';
                } else {
                    *p++ = sEncodingTable[((data[i] & 0x3) << 4) |
                                          ((int)(data[i + 1] & 0xF0) >> 4)];
                    *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2)];
                }
                *p++ = '=';
            }

        }

        static void DyBase64Encode(const char* FWS_RESTRICT data, size_t in_len, char* FWS_RESTRICT ret) {
            static constexpr char sEncodingTable[] = {
                    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

//            constexpr size_t in_len = N;
            size_t i = 0;
            char* FWS_RESTRICT p  = const_cast<char *>(ret);
            size_t in_len_2 = in_len - 2;
            for (i = 0; (in_len > 2) & (i < in_len_2); i += 3) {
                *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
                *p++ = sEncodingTable[((data[i] & 0x3) << 4) |
                                      ((int)(data[i + 1] & 0xF0) >> 4)];
                *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2) |
                                      ((int)(data[i + 2] & 0xC0) >> 6)];
                *p++ = sEncodingTable[data[i + 2] & 0x3F];
            }
            if (i < in_len) {
                *p++ = sEncodingTable[(data[i] >> 2) & 0x3F];
                if (i == (in_len - 1)) {
                    *p++ = sEncodingTable[((data[i] & 0x3) << 4)];
                    *p++ = '=';
                } else {
                    *p++ = sEncodingTable[((data[i] & 0x3) << 4) |
                                          ((int)(data[i + 1] & 0xF0) >> 4)];
                    *p++ = sEncodingTable[((data[i + 1] & 0xF) << 2)];
                }
                *p++ = '=';
            }

        }

        static inline void uws_base64(unsigned char * FWS_RESTRICT src, char* FWS_RESTRICT dst) {
            static constexpr const char * FWS_RESTRICT b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for (int i = 0; i < 18; i += 3) {
                *dst++ = b64[(src[i] >> 2) & 63];
                *dst++ = b64[((src[i] & 3) << 4) | ((src[i + 1] & 240) >> 4)];
                *dst++ = b64[((src[i + 1] & 15) << 2) | ((src[i + 2] & 192) >> 6)];
                *dst++ = b64[src[i + 2] & 63];
            }
            *dst++ = b64[(src[18] >> 2) & 63];
            *dst++ = b64[((src[18] & 3) << 4) | ((src[19] & 240) >> 4)];
            *dst++ = b64[((src[19] & 15) << 2)];
            *dst++ = '=';
        }
    } // namespace detail

    /**
     * size for null-terminator is needed in dst
     * @param src
     * @param src_len
     * @param dst length should be Ceil(src_len / 3) * 4 + 1,
     * i.e. (src_len + 2) / 3 * 4 + 1, including one null terminator
     * @return size of dst, excluding the null terminator
     */
    template<size_t src_len>
    inline int Fix20Base64Encode(const void* FWS_RESTRICT src, void* FWS_RESTRICT dst) {
        detail::Fix20Base64Encode<src_len>((const char*)src, (char*)dst);
        constexpr size_t dst_len = GetBase64EncodeLength(src_len);
        return dst_len;
    }

    template<size_t src_len>
    inline int FixBase64Encode(const void* FWS_RESTRICT src, void* FWS_RESTRICT dst) {
        detail::FixBase64Encode<src_len>((const char*)src, (char*)dst);
        constexpr size_t dst_len = GetBase64EncodeLength(src_len);
        return dst_len;
    }

    inline int DynamicBase64Encode(const void* FWS_RESTRICT src, int src_len, void* FWS_RESTRICT dst) {
        detail::DyBase64Encode((const char*)src, src_len, (char*)dst);
        int dst_len = GetBase64EncodeLength(src_len);
        return dst_len;
    }

    inline int OSLBase64Encode(const void* FWS_RESTRICT src, int src_len, void* FWS_RESTRICT dst) {
        int dst_len = EVP_EncodeBlock((unsigned char* FWS_RESTRICT)(dst),
                                      (const unsigned char* FWS_RESTRICT)src,
                                      src_len);
        return dst_len;
    }


    FWS_ALWAYS_INLINE int OSLBase64Decode(const void* FWS_RESTRICT src, int src_len, void* FWS_RESTRICT dst) {
        const unsigned char* FWS_RESTRICT input = (const unsigned char*)src;
        unsigned char* FWS_RESTRICT output = (unsigned char*) dst;
        int dst_len = EVP_DecodeBlock(output, input, src_len);
        return dst_len;
    }

} // namespace fws