#pragma once

#include <openssl/evp.h>
#include "flashws/base/basic_macros.h"

namespace fws {

    /**
     * size for null-terminator is needed in dst
     * @param src
     * @param src_len
     * @param dst length should be Ceil(src_len / 3) * 4 + 1,
     * i.e. (src_len + 2) / 3 * 4 + 1, including one null terminator
     * @return size of dst, excluding the null terminator
     */
    FWS_ALWAYS_INLINE int Base64Encode(const void* FWS_RESTRICT src, int src_len, void* FWS_RESTRICT dst) {
        int dst_len = EVP_EncodeBlock((unsigned char* FWS_RESTRICT)(dst),
                                      (const unsigned char* FWS_RESTRICT)src,
                                      src_len);
        return dst_len;
    }

    /**
     *
     * @param src_len
     * @return The length of base64 encode string, including a null terminator
     */
    FWS_ALWAYS_INLINE constexpr size_t GetBase64EncodeLength(size_t src_len) {
        return (src_len + 2U) / 3U * 4U + 1U;
    }

    FWS_ALWAYS_INLINE int Base64Decode(const void* FWS_RESTRICT src, int src_len, void* FWS_RESTRICT dst) {
        const unsigned char* FWS_RESTRICT input = (const unsigned char*)src;
        unsigned char* FWS_RESTRICT output = (unsigned char*) dst;
        int dst_len = EVP_DecodeBlock(output, input, src_len);
        return dst_len;
    }

} // namespace fws