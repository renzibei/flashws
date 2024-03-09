#pragma once

#include <openssl/hmac.h>
#include <utility>
#include <string_view>

namespace fws {

    FWS_ALWAYS_INLINE void BytesToHex(char* FWS_RESTRICT dst, const unsigned char* FWS_RESTRICT src, size_t src_len) {
        for (size_t i = 0; i < src_len; i++) {
            int b1 = src[i] >> 4;
            dst[i * 2] = (char)(55 + b1 + (((b1-10)>>31)&-7));
            int b2 = src[i] & 0xF;
            dst[i * 2 + 1] = (char)(55 + b2 + (((b2-10)>>31)&-7));
        }
    }

    struct HMACContext {
        HMAC_CTX *ctx;

        int Init(std::string_view key) {
            ctx = HMAC_CTX_new();
            if FWS_UNLIKELY(!ctx) {
                return -1;
            }
            if FWS_UNLIKELY(HMAC_Init_ex(ctx, key.data(), key.length(), EVP_sha256(), nullptr) != 1) {
                return -2;
            }
            return 0;
        }

        HMACContext(): ctx(nullptr) {}

        HMACContext(const HMACContext &) = delete;

        HMACContext &operator=(const HMACContext &) = delete;

        HMACContext(HMACContext &&o) noexcept:
                ctx(std::exchange(o.ctx, nullptr)) {}

        ~HMACContext() {
            if (ctx) {
                HMAC_CTX_free(ctx);
                ctx = nullptr;
            }
        }
    };

    template<size_t buf_len>
    ssize_t GetHMACSHA256(HMACContext& FWS_RESTRICT ctx, std::string_view msg, char* dst) {
        static_assert(buf_len >= 64, "Buffer must be at least 64 bytes long");
        if FWS_UNLIKELY(HMAC_Init_ex(ctx.ctx, nullptr, 0, EVP_sha256(), nullptr) != 1) {
            return -1;
            // Handle errors
        }

        HMAC_Update(ctx.ctx, reinterpret_cast<const unsigned char*>(msg.data()), msg.length());

        unsigned int mac_length = 0;
        unsigned char digest[EVP_MAX_MD_SIZE];
        HMAC_Final(ctx.ctx, digest, &mac_length);
        // Hex string length is twice the binary length
        ssize_t ret = mac_length * 2;

        BytesToHex(dst, digest, mac_length);

        return ret;
    }

} // namespace fws