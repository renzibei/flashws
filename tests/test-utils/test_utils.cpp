#include "flashws/crypto/base64.h"
#include "flashws/crypto/sha.h"
#include "flashws/utils/cpu_timer.h"
//#include "compile_time_hash.hpp"

#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <cstring>


namespace detail {

    namespace uws {
        template <int N, typename T>
        struct static_for {
            void operator()(uint32_t *a, uint32_t *b) {
                static_for<N - 1, T>()(a, b);
                T::template f<N - 1>(a, b);
            }
        };

        template <typename T>
        struct static_for<0, T> {
            void operator()(uint32_t */*a*/, uint32_t */*hash*/) {}
        };

        static inline uint32_t rol(uint32_t value, size_t bits) {return (value << bits) | (value >> (32 - bits));}
        static inline uint32_t blk(uint32_t b[16], size_t i) {
            return rol(b[(i + 13) & 15] ^ b[(i + 8) & 15] ^ b[(i + 2) & 15] ^ b[i], 1);
        }

        struct Sha1Loop1 {
            template <int i>
            static inline void f(uint32_t *a, uint32_t *b) {
                a[i % 5] += ((a[(3 + i) % 5] & (a[(2 + i) % 5] ^ a[(1 + i) % 5])) ^ a[(1 + i) % 5]) + b[i] + 0x5a827999 + rol(a[(4 + i) % 5], 5);
                a[(3 + i) % 5] = rol(a[(3 + i) % 5], 30);
            }
        };
        struct Sha1Loop2 {
            template <int i>
            static inline void f(uint32_t *a, uint32_t *b) {
                b[i] = blk(b, i);
                a[(1 + i) % 5] += ((a[(4 + i) % 5] & (a[(3 + i) % 5] ^ a[(2 + i) % 5])) ^ a[(2 + i) % 5]) + b[i] + 0x5a827999 + rol(a[(5 + i) % 5], 5);
                a[(4 + i) % 5] = rol(a[(4 + i) % 5], 30);
            }
        };
        struct Sha1Loop3 {
            template <int i>
            static inline void f(uint32_t *a, uint32_t *b) {
                b[(i + 4) % 16] = blk(b, (i + 4) % 16);
                a[i % 5] += (a[(3 + i) % 5] ^ a[(2 + i) % 5] ^ a[(1 + i) % 5]) + b[(i + 4) % 16] + 0x6ed9eba1 + rol(a[(4 + i) % 5], 5);
                a[(3 + i) % 5] = rol(a[(3 + i) % 5], 30);
            }
        };
        struct Sha1Loop4 {
            template <int i>
            static inline void f(uint32_t *a, uint32_t *b) {
                b[(i + 8) % 16] = blk(b, (i + 8) % 16);
                a[i % 5] += (((a[(3 + i) % 5] | a[(2 + i) % 5]) & a[(1 + i) % 5]) | (a[(3 + i) % 5] & a[(2 + i) % 5])) + b[(i + 8) % 16] + 0x8f1bbcdc + rol(a[(4 + i) % 5], 5);
                a[(3 + i) % 5] = rol(a[(3 + i) % 5], 30);
            }
        };
        struct Sha1Loop5 {
            template <int i>
            static inline void f(uint32_t *a, uint32_t *b) {
                b[(i + 12) % 16] = blk(b, (i + 12) % 16);
                a[i % 5] += (a[(3 + i) % 5] ^ a[(2 + i) % 5] ^ a[(1 + i) % 5]) + b[(i + 12) % 16] + 0xca62c1d6 + rol(a[(4 + i) % 5], 5);
                a[(3 + i) % 5] = rol(a[(3 + i) % 5], 30);
            }
        };
        struct Sha1Loop6 {
            template <int i>
            static inline void f(uint32_t *a, uint32_t *b) {
                b[i] += a[4 - i];
            }
        };

        static inline void sha1(uint32_t hash[5], uint32_t b[16]) {
            uint32_t a[5] = {hash[4], hash[3], hash[2], hash[1], hash[0]};
            static_for<16, Sha1Loop1>()(a, b);
            static_for<4, Sha1Loop2>()(a, b);
            static_for<20, Sha1Loop3>()(a, b);
            static_for<20, Sha1Loop4>()(a, b);
            static_for<20, Sha1Loop5>()(a, b);
            static_for<5, Sha1Loop6>()(a, hash);
        }

        static inline void base64(unsigned char *src, char *dst) {
            const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

        static inline void generate(const char input[24], char output[28]) {
            uint32_t b_output[5] = {
                    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
            };
            uint32_t b_input[16] = {
                    0, 0, 0, 0, 0, 0, 0x32353845, 0x41464135, 0x2d453931, 0x342d3437, 0x44412d39,
                    0x3543412d, 0x43354142, 0x30444338, 0x35423131, 0x80000000
            };

            for (int i = 0; i < 6; i++) {
                b_input[i] = (uint32_t) ((input[4 * i + 3] & 0xff) | (input[4 * i + 2] & 0xff) << 8 | (input[4 * i + 1] & 0xff) << 16 | (input[4 * i + 0] & 0xff) << 24);
            }
            sha1(b_output, b_input);
            uint32_t last_b[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 480};
            sha1(b_output, last_b);
            for (int i = 0; i < 5; i++) {
                uint32_t tmp = b_output[i];
                char *bytes = (char *) &b_output[i];
                bytes[3] = (char) (tmp & 0xff);
                bytes[2] = (char) ((tmp >> 8) & 0xff);
                bytes[1] = (char) ((tmp >> 16) & 0xff);
                bytes[0] = (char) ((tmp >> 24) & 0xff);
            }
            base64((unsigned char *) b_output, output);
        }
    } // namespace uws

    template<size_t src_len>
    static inline void UWS_SHA1(const void* FWS_RESTRICT src, void* FWS_RESTRICT dst) {
        static_assert(src_len == 60, "src_len should be 20 for SHA1");
        uws::sha1((uint32_t*)dst, (uint32_t*)src);
    }



} // namespace detail



namespace test{


    template<size_t client_key_len, size_t uuid_len>
    int64_t OSLSha1AndBase(const char* FWS_RESTRICT src_data, char* FWS_RESTRICT dst_buf, const char* FWS_RESTRICT ref_sha1, const char* FWS_RESTRICT ref_dst) {
        constexpr size_t buf_len = (20 + 2) / 3 * 4 + 1;
        memset(dst_buf, 0, buf_len);
        int64_t start_t = cpu_t::Start64();
        char sha1_buf[20];
        fws::Sha1(src_data, client_key_len + uuid_len, sha1_buf);
//        char dst_buf[buf_len];
        fws::OSLBase64Encode(sha1_buf, 20, dst_buf);
        int64_t end_t = cpu_t::Stop64();
        int64_t pass_ticks = end_t - start_t;
        if FWS_UNLIKELY(memcmp(dst_buf, ref_dst, buf_len) != 0) {
            printf("Error: sha1 and base64 encode result not match\n");
            return -1;
        }
        if FWS_UNLIKELY(memcmp(sha1_buf, ref_sha1, 20) != 0) {
            printf("Error: sha1 result not match\n");
            return -1;
        }

        return pass_ticks;
    }

    template<size_t client_key_len, size_t uuid_len>
    int64_t ConsSha1AndBase(const char* FWS_RESTRICT src_data, char* FWS_RESTRICT dst_buf, const char* FWS_RESTRICT ref_sha1, const char* FWS_RESTRICT ref_dst) {
        constexpr size_t buf_len = (20 + 2) / 3 * 4 + 1;
        memset(dst_buf, 0, buf_len);
        int64_t start_t = cpu_t::Start64();
        char sha1_buf[20];
        fws::Sha1(src_data, client_key_len + uuid_len, sha1_buf);
//        char dst_buf[buf_len];
        fws::detail::Fix20Base64Encode<20>(sha1_buf, dst_buf);
        int64_t end_t = cpu_t::Stop64();
        int64_t pass_ticks = end_t - start_t;
        if FWS_UNLIKELY(memcmp(dst_buf, ref_dst, buf_len) != 0) {
            printf("Error: sha1 and base64 encode result not match\n");
            return -1;
        }
        if FWS_UNLIKELY(memcmp(sha1_buf, ref_sha1, 20) != 0) {
            printf("Error: sha1 result not match\n");
            return -1;
        }

        return pass_ticks;
    }

    template<size_t client_key_len, size_t uuid_len>
    int64_t UWSSha1AndBase(const char* FWS_RESTRICT src_data, char* FWS_RESTRICT dst_buf, const char* FWS_RESTRICT ref_sha1, const char* FWS_RESTRICT ref_dst) {
        constexpr size_t buf_len = (20 + 2) / 3 * 4 + 1;
        memset(dst_buf, 0, buf_len);
        int64_t start_t = cpu_t::Start64();
        char sha1_buf[20];
//        fws::detail::UWS_SHA1<client_key_len + uuid_len>(src_data, sha1_buf);
        fws::Sha1(src_data, client_key_len + uuid_len, sha1_buf);
//        char dst_buf[buf_len];
        fws::detail::uws_base64((unsigned char*)sha1_buf, dst_buf);
        int64_t end_t = cpu_t::Stop64();
        int64_t pass_ticks = end_t - start_t;
        if FWS_UNLIKELY(memcmp(dst_buf, ref_dst, buf_len) != 0) {
            printf("Error: sha1 and base64 encode result not match\n");
            return -1;
        }
        if FWS_UNLIKELY(memcmp(sha1_buf, ref_sha1, 20) != 0) {
            printf("Error: sha1 result not match\n");
            return -1;
        }

        return pass_ticks;
    }

    template<size_t client_key_len, size_t uuid_len>
    int64_t PureSha1AndBase(const char* FWS_RESTRICT client_key, char* FWS_RESTRICT dst_buf, const char* FWS_RESTRICT ref_sha1, const char* FWS_RESTRICT ref_dst) {
        constexpr size_t buf_len = (20 + 2) / 3 * 4 + 1;
        memset(dst_buf, 0, buf_len);
        int64_t start_t = cpu_t::Start64();
//        char sha1_buf[20];
//        fws::detail::UWS_SHA1<client_key_len + uuid_len>(src_data, sha1_buf);
//        fws::Sha1(src_data, client_key_len + uuid_len, sha1_buf);
        detail::uws::generate(client_key, dst_buf);
//        char dst_buf[buf_len];
//        fws::detail::uws_base64((unsigned char*)sha1_buf, dst_buf);
        int64_t end_t = cpu_t::Stop64();
        int64_t pass_ticks = end_t - start_t;
        if FWS_UNLIKELY(memcmp(dst_buf, ref_dst, buf_len) != 0) {
            printf("Error: sha1 and base64 encode result not match\n");
            return -1;
        }
//        if FWS_UNLIKELY(memcmp(sha1_buf, ref_sha1, 20) != 0) {
//            printf("Error: sha1 result not match\n");
//            return -1;
//        }

        return pass_ticks;
    }


    int TestSha1AndBase64() {
        const char client_key[] = "dGhlIHNhbXBsZSBub25jZQ==";
        constexpr const char uuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string src_str = std::string(client_key) + std::string(uuid);
//    size_t src_len = src_str.size();
        std::string sha1_buf(20, '\0');
        fws::Sha1(src_str.data(), src_str.size(), sha1_buf.data());
//    for (size_t i = 0; i < 20; ++i) {
//        printf("")
//    }
        constexpr size_t buf_len = (20 + 2) / 3 * 4 + 1;
        std::string dst_buf(buf_len, '\0');
        fws::Fix20Base64Encode<20>(sha1_buf.data(), dst_buf.data());
        printf("Final base64:\n%s\n", dst_buf.c_str());
        char temp_dst_buf[buf_len];

        size_t warmup_round = 10'000;
        for (size_t i = 0; i < warmup_round; ++i) {
            int64_t temp_ols_tick = OSLSha1AndBase<24, 36>(src_str.data(), temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_ols_tick < 0) {
                return -1;
            }
            int64_t temp_cons_tick = ConsSha1AndBase<24, 36>(src_str.data(), temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_cons_tick < 0) {
                return -1;
            }
            int64_t temp_uws_tick = UWSSha1AndBase<24, 36>(src_str.data(), temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_uws_tick < 0) {
                return -1;
            }
            int64_t temp_pure_tick = PureSha1AndBase<24, 36>(client_key, temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_pure_tick < 0) {
                return -1;
            }
        }

        const size_t repeat = 2'000'000;

        int64_t ols_ticks = 0, cons_ticks = 0, uws_ticks = 0, pure_ticks = 0;


        for (size_t k = 0; k < repeat; ++k) {
            int64_t temp_ols_tick = OSLSha1AndBase<24, 36>(src_str.data(), temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_ols_tick < 0) {
                return -1;
            }
            ols_ticks += temp_ols_tick;

            int64_t temp_cons_tick = ConsSha1AndBase<24, 36>(src_str.data(), temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_cons_tick < 0) {
                return -1;
            }
            cons_ticks += temp_cons_tick;

            int64_t temp_uws_tick = UWSSha1AndBase<24, 36>(src_str.data(), temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_uws_tick < 0) {
                return -1;
            }
            uws_ticks += temp_uws_tick;
            int64_t temp_pure_tick = PureSha1AndBase<24, 36>(client_key, temp_dst_buf, sha1_buf.data(), dst_buf.data());
            if FWS_UNLIKELY(temp_pure_tick < 0) {
                return -1;
            }
            pure_ticks += temp_pure_tick;
        }

        for (size_t k = 0; k < repeat; ++k) {

        }

        double avg_ols_ns = ols_ticks / double(repeat);
        double avg_cons_ns = cons_ticks / double(repeat);
        double avg_uws_ns = uws_ticks / double(repeat);
        double avg_pure_ns = pure_ticks / double(repeat);
        printf("OSL sha1 and base64 encode average time: %lf ns\n", avg_ols_ns);
        printf("Cons sha1 and base64 encode average time: %lf ns\n", avg_cons_ns);
        printf("UWS sha1 and base64 encode average time: %lf ns\n", avg_uws_ns);
        printf("Pure sha1 and base64 encode average time: %lf ns\n", avg_pure_ns);

        return 0;
    }









} // namespace test



int main(int argc, const char** argv) {


    return test::TestSha1AndBase64();
}