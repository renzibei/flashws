#include "flashws/crypto/ws_mask.h"
#include "flashws/utils/cpu_timer.h"
#include <cstdint>
#include <cstdio>
#include <random>
#include <chrono>

namespace test {

    void Mask1(uint8_t *__restrict src, size_t size,
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

    void Mask2(uint8_t *__restrict src, size_t size,
               uint32_t mask) {
        uint8_t mask_arr[4];
        memcpy(mask_arr, &mask, 4);
        size_t size_div_4 = size / 4UL;
//        size_t size_div_16=size/16UL;
        uint32_t * __restrict u32_src = (uint32_t*)src;
        for (size_t i = 0; i < size_div_4; ++i) {
            // printf("in mask2, load %x\n", u32_src[i]);
            u32_src[i] = u32_src[i] ^ mask;
            // printf("in mask2, save %x\n", u32_src[i]);
        }
//        for (size_t i = 0; i < size_div_16; ++i) {
//            u32_src[i * 4UL + 0UL] = u32_src[i * 4UL + 0UL] ^ mask;
//            u32_src[i * 4UL + 1UL] = u32_src[i * 4UL + 1UL] ^ mask;
//            u32_src[i * 4UL + 2UL] = u32_src[i * 4UL + 2UL] ^ mask;
//            u32_src[i * 4UL + 3UL] = u32_src[i * 4UL + 3UL] ^ mask;
//        }
//        for (size_t i = size_div_16 * 4UL; i < size_div_4; ++i) {
//            u32_src[i] = u32_src[i] ^ mask;
//        }
        for (size_t i = size_div_4 * 4UL; i < size; ++i) {
            src[i] = src[i] ^ mask_arr[i & 3UL];
        }
        // printf("\n");
    }





    void Mask6(uint8_t * FWS_RESTRICT src, size_t size,
               uint32_t mask) {
//        using UInt = uint64_t;
        using UInt = __uint128_t;
//        UInt mask_uint = mask;
//        uint64_t mask_uint = ((uint64_t)mask << 32U) | mask;
//        UInt mask_uint = (UInt(mask) << 32U) | mask;
        UInt mask_uint = (UInt(mask) << 96U) | UInt(mask) << 64U | (UInt(mask) << 32U) | (UInt)mask;
        uint8_t mask_arr[4];

        memcpy(mask_arr, &mask, 4);
        size_t size_div = size / sizeof(UInt);
//        size_t size_div = size / 8UL;
//        uint64_t * FWS_RESTRICT  uint_src = (uint64_t* FWS_RESTRICT )src;
        UInt * FWS_RESTRICT  uint_src = (UInt* FWS_RESTRICT )src;
        for (size_t i = 0; i < size_div; ++i) {
            uint_src[i] = uint_src[i] ^ mask_uint;
        }
        for (size_t i = size_div * sizeof(UInt); i < size; ++i) {
            src[i] = src[i] ^ mask_arr[i & 3UL];
        }
    }





    FWS_ALWAYS_INLINE void Mask5(uint8_t * FWS_RESTRICT src, size_t size,
                                 uint32_t mask) {
        return fws::MaskLargeChunkAVX2(src, size, mask);
    }

    FWS_ALWAYS_INLINE void Mask4(uint8_t * FWS_RESTRICT src, size_t size,
                                 uint32_t mask) {

        return fws::MaskAVX2(src, size, mask);
    }

    size_t GetHash(const uint8_t *src, size_t len) {
        size_t src_hash = std::hash<std::string_view>{}(std::string_view((char*)src, len));
        return src_hash;
    }

    struct alignas(1) Pack {
//        uint64_t data[4];
        char data;
    };

    int test_main(int argc, const char** argv) {
        if (argc != 2) {
            printf("Invalid arguments!, Usage:\n./test_utils function_index\n");
            return 0;
        }
        int m_index = atoi(argv[1]);
        // CB cb;
        // cb.Init();
        cpu_t::CpuTimer<uint64_t> cpu_timer{};
        printf("cpu timer overhead ticks: %ld, ticks per ns: %lf\n",
               cpu_timer.overhead_ticks(), 1.0 / cpu_timer.ns_per_tick());
        size_t seed = std::random_device{}();
        std::mt19937_64 gen64{seed};
        size_t len = 3024;
        size_t repeat = 65536 * 64;
        constexpr size_t offset = 1;
        using UInt = Pack;
        std::vector<UInt> data((len + offset + sizeof(UInt) - 1UL) / sizeof(UInt));
        for (size_t i = 0; i < len; ++i) {
            *((uint8_t*)data.data() + offset + i) = gen64();
        }
        std::vector<UInt> back_up_data(data);
        uint32_t mask = gen64();
        printf("mask: %x\n", mask);
        uint64_t mask64 = (uint64_t(mask) << 32U) | mask;
        printf("mask64: %lx\n", mask64);
        uint8_t *src_data = ((uint8_t*)data.data()) + offset;
//        uint8_t *src_backup = ((uint8_t*)back_up_data.data()) + offset;
        Mask1(src_data, len, mask);
        size_t src_hash = GetHash(src_data, len);
        Mask1(src_data, len, mask);
        printf("src hash: %zu\n", src_hash);

        using MaskFunc = void (*)(uint8_t * FWS_RESTRICT src, size_t size,
                                  uint32_t mask);
        MaskFunc all_funcs[] = {Mask1, Mask2, fws::WSMaskBytes, Mask4, Mask5, Mask6, fws::WSMaskBytesFast};
        MaskFunc mask_func;
        if (m_index >= 1 && m_index <= 7) {
            mask_func = all_funcs[m_index - 1];
        }
        else {
            printf("m_index out of range!\n");
            return -1;
        }


        std::vector<size_t> test_lens = {34,45,67,93,131,223,225,266,329,430, 431, 432, 433, 434, 522, 528, 529, 531, 9872, 37840};

        std::vector<size_t> test_offsets;
        for (size_t i = 0; i <= 512; ++i) {
            test_lens.push_back(i);
            test_offsets.push_back(i);
        }
        for (auto test_len: test_lens) {
            for (auto test_offset: test_offsets) {
                uint8_t *test_src = ((uint8_t*)data.data()) + test_offset;
                Mask1(src_data, test_len, mask);
                size_t test_target_hash = GetHash(test_src, test_len);
                Mask1(src_data, test_len, mask);

                mask_func(src_data, test_len, mask);
                size_t test_custom_hash = GetHash(test_src, test_len);
                if (test_custom_hash != test_target_hash) {
                    printf("Error, target hash: %zu, custom hash: %zu, len: %zu, offset: %zu\n",
                           test_target_hash, test_custom_hash, test_len, test_offset);
                    return -1;
                }
                mask_func(src_data, test_len, mask);
                for (size_t i = 0; i < data.size(); ++i) {
                    if (data[i].data != back_up_data[i].data) {
                        printf("Error, data is changed in %zu byte\n", i);
                        return -1;
                    }
                }
            }
        }






        // warmup
        for (size_t i = 0; i < 128; ++i) {
            mask_func(src_data, len, mask);
        }

        {
            auto t0 = cpu_timer.Start();
            for (size_t i = 0; i < repeat; ++i) {
                mask_func(src_data, len, mask);
            }
            auto t1 = cpu_timer.Stop();

            mask_func(src_data, len, mask);
            size_t temp_hash = GetHash(src_data, len);
            mask_func(src_data, len, mask);
            auto pass_ticks = t1 - t0;
            uint64_t dur0_ns = pass_ticks * cpu_timer.ns_per_tick();
            double dur0_ms = dur0_ns / (1e+6);
            if (temp_hash != src_hash) {
                printf("Error, hash: %zu not equals to src_hash: %zu\n",
                       temp_hash, src_hash);
            }
            double throughput = len * repeat / double(1024LL * 1024LL * 1024LL) / (dur0_ms / (1e+3));
            printf("hash%d: %zu,\t%lf ms\t%lf GB/s\n",
                   m_index, temp_hash, dur0_ms, throughput);
        }




        return 0;

    }

} // namespace test


int main(int argc, const char** argv) {

    return test::test_main(argc, argv);
}