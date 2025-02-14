#include "flashws/utils/flash_alloc.h"
#include "flashws/base/constexpr_math.h"
#include "flashws/utils/histogram_wrapper.h"
#include "flashws/utils/cpu_timer.h"

#include <algorithm>  // for std::max
#include <array>
#include <cstdio>
#include <cstring>
#include <list>
#include <vector>

namespace test {

    static constexpr size_t MAX_TOTAL_SIZE = 1UL << 24;
    static constexpr size_t MIN_STR_LEN = 1ULL << 8;
    static constexpr size_t MAX_STR_LEN = (1ULL << 20) * 2UL;
    static constexpr size_t LOOP_NUM = fws::RoundUpLog2(MAX_STR_LEN) + 1UL;

    int TestAlloc1() {
        // Ensure the MemPoolEnv is initialized
        fws::MemPoolEnv::instance();

        // CPU timer for measuring overhead and allocation times
        cpu_t::CpuTimer<uint64_t> cpu_timer;
        printf("overhead ticks: %ld, ticks per ns: %lf\n",
               cpu_timer.overhead_ticks(), 1.0 / cpu_timer.ns_per_tick());

        // Arrays/vectors to keep track of pointers and histograms
        std::array<std::vector<char*>, LOOP_NUM> str_arr;
        std::vector<hist::HistWrapper> alloc_hist_arr(LOOP_NUM);
        std::vector<hist::HistWrapper> de_hist_arr(LOOP_NUM);

        hist::HistWrapper total_alloc_hist(1000000, 1, 10'000'000LL);
        hist::HistWrapper total_de_hist(1000000, 1, 10'000'000LL);

        constexpr size_t REPEAT_TIME = 128;

        for (size_t re = 0; re < REPEAT_TIME; ++re) {
            // Allocation phase
            for (size_t str_len = MIN_STR_LEN; str_len <= MAX_STR_LEN; str_len *= 2UL) {
                size_t construct_num = MAX_TOTAL_SIZE / str_len;
                size_t index = fws::RoundUpLog2(str_len);

                // Initialize histogram objects and vector storage once
                if (re == 0) {
                    alloc_hist_arr[index] = hist::HistWrapper(construct_num, 1, 10'000'000LL);
                    de_hist_arr[index] = hist::HistWrapper(construct_num, 1, 10'000'000LL);
                    str_arr[index].resize(construct_num);
                }

                for (size_t i = 0; i < construct_num; ++i) {
                    auto t0 = cpu_timer.Start();
                    char* new_p = static_cast<char*>(fws::MemPoolEnv::instance().allocate(str_len));
                    auto t1 = cpu_timer.Stop();

                    str_arr[index][i] = new_p;

                    if (re != 0) {
                        int64_t pass_ticks = t1 - t0;
                        int64_t temp_ticks = std::max<int64_t>(0, pass_ticks - cpu_timer.overhead_ticks());
                        alloc_hist_arr[index].AddValue(temp_ticks);
                        total_alloc_hist.AddValue(temp_ticks);
                    }

                    // Initialize memory
                    memset(str_arr[index][i], 1, str_len);
                }
            }

            // Deallocation phase
            for (size_t str_len = MIN_STR_LEN; str_len <= MAX_STR_LEN; str_len *= 2UL) {
                size_t construct_num = MAX_TOTAL_SIZE / str_len;
                size_t index = fws::RoundUpLog2(str_len);

                for (size_t i = 0; i < construct_num; ++i) {
                    char* to_free_p = str_arr[index][i];

                    auto t0 = cpu_timer.Start();
                    fws::MemPoolEnv::instance().deallocate(to_free_p);
                    auto t1 = cpu_timer.Stop();

                    if (re != 0) {
                        int64_t pass_ticks = t1 - t0;
                        int64_t temp_ticks = std::max<int64_t>(0, pass_ticks - cpu_timer.overhead_ticks());
                        de_hist_arr[index].AddValue(temp_ticks);
                        total_de_hist.AddValue(temp_ticks);
                    }
                }
            }
        }

        // Print histograms per size
        for (size_t str_len = MIN_STR_LEN; str_len <= MAX_STR_LEN; str_len *= 2UL) {
            size_t index = fws::RoundUpLog2(str_len);
            printf("alloc hist for %zu size:\n", str_len);
            auto& alloc_hist = alloc_hist_arr[index];
            alloc_hist.SortForUse();
            printf("P0: %ld,\tP50: %ld,\tP99: %ld,\tP999: %ld\n",
                   alloc_hist.Quantile(0.0), alloc_hist.Quantile(0.5),
                   alloc_hist.Quantile(0.99), alloc_hist.Quantile(0.999));

            printf("dealloc hist for %zu size:\n", str_len);
            auto& de_hist = de_hist_arr[index];
            de_hist.SortForUse();
            printf("P0: %ld,\tP50: %ld,\tP99: %ld,\tP999: %ld\n\n",
                   de_hist.Quantile(0.0), de_hist.Quantile(0.5),
                   de_hist.Quantile(0.99), de_hist.Quantile(0.999));
        }

        // Print total histograms
        printf("Total alloc hist:\n");
        total_alloc_hist.PrintHdr(10, stdout, 1);
        printf("\nTotal dealloc hist:\n");
        total_de_hist.PrintHdr(10, stdout, 1);

        // Log final allocation stats
        fws::MemPoolEnv::instance().LogAllocStats();

        return 0;
    }

    int TestAlloc2() {
        constexpr size_t REPEAT_TIME = 32;

        for (size_t re = 0; re < REPEAT_TIME; ++re) {
            for (size_t str_len = MIN_STR_LEN; str_len <= MAX_STR_LEN; str_len *= 2UL) {
                // Using FlashAllocator for demonstration
                std::vector<uint64_t, fws::FlashAllocator<uint64_t>> vec1(str_len);
                std::vector<uint32_t, fws::FlashAllocator<uint32_t>> vec2;
                std::list<uint64_t, fws::FlashAllocator<uint64_t>> list1;

                // Fill containers
                for (size_t i = 0; i < str_len; ++i) {
                    vec2.push_back(rand());
                    list1.push_back(rand());
                }
            }
        }

        // Log final allocation stats
        printf("\n");
        fws::MemPoolEnv::instance().LogAllocStats();

        return 0;
    }

}  // namespace test

int main() {
    int ret1 = test::TestAlloc1();
    if (ret1 != 0) {
        return ret1;
    }
    return test::TestAlloc2();
}
