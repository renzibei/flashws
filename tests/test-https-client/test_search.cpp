#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <vector>
#include "flashws/utils/cpu_timer.h"
#include <cstddef>
#include <cstdlib>
#include <cstring>

template<typename F>
static void timed(const char *name, F f)
{
    using namespace std::chrono;
    int64_t start_tick = cpu_t::Start64();
//    auto begin = high_resolution_clock::now();
    constexpr size_t repeat = 100000;
    for (size_t i = 0; i < repeat; ++i) {
        f();
    }
//    f();
    int64_t end_tick = cpu_t::Stop64();
//    auto end = high_resolution_clock::now();
    int64_t pass_tick = end_tick - start_tick;
    double avg_pass_tick = double(pass_tick) / repeat;
    std::cout << name << " : " << avg_pass_tick << " ticks\n";
//    std::cout << name << " : "
//              << duration_cast<nanoseconds>(end - begin).count() << " ns\n";
}

int main(int argc, char *argv[])
{
    std::vector<char> buf(1024);
//    std::vector<char> buf(4 * 1024);
//    std::vector<char> pattern(111);
//    pattern[110] = std::byte(1);
    std::vector<char> pattern = {'\r', '\n', '\r', '\n'};
    //warm up
    for (int i = 0; i < 10000; ++i) {
        memset(buf.data(), 0, buf.size());
    }
    memcpy(buf.data() + 384, pattern.data(), pattern.size());




    timed("std::default_searcher", [&] {
//        auto it = std::search(buf.begin(), buf.end(), pattern.begin(), pattern.end());
        auto it = std::search(buf.begin(), buf.end(),
                              std::default_searcher(pattern.begin(), pattern.end()));
        if (it == buf.end()) {
            std::cerr << "Incorrect result\n";
        }
    });

    timed("memmem", [&] {
        auto match = memmem(buf.data(), buf.size(),
                            pattern.data(), pattern.size());
        if (match == nullptr) {
            std::cerr << "Incorrect result\n";
        }
    });

    timed("std::boyer_moore_searcher", [&] {
        auto it = std::search(buf.begin(), buf.end(),
                              std::boyer_moore_searcher(pattern.begin(), pattern.end()));
        if (it == buf.end()) {
            std::cerr << "Incorrect result\n";
        }
    });

    timed("std::boyer_moore_horspool_searcher", [&] {
        auto it = std::search(buf.begin(), buf.end(),
                              std::boyer_moore_horspool_searcher(pattern.begin(), pattern.end()));
        if (it == buf.end()) {
            std::cerr << "Incorrect result\n";
        }
    });
}