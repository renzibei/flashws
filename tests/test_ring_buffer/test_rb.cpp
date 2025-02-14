#include "flashws/utils/ring_buffer.h"
#include "flashws/utils/cpu_timer.h"
#include "flashws/utils/histogram_wrapper.h"
#include "flashws/utils/flash_alloc.h"
#include <random>
#include <cstdio>
#include <string>
#include <deque>

#include "flashws/base/errno_str.h"

#define TEST_RB_CORRECT 1

namespace test {

    class TestClass {
    public:
//        TestClass() = default;

//        TestClass(const TestClass& o) = delete;
//        TestClass& operator=(const TestClass&o) = delete;
        TestClass(TestClass &&o) noexcept {
            memcpy(data, o.data, sizeof(data));
        }
        TestClass& operator=(TestClass &&o) noexcept {
            std::swap(data, o.data);
            return *this;
        }
//        TestClass(const TestClass& o) = default;
//        TestClass(TestClass &&o) = delete;
//        TestClass& operator=(TestClass &&o) = delete;

        template<class PRNG>
        explicit TestClass(size_t max_len, PRNG &rng) {
            size_t r = rng();
            memset(data, 0, sizeof(data));
            memcpy(data, &r, sizeof(r));
//            size_t len = rng() % max_len + 1U;
//            data = std::string(len, '\0');
//            for (size_t i = 0; i < len; ++i) {
//                data[i] = 'A' + rng() % 26;
//            }
        }

        friend bool operator==(const TestClass& a, const TestClass& b) {
//            return a.data == b.data;
            return !memcmp(a.data, b.data, sizeof(a.data));
        }

        friend bool operator!=(const TestClass& a, const TestClass& b) {
//            return a.data != b.data;
            return memcmp(a.data, b.data, sizeof(a.data));
        }

        const char* data_ptr() const {
            return data;
        }

//        const std::string& str() const {
//            return data;
//        }
    protected:
        char data[64];
//        std::string data;
    };

    template<class C>
    void PrintContainer(const C& container) {
        for (auto it = container.begin(); it != container.end(); ++it) {
            size_t data = 0;
            memcpy(&data, it->data_ptr(), sizeof(data));
            printf("%zu ",data);
        }
        printf("\n");
    }

    template<class C1, class C2>
    bool IsSame(const C1& container1, const C2& container2) {
        size_t size = container1.size();
        if FWS_UNLIKELY(size != container2.size()) {
            printf("C1 size: %zu, C2 size: %zu\n",
                   size, container2.size());
            ssize_t it_diff = container2.end() - container2.begin();
            if FWS_UNLIKELY(it_diff != ssize_t(size)) {
                printf("C2 end - begin: %zd\n",
                       it_diff);
                return false;
            }
            return false;
        }

        auto it = container1.begin();
        auto jt = container2.begin();
        for (size_t i = 0; i < size; ++i) {
            if (!(*it++ == *jt++)) {
                printf("data at %zu is different\n",
                       i);
                printf("container1:\n");
                PrintContainer(container1);
                printf("Container2:\n");
                PrintContainer(container2);
                return false;
            }
        }

        auto rit = container1.rbegin();
        auto rjt = container2.rbegin();
        for (size_t i = 0; i < size; ++i) {
            if (!(*rit++ == *rjt++)) {
                printf("data at %zu is different\n",
                       i);
                printf("container1:\n");
                PrintContainer(container1);
                printf("Container2:\n");
                PrintContainer(container2);
                return false;
            }
        }



        return true;

    }

    void TestRingBuffer() {
        size_t TEST_ROUND = 100;
        constexpr size_t OP_PER_ROUND = 200000;
        size_t seed = 0;
//        size_t seed = std::random_device{}();
        auto rand_gen = std::mt19937_64(seed);
        constexpr double add_prop = 0.5;
        constexpr double erase_prop = 0.8; // Use erase instead of pop, check after not add
        constexpr size_t add_threshold = UINT64_MAX * add_prop;
        constexpr size_t erase_threshold = UINT64_MAX * erase_prop;

        constexpr double add_front_prop = 0.35;
        constexpr double add_back_prop = 0.35;
        constexpr size_t add_front_threshold = UINT64_MAX * add_front_prop;
        constexpr size_t add_back_threshold = add_front_threshold + UINT64_MAX * add_back_prop;
        constexpr size_t MAX_LEN = 63;

        cpu_t::CpuTimer<int64_t> cpu_timer{};
        size_t MAX_OP_NUM = TEST_ROUND * OP_PER_ROUND;
        hist::HistWrapper rb_push_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper rb_emplace_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper rb_pop_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper rb_erase_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper dq_push_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper dq_emplace_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper dq_pop_hist{MAX_OP_NUM, 1, 1'000'000LL};
        hist::HistWrapper dq_erase_hist{MAX_OP_NUM, 1, 1'000'000LL};

        for (size_t r = 0; r < TEST_ROUND; ++r) {
            using Alloc = fws::FlashAllocator<TestClass>;
            using DequeType = std::deque<TestClass, Alloc>;
            using RingBufferType = frb::RingBuffer<TestClass, Alloc>;
            RingBufferType rb;
//            rb.reserve(16);
//            rb.reserve(OP_PER_ROUND / 2);
            DequeType deque;
            for (size_t op_cnt = 0; op_cnt < OP_PER_ROUND; ++op_cnt) {
//                bool is_front = rand_gen() & 1U;
                bool is_add = rand_gen() <= add_threshold;
                if (is_add) {
                    uint64_t deter_add_pos = rand_gen();
                    bool add_front = deter_add_pos <= add_front_threshold;
                    bool add_back = !add_front && (deter_add_pos <= add_back_threshold);
                    size_t temp_seed = rand_gen();
                    rand_gen.seed(temp_seed);
                    TestClass c1(MAX_LEN, rand_gen);
                    rand_gen.seed(temp_seed);
                    TestClass c2(MAX_LEN, rand_gen);
                    if (add_front) {
//                        rb.push_front(c1);
//                        deque.push_front(c2);
                        auto rb_push_ticks = cpu_timer.Measure<true>([&](){
                            rb.push_front(std::move(c1));
                        });
                        auto deque_push_ticks = cpu_timer.Measure<true>([&](){
                            deque.push_front(std::move(c2));
                        });
                        rb_push_hist.AddValue(rb_push_ticks);
                        dq_push_hist.AddValue(deque_push_ticks);

                    }
                    else if (add_back) {
//                        rb.push_back(c1);
//                        deque.push_back(c2);
                        auto rb_push_ticks = cpu_timer.Measure<true>([&](){
                            rb.push_back(std::move(c1));
                        });
                        auto deque_push_ticks = cpu_timer.Measure<true>([&](){
                            deque.push_back(std::move(c2));
                        });
                        rb_push_hist.AddValue(rb_push_ticks);
                        dq_push_hist.AddValue(deque_push_ticks);

                    }
                    else {
                        size_t add_pos = rand_gen() % (deque.size() + 1);
                        auto dq_it = deque.begin();
                        auto rb_it = rb.begin();
                        dq_it += add_pos;
                        rb_it += add_pos;
                        if (op_cnt == 15) {
                            int a = 0;
                        }
                        auto rb_emplace_ticks = cpu_timer.Measure<true>([&](){
                            rb_it = rb.emplace(rb_it, std::move(c1));
                        });
                        auto dq_emplace_ticks = cpu_timer.Measure<true>([&](){
                            dq_it = deque.emplace(dq_it, std::move(c2));
                        });
                        rb_emplace_hist.AddValue(rb_emplace_ticks);
                        dq_emplace_hist.AddValue(dq_emplace_ticks);
                        FWS_ASSERT(*rb_it == *dq_it);
//                        if (!IsSame(rb, deque)) {
//                            printf("round %zu, op_cnt %zu, not same\n",
//                                   r, op_cnt);
//                        }
//                        FWS_ASSERT(IsSame(rb, deque));
                    }
                } else {
                    if (deque.empty()) {
                        FWS_ASSERT(rb.empty());
                        continue;
                    }
                    bool is_erase = rand_gen() <= erase_threshold;
                    if (is_erase) {
                        int64_t dq_erase_ticks = 0, rb_erase_ticks = 0;
                        bool use_reverse_it = rand_gen() & 1U;
                        DequeType::iterator dq_erase_it;
                        RingBufferType::iterator rb_erase_it;
                        if (use_reverse_it) {

                            auto dq_it = deque.rbegin();
                            auto rb_it = rb.rbegin();
                            size_t inc_num = rand_gen() % (deque.size());
//                            for (size_t i = 0; i < inc_num; ++i) {
//                                ++dq_it; ++rb_it;
//                            }
                            dq_it += inc_num;
                            rb_it += inc_num;
                            dq_erase_ticks = cpu_timer.Measure<true>([&](){
                                dq_erase_it = deque.erase((++dq_it).base());
                            });
                            rb_erase_ticks = cpu_timer.Measure<true>([&](){
                                rb_erase_it = rb.erase((++rb_it).base());
                            });

                        }
                        else {
                            auto dq_it = deque.begin();
                            auto rb_it = rb.begin();
                            size_t inc_num = rand_gen() % (deque.size());
//                            for (size_t i = 0; i < inc_num; ++i) {
//                                ++dq_it; ++rb_it;
//                            }
                            dq_it += inc_num;
                            rb_it += inc_num;
                            dq_erase_ticks = cpu_timer.Measure<true>([&](){
                                dq_erase_it = deque.erase(dq_it);
                            });
                            rb_erase_ticks = cpu_timer.Measure<true>([&](){
                                rb_erase_it = rb.erase(rb_it);
                            });
//                        auto dq_erase_it = deque.erase(dq_it);
//                        auto rb_erase_it = rb.erase(rb_it);

                        }
                        if FWS_UNLIKELY(dq_erase_it == deque.end()) {
                            FWS_ASSERT(rb_erase_it == rb.end());
                        }
                        else {
                            FWS_ASSERT(*dq_erase_it == *rb_erase_it);
                        }

                        rb_erase_hist.AddValue(rb_erase_ticks);
                        dq_erase_hist.AddValue(dq_erase_ticks);
                    }
                    else if (rand_gen() & 1U) {
//                        if FWS_UNLIKELY(rb.front() != deque.front()) {
//                            PrintContainer(rb);
//                            PrintContainer(deque);
//                        }
#ifdef TEST_RB_CORRECT
                        FWS_ASSERT(rb.front() == deque.front());
#endif
                        auto rb_pop_ticks = cpu_timer.Measure<true>([&](){
//                            auto rb_front = rb.get_pop_front();
//#ifdef TEST_RB_CORRECT
//                            FWS_ASSERT(rb_front == deque.front());
//#endif
                            rb.pop_front();
                        });
                        auto dq_pop_ticks = cpu_timer.Measure<true>([&](){
                            deque.pop_front();
                        });
                        rb_pop_hist.AddValue(rb_pop_ticks);
                        dq_pop_hist.AddValue(dq_pop_ticks);
                    } else {
//                        if FWS_UNLIKELY(rb.back() != deque.back()) {
////                            printf("rb back: %s\n", rb.back().str().c_str());
////                            printf("deque back: %s\n", deque.back().str().c_str());
//                            PrintContainer(rb);
//                            PrintContainer(deque);
//                        }
#ifdef TEST_RB_CORRECT
                        FWS_ASSERT(rb.back() == deque.back());
#endif
                        auto rb_pop_ticks = cpu_timer.Measure<true>([&](){
//                            auto rb_back = rb.get_pop_back();
//#ifdef TEST_RB_CORRECT
//                            FWS_ASSERT(rb_back == deque.back());
//#endif
                            rb.pop_back();
                        });
                        auto dq_pop_ticks = cpu_timer.Measure<true>([&](){
                            deque.pop_back();
                        });
                        rb_pop_hist.AddValue(rb_pop_ticks);
                        dq_pop_hist.AddValue(dq_pop_ticks);

                    }
                }

            }
#ifdef TEST_RB_CORRECT
            if FWS_UNLIKELY(!IsSame(rb, deque)) {
                printf("not same after this round %zu\n",
                       r);
//                printf("Failed at round %zu, op_cnt %zu\n",
//                       r, op_cnt);
                std::abort();
            }
#endif
        }
        printf("Test End\n");
        printf("\nRing Buffer push back or front hist:\n");
        rb_push_hist.PrintHdr(20, stdout, 1);
        printf("\ndeque push back or front hist:\n");
        dq_push_hist.PrintHdr(20, stdout, 1);
        printf("\nRing Buffer emplace hist:\n");
        rb_emplace_hist.PrintHdr(20, stdout, 1);
        printf("\ndeque emplace hist:\n");
        dq_emplace_hist.PrintHdr(20, stdout, 1);
        printf("\nRing Buffer pop back or front hist:\n");
        rb_pop_hist.PrintHdr(20, stdout, 1);
        printf("\ndeque pop back or front hist:\n");
        dq_pop_hist.PrintHdr(20, stdout, 1);
        printf("\nRing Buffer erase hist:\n");
        rb_erase_hist.PrintHdr(20, stdout, 1);
        printf("\ndeque erase hist:\n");
        dq_erase_hist.PrintHdr(20, stdout, 1);


    }


} // namespace test

int main () {

    test::TestRingBuffer();
    return 0;
}