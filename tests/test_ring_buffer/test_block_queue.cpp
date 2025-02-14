#include "flashws/utils/block_queue.h"
#include "flashws/utils/flash_alloc.h"
//#include "fast_alloc.h"
#include <deque>
#include <cstdlib>
#include <sys/mman.h>
#include <limits>

static uint64_t RandSeed = 0x12345678911ULL;
static inline uint64_t CustomRand() {
    RandSeed = 1103515245 * RandSeed + 12345;
    return RandSeed;
}

static inline void ResetSeed() {
    RandSeed = 0x12345678911ULL;
}

static inline void setSeed(uint64_t seed) {
    RandSeed = seed;
}

void testBlockQueue() {
    constexpr size_t BlockSize = 1 << 21;
    using TestType = uint64_t;
//    using Uint8Allocator = fws::internal::InternalAllocator<uint8_t>;
//    using Uint8PtrAllocator = fws::internal::InternalAllocator<uint8_t*>;
    using BlockQueueAllocator = fws::internal::InternalAllocator<TestType>;
    using BlockQueue = fws::BlockQueue<TestType, true, BlockQueueAllocator>;

    constexpr size_t TestSizeArray[] = {0, 1, 3, 8, 16, 47238947, 1 << 21, 1 << 22, (1 << 23) + 4, ( 1 << 24) + 123789, (1 << 27) + 37489, 5000};
    constexpr size_t TestNum = sizeof(TestSizeArray) / sizeof(TestSizeArray[0]);

    std::deque<TestType> stdDeque, stdDeque2;
    BlockQueue blockQueue(BlockSize), blockQueue2;
    size_t preDataSize = 0;
    for (size_t t = 0; t < TestNum; ++t) {

        auto temp_std_queue = std::move(stdDeque);
        stdDeque = std::move(stdDeque2);
        stdDeque2 = std::move(temp_std_queue);

        auto temp_block_queue = std::move(blockQueue);
        blockQueue = std::move(blockQueue2);
        blockQueue2 = std::move(temp_block_queue);

        size_t dataSize = TestSizeArray[t];
        stdDeque.resize(dataSize);
        blockQueue.resize(dataSize);

        stdDeque2.resize(0);
        blockQueue2.resize(0);




        setSeed(dataSize * 2);

        for (size_t i = 0; i < dataSize; ++i) {
            if (dataSize == 47238947 && i == 1048577) {
                int c = 0;
            }
            TestType x = CustomRand();
            if ((x & 3) && !stdDeque2.empty()) {
                stdDeque2.pop_back();
                blockQueue2.pop_back();
            }
            else {
                stdDeque2.push_back(x);
                blockQueue2.push_back(x);
            }
            if (!stdDeque2.empty()) {
                if (stdDeque2.back() != blockQueue2.back()) {
                    fprintf(stderr, "stdDeque2.back() != blockQueue2.back()");
                    return;
                }
            }
        }


        for (size_t i = 0; i < stdDeque2.size(); ++i) {
            if (stdDeque2[i] != blockQueue2[i]) {
                fprintf(stderr, "std deque[%lu] = %u while block queue[%lu] = %u", i, stdDeque2[i], i, blockQueue2[i]);
                return;
            }
        }

        setSeed(dataSize);
        for (size_t i = preDataSize; i < dataSize; ++i) {
            stdDeque[i] = CustomRand();
        }
        setSeed(dataSize);
        for (size_t i = preDataSize; i < dataSize; ++i) {
            blockQueue[i] = CustomRand();
        }

        for (size_t i = 0; i < dataSize; ++i) {
            if (stdDeque[i] != blockQueue[i]) {
                fprintf(stderr, "std deque[%lu] = %u while block queue[%lu] = %u", i, stdDeque[i], i, blockQueue[i]);
                return;
            }
        }
        if (stdDeque.size() != blockQueue.size()) {
            fprintf(stderr, "size not equal!");
            return;
        }

        if (t == 2) {
            int c = 0;
        }


        preDataSize = dataSize;

    }
    fprintf(stderr, "BlockQueue test passed!\n");

}

int main() {
    testBlockQueue();
}