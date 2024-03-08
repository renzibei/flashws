#pragma once

#include <cstdlib>   // posix_memalign
#include <sys/mman.h> // madvise
#include <limits>
#include <new>
#include "flashws/utils/flash_alloc.h"
#include "flashws/base/constexpr_math.h"
#include "flashws/utils/block_queue.h"
#include "flashws/utils/flat_hash_map.h"
#include "flashws/utils/singleton.h"
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <string>
//#include <execinfo.h>
//#include <unistd.h>
//#include <dlfcn.h>
//#include <cxxabi.h>

#ifdef __linux__
#   define FWS_ENABLE_HUGE_PAGE_ALLOC 1
#else
#   define FWS_ENABLE_HUGE_PAGE_ALLOC 0
#endif

#define FWS_ENABLE_MEM_POOL 1
#define FWS_ALLOC_ENABLE_PREFAULT 1

//#define FWS_DEBUG_FLASH_ALLOC
#define FWS_POOL_RECLAIM_MEMORY

// We use memory pools with no buddy system. So will be some waste if some size
// were once used a lot but never be used later

namespace fws {

    namespace internal {

        constexpr static std::size_t ALLOC_HUGE_PAGE_SIZE = 1ULL << 21; // 2 MiB
        constexpr static std::size_t ALLOC_HUGE_PAGE_THRESHOLD = 1 << 14; // 16KB

        void *internal_alloc(size_t n, bool prefault) {
            void *p = nullptr;
            size_t alloc_bytes = n;
#if FWS_ENABLE_HUGE_PAGE_ALLOC
            if (alloc_bytes >= ALLOC_HUGE_PAGE_THRESHOLD) {
                int ret = posix_memalign(&p, ALLOC_HUGE_PAGE_SIZE, alloc_bytes);
                if FWS_UNLIKELY(ret != 0) {
                    throw std::bad_alloc();
                }
                madvise(p, alloc_bytes, MADV_HUGEPAGE);
            }
            else {
                p = malloc(alloc_bytes);
            }
#else
            int ret = posix_memalign(&p, ALLOC_HUGE_PAGE_SIZE, alloc_bytes);
            if FWS_UNLIKELY(ret != 0) {
                throw std::bad_alloc();
            }
//            p = std::malloc(alloc_bytes);
#endif

#if FWS_ALLOC_ENABLE_PREFAULT
            if (prefault) {
                // map into physical page, cause page fault
                memset(p, 0, alloc_bytes);
            }
#endif
            return p;
        }

        void internal_free(void *ptr) {
            std::free(ptr);
        }


        template <typename T>
        class InternalAllocator {
        public:
            using value_type = T;

            InternalAllocator() = default;

            template<class U>
            constexpr InternalAllocator(const InternalAllocator<U> &) noexcept {}

            InternalAllocator(const InternalAllocator&) = default;

            friend bool operator==(const InternalAllocator&, const InternalAllocator&) {
                return true;
            }

            friend bool operator!=(const InternalAllocator&, const InternalAllocator&) {
                return false;
            }

            T *allocate(std::size_t n) {
                if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
                    throw std::bad_alloc();
                }
                void *p = internal_alloc(n * sizeof(T), true);
//            p = malloc(n * sizeof(T));

                if (p == nullptr) {
                    throw std::bad_alloc();
                }

                return static_cast<T *>(p);
            }

            void deallocate(T *p, std::size_t /**/) {
                internal_free(p);
//                std::free(p);
//                deallocate(p);
            }
        };
    }; // namespace internal



    class MemPool {
    protected:
        constexpr static uint64_t MAX_TYPE_SIZE_LOG2 = 42; // 4T
        constexpr static size_t TYPE_SIZE_NUM = MAX_TYPE_SIZE_LOG2 + 1;
        constexpr static size_t META_DATA_HEAD_SIZE = 16;
    public:

        MemPool() {
            InitializeFlashAllocator();
        }



        void *allocate(size_t n) {
            if (n == 0) {
                return nullptr;
            }
#ifdef FWS_POOL_RECLAIM_MEMORY
            size_t demand_bytes = n;
            size_t head_bytes = 0;
            bool save_meta_ahead_flag = false;
            if (demand_bytes < SMALL_MEM_ENTRY_THRES) {
                save_meta_ahead_flag = true;
                head_bytes = META_DATA_HEAD_SIZE;
                demand_bytes = META_DATA_HEAD_SIZE + n;
                static_assert(alignof(std::max_align_t) <= META_DATA_HEAD_SIZE);
//                head_bytes = 8;
//                demand_bytes = 8 + n;
            }

#else
            size_t demand_bytes = n;
#endif
            uint64_t power2 = RoundUpPow2(demand_bytes);
            uint64_t log2 = RoundUpLog2(demand_bytes);
            alloc_cnt_[log2]++;
            int64_t now_cnt = alloc_cnt_[log2] - dealloc_cnt_[log2];
            peak_cnt_[log2] = now_cnt > peak_cnt_[log2] ? now_cnt : peak_cnt_[log2];


            void *p = nullptr;



#if FWS_ENABLE_MEM_POOL

            if (has_alloc_num_[log2] + 1 > reserve_cap_[log2]) {

                if (reserve_cap_[log2] == 0) {
                    reserve_cap_[log2] = 1;
                }
                else {
                    reserve_cap_[log2] *= 2;
                }
                memory_buffers_[log2].resize(power2 * reserve_cap_[log2]);
#ifdef FWS_POOL_RECLAIM_MEMORY
                size_t previousCap = has_alloc_num_[log2], nowCap = reserve_cap_[log2];
                size_t capDiff = nowCap - previousCap;
                size_t previousPoolStackSize = pool_index_stack_[log2].size();
                pool_index_stack_[log2].resize(pool_index_stack_[log2].size() + capDiff);
                for (size_t i = 0; i < capDiff; ++i) {
//                    if (i + 1 > nowCap) {
//                        throw std::runtime_error("i + 1>= nowCap, i: " + std::to_string(i) + ", nowCap: " + std::to_string(nowCap)
//                                                 + ", capDiff: " + std::to_string(capDiff) + ", previousCap: " + std::to_string(previousCap)) ;
//                    }
                    pool_index_stack_[log2][previousPoolStackSize + i] = (nowCap - i) - 1;
                }
#endif

            }
#ifdef FWS_POOL_RECLAIM_MEMORY
            size_t newPoolIndex = pool_index_stack_[log2].back();
            pool_index_stack_[log2].pop_back();
            if FWS_UNLIKELY(newPoolIndex > reserve_cap_[log2]) {
                throw std::runtime_error("newPoolIndex > reserve_cap_[log2], newPoolIndex: " + std::to_string(newPoolIndex) +
                                        ", reserve_cap_[log2]: " + std::to_string(reserve_cap_[log2]) + ", log2: " + std::to_string(log2));
            }
            uint8_t *memPtr = &(memory_buffers_[log2][power2 * newPoolIndex]);
            if (save_meta_ahead_flag) {
                uint8_t *userDataPtr = memPtr + head_bytes;
                p = static_cast<void*>(userDataPtr);
                uint32_t *log2InfoPtr = (uint32_t*)(userDataPtr - 8);
                uint32_t *poolIndexInfoPtr = (uint32_t*)(userDataPtr - 4);
                *log2InfoPtr = log2;
                *poolIndexInfoPtr = newPoolIndex;
            }
            else {
                p = static_cast<void*>(memPtr);
                mem_meta_map_[p] = MemMetaData{(uint32_t)log2, (uint32_t)newPoolIndex};
            }

#else
            p = static_cast<void*>(&(memory_buffers_[log2][power2 * has_alloc_num_[log2]]));
#endif

            has_alloc_num_[log2]++;

#else
            uint64_t allocate_bytes = power2;
            //        p = std::malloc(allocate_bytes);
            int ret = posix_memalign(&p, 512, allocate_bytes);
            if (ret != 0) {
                throw std::bad_alloc();
            }
#endif


#ifdef FWS_DEBUG_FLASH_ALLOC
            if (p != nullptr) {
            try {
                allocSizeMap[(uint64_t) p] = log2;
            }
            catch (const std::exception& e) {
                LogHelper::log(Error, "Error in write allocSizeMap, pointer p: %llx, cur log2: %lu, alloc_cnt_[] is %lu, peak_cnt_[] is %lu, now_cnt is %lu",
                               (uint64_t)p, log2, alloc_cnt_[log2], peak_cnt_[log2], now_cnt);
                throw e;
            }
        }
#endif
            return p;
        } // fast_alloc

        void *aligned_alloc(size_t alignment, size_t size) {
            size_t demandSize = alignment - 1 + size + sizeof(uint8_t*);
            uint8_t *realPtr = (uint8_t*) allocate(demandSize);
            uint8_t *startPtr = realPtr + sizeof(uint8_t*);
            uint8_t *userPtr = startPtr + ( alignment - (((uint64_t)startPtr) & (alignment - 1)) );
            uint8_t **infoPtr = (uint8_t **)(userPtr - sizeof(uint8_t*));
            *infoPtr = realPtr;
            return (void*)userPtr;
        }

        void *allocate(size_t num, size_t size) {
            return allocate(num * size);
        }

//        static void printStackTrace() {
//            void* array[30];
//            char** strings;
//            int size, i;
//
//            size = backtrace(array, 30);
//            strings = backtrace_symbols(array, size);
//
//            for (i = 0; i < size; i++) {
//                Dl_info info;
//                if (dladdr(array[i], &info) && info.dli_sname) {
//                    char* demangled = NULL;
//                    int status = -1;
//                    if (info.dli_sname[0] == '_')
//                        demangled = abi::__cxa_demangle(info.dli_sname, NULL, 0, &status);
//                    printf("%s - %s: %s\n",
//                           strings[i], info.dli_sname,
//                           status == 0 ? demangled : info.dli_sname);
//                    free(demangled);
//                } else {
//                    printf("%s\n", strings[i]);
//                }
//            }
//            free(strings);
//        }

        void deallocate(void *ptr) {
            if (ptr == nullptr) {
                return;
            }


#ifdef FWS_POOL_RECLAIM_MEMORY
            auto find_it = mem_meta_map_.find(ptr);
            uint32_t log2Size, tempPoolIndex;
            if FWS_LIKELY(find_it == mem_meta_map_.end()) {
                uint8_t *userDataPtr = (uint8_t*)ptr;
                uint32_t *log2InfoPtr = (uint32_t*)(userDataPtr - 8);
                uint32_t *poolIndexInfoPtr = (uint32_t*)(userDataPtr - 4);
                log2Size = *log2InfoPtr;
                tempPoolIndex = *poolIndexInfoPtr;
            }
            else {
                log2Size = find_it->second.log2;
                tempPoolIndex = find_it->second.pool_index;
            }
            pool_index_stack_[log2Size].push_back(tempPoolIndex);


#endif
            if FWS_UNLIKELY(has_alloc_num_[log2Size] == 0) {
//                printStackTrace();
                throw std::runtime_error("has_alloc_num_[log2Size] == 0, log2Size: " + std::to_string(log2Size)
                + ", dealloc_cnt_[log2Size]: " + std::to_string(dealloc_cnt_[log2Size]));
            }
            dealloc_cnt_[log2Size]++;
            has_alloc_num_[log2Size]--;

#if !FWS_ENABLE_MEM_POOL
            std::free(ptr);
#endif
        }

        void aligned_deallocate(void *ptr) {
            uint8_t *userPtr = (uint8_t*)ptr;
            uint8_t **infoPtr = (uint8_t **)(userPtr - sizeof(uint8_t*));
            uint8_t *realPtr = *infoPtr;
            deallocate((void *) realPtr);
        }

        void LogAllocStats() {
            size_t totalSum = 0, peakSum = 0;
            for (size_t i = 0; i < TYPE_SIZE_NUM; ++i) {
                if (alloc_cnt_[i] > 0) {
                    totalSum += alloc_cnt_[i] * SIZE_OF_TYPE[i];
                    peakSum += peak_cnt_[i] * SIZE_OF_TYPE[i];
                    printf("ItemAllocator for %zu\tbytes buckets, alloc %" PRIu64 "\tcount,"
                          "%" PRId64 "\tbytes in total; Peak %" PRId64 "\tcount, %" PRId64 "\tbytes\n",
                           SIZE_OF_TYPE[i], alloc_cnt_[i], alloc_cnt_[i] * SIZE_OF_TYPE[i], peak_cnt_[i],
                           peak_cnt_[i] * SIZE_OF_TYPE[i]);
                }
            }
            printf("In sum, total alloc %ld bytes, peak %ld bytes\n", totalSum, peakSum);

        }

    protected:
        int64_t alloc_cnt_[TYPE_SIZE_NUM] = {0}, dealloc_cnt_[TYPE_SIZE_NUM] = {0}, peak_cnt_[TYPE_SIZE_NUM] = {0};
        size_t has_alloc_num_[TYPE_SIZE_NUM] = {0}, reserve_cap_[TYPE_SIZE_NUM] = {0};
        constexpr static size_t SIZE_OF_TYPE[TYPE_SIZE_NUM] = {
                1ULL     , 1ULL << 1, 1ULL << 2, 1ULL<< 3, 1ULL << 4, 1ULL << 5, 1ULL << 6, 1ULL << 7,
                1ULL << 8, 1ULL << 9, 1ULL << 10, 1ULL << 11, 1ULL << 12, 1ULL << 13, 1ULL << 14, 1ULL << 15,
                1ULL << 16, 1ULL << 17, 1ULL << 18, 1ULL << 19, 1ULL << 20, 1ULL << 21, 1ULL << 22, 1ULL << 23,
                1ULL << 24, 1ULL << 25, 1ULL << 26, 1ULL << 27, 1ULL << 28, 1ULL << 29, 1ULL << 30, 1ULL << 31,
                1ULL << 32, 1ULL << 33, 1ULL << 34, 1ULL << 35, 1ULL << 36, 1ULL << 37, 1ULL << 38, 1ULL << 39,
                1ULL << 40, 1ULL << 41, 1ULL << 42,
        };

        // from past run
        constexpr static size_t RESERVE_NUM[TYPE_SIZE_NUM] = {
                0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,  0,  0,  0,  0,  0,
                0,  0,  0,
        };

#ifdef FWS_POOL_RECLAIM_MEMORY
        using PoolIndexStack = BlockQueue<uint32_t, false, internal::InternalAllocator<uint32_t>>;
        PoolIndexStack pool_index_stack_[TYPE_SIZE_NUM];

        // If there are many large chunk allocs, set larger SMALL_MEM_ENTRY_THRES
        static constexpr size_t SMALL_MEM_ENTRY_THRES = (1UL << 10);
//        static constexpr size_t SMALL_MEM_ENTRY_THRES = (1UL << 12);
        struct MemMetaData {
            uint32_t log2;
            uint32_t pool_index;
        };
        // used to save the metadata of allocated memory when allocated size is
        // larger than threshold
        using MemMetaAllocator = internal::InternalAllocator<std::pair<const void*, MemMetaData>>;
        using MemMetaMap = ska::flat_hash_map<void*, MemMetaData, std::hash<void*>,
                std::equal_to<>, MemMetaAllocator>;
//    using MemMetaMap = fph::meta_fph_map<void*, MemMetaData, std::hash<void*>,
//            std::equal_to<>, MemMetaAllocator>;
//    using MemMetaMap = fph::dynamic_fph_map<void*, MemMetaData, std::hash<void*>,
//            std::equal_to<>, MemMetaAllocator>;
        MemMetaMap mem_meta_map_;

        using Uint8Allocator = internal::InternalAllocator<uint8_t>;
        static constexpr bool NEED_ZERO_INIT_FOR_MEM = false;
//        using Uint8PtrAllocator = internal::InternalAllocator<uint8_t*>;
        using MemBuffer = BlockQueue<uint8_t, NEED_ZERO_INIT_FOR_MEM, Uint8Allocator>;
        MemBuffer memory_buffers_[TYPE_SIZE_NUM];
#endif

        void InitializeFlashAllocator() {


            size_t reserveTotalBytes = 0;
            for (size_t i = 0; i < TYPE_SIZE_NUM; ++i) {

                size_t tempBlockSize = 0;
                if (SIZE_OF_TYPE[i] <= (1 << 26)) {
                    tempBlockSize = std::max(internal::ALLOC_HUGE_PAGE_SIZE * 4, SIZE_OF_TYPE[i] * 16);
                }
                else if (SIZE_OF_TYPE[i] <= (1 << 27)) {
                    tempBlockSize = std::max(internal::ALLOC_HUGE_PAGE_SIZE * 16, SIZE_OF_TYPE[i] * 4);
                }
                else {
                    tempBlockSize = std::max(internal::ALLOC_HUGE_PAGE_SIZE * 16, SIZE_OF_TYPE[i]);
                }



                memory_buffers_[i] = MemBuffer(tempBlockSize);
                if (RESERVE_NUM[i] > 0) {
                    reserveTotalBytes += SIZE_OF_TYPE[i] * RESERVE_NUM[i];
                    memory_buffers_[i].resize(SIZE_OF_TYPE[i] * RESERVE_NUM[i]);
#ifdef FWS_POOL_RECLAIM_MEMORY
                    assert(RESERVE_NUM[i] < UINT32_MAX);
                    uint32_t tempReserveNum = RESERVE_NUM[i];
                    pool_index_stack_[i].resize(RESERVE_NUM[i]);
                    for (uint32_t j = 0; j < tempReserveNum; ++j) {
                        pool_index_stack_[i][j] = (tempReserveNum - j) - 1;
                    }
#endif
                }
                reserve_cap_[i] = RESERVE_NUM[i];
                has_alloc_num_[i] = 0;
            }
            (void)reserveTotalBytes;

        }
    }; // class MemPool

    // TODO: This is not thread-safe
    class MemPoolEnv: public MemPool, public Singleton<MemPoolEnv> {
    public:
    protected:

    };

    template <typename T>
    class FlashAllocator {
    public:

        using value_type = T;

        FlashAllocator() = default;

        template<class U>
        constexpr FlashAllocator(const FlashAllocator<U> &) noexcept {}

        friend bool operator==(const FlashAllocator&, const FlashAllocator&) {
            return true;
        }

        friend bool operator!=(const FlashAllocator&, const FlashAllocator&) {
            return false;
        }

        T *allocate(std::size_t n) {
            if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
                throw std::bad_alloc();
            }
            void *p = nullptr;
            p = MemPoolEnv::instance().allocate(n, sizeof(T));
//            p = flash_alloc(n, sizeof(T));

            if (p == nullptr) {
                throw std::bad_alloc();
            }

            return static_cast<T *>(p);
        }

        void deallocate(T *p, std::size_t /*n*/) {
            MemPoolEnv::instance().deallocate(p);
        }


    };

    template <typename T, size_t alignment>
    class FlashAlignedAllocator {
    public:
        using value_type = T;

        FlashAlignedAllocator() = default;
//        FlashAlignedAllocator(size_t alignment): alignment(alignment) {}

//        template<class U, size_t a>
//        constexpr FlashAlignedAllocator(const FlashAlignedAllocator<U, a> &) noexcept {}

        T *allocate(std::size_t n) {
            if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
                throw std::bad_alloc();
            }
            void *p = nullptr;
            p = MemPoolEnv::instance().aligned_alloc(alignment, n * sizeof(T));
//            p = flash_aligned_alloc(n * sizeof(T), alignment);

            if (p == nullptr) {
                throw std::bad_alloc();
            }

            return static_cast<T *>(p);
        }

        void deallocate(T *p, std::size_t /*n*/) {
            MemPoolEnv::instance().aligned_deallocate(p);
        }

    protected:
//        size_t alignment;
    };

}
//namespace fws

