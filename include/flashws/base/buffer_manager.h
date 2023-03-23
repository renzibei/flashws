#pragma once

#include "flashws/utils/flash_alloc.h"
#include "flashws/utils/flat_hash_map.h"
#include "errno_str.h"

namespace fws {

    class BufferManager : public Singleton<BufferManager> {
    public:

        FWS_ALWAYS_INLINE void AddBufRefCount(uint8_t *buf_data_ptr) noexcept {
            auto find_it = buf_cnt_map_.find(buf_data_ptr);
            if (find_it == buf_cnt_map_.end()) {
                auto [emplace_it, ok] = buf_cnt_map_.emplace(buf_data_ptr, uint64_t(0));
                find_it = emplace_it;
                (void)ok;
            }
            ++(find_it->second);
        }

        FWS_ALWAYS_INLINE uint64_t DecBufRefCount(uint8_t *buf_data_ptr) {
            auto find_it = buf_cnt_map_.find(buf_data_ptr);
            FWS_ASSERT_M(find_it->second > 0, "Call DecBufRefCount more than"
                                              "AddBufRefCount");
            // TODO:now we do not erase data_ptr from hash map because we assume
            // that the freed data would be allocated again
            return --(find_it->second);
        }

    protected:
        ska::flat_hash_map<uint8_t*, uint64_t> buf_cnt_map_;
    };

    struct IOBuffer {
        uint8_t *data = nullptr;

        // meaningful size of data from start_pos
        ssize_t size = 0;

        // data[start_pos] is the first byte of data
        size_t start_pos = 0;
        // capacity of the buf, start from data+0
        size_t capacity = 0;

        IOBuffer(uint8_t *data, ssize_t size, size_t start_pos, size_t cap) noexcept:
                data(data), size(size), start_pos(start_pos), capacity(cap) {
            if (data != nullptr) {
                BufferManager::instance().AddBufRefCount((uint8_t*)data);
            }
        }
        IOBuffer() noexcept: data(nullptr), size(0), start_pos(0), capacity(0) {}

        IOBuffer(const IOBuffer&) = delete;
        IOBuffer& operator=(const IOBuffer&) = delete;

        IOBuffer(IOBuffer &&o) noexcept: data(std::exchange(o.data, nullptr)),
                                size(std::exchange(o.size, 0)),
                                start_pos(std::exchange(o.start_pos, 0)),
                                capacity(std::exchange(o.capacity, 0)) {}

        IOBuffer& operator=(IOBuffer &&o) noexcept {
            if FWS_UNLIKELY(&o == this) {
                return *this;
            }
            std::swap(data, o.data);
            std::swap(size, o.size);
            std::swap(start_pos, o.start_pos);
            std::swap(capacity, o.capacity);
            return *this;
        }

        ~IOBuffer() {
            if (data) {
                uint64_t ref_count = BufferManager::instance().DecBufRefCount(data);
                if (ref_count == 0) {
                    MemPoolEnv::instance().deallocate(data);
                }
                data = nullptr;
            }
        }

    };



    // TODO: maybe can set the capacity to the true capacity in underlying
    // data is null if fail
    IOBuffer RequestBuf(size_t size) {
        void* p = MemPoolEnv::instance().allocate(size);
//        BufferManager::instance().AddBufRefCount((uint8_t*)p);
        IOBuffer ret((uint8_t*)p, 0, 0, size);
        return ret;
    }


    void ReclaimBuf(IOBuffer& buf) {
        uint64_t ref_count = BufferManager::instance().DecBufRefCount(buf.data);
        if (ref_count == 0) {
            MemPoolEnv::instance().deallocate(buf.data);
        }
        buf.data = nullptr;
    }

} // namespace fws