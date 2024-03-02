#pragma once
#include <cstdint>
#include <cstddef>
#include <new>
#include <vector>
#include <stdexcept>
#include <utility>
#include "flashws/base/basic_macros.h"
#include "flashws/base/constexpr_math.h"

namespace fws {

    // A block-queue with runtime block size setting, but should be set when
    // it is empty.
    // Won't deallocate until destroyed. Only support op in the back direction
    // Block size should be power of 2 for performance reason
    template<typename ItemType, bool need_default_construct, class ItemAllocator = std::allocator<ItemType> >
    class BlockQueue: protected ItemAllocator {
    private:
        static constexpr bool IsPowerOfTwo(size_t x) {
            return (x & (x - size_t(1UL))) == 0U;
        }

        constexpr static size_t DEFAULT_BLOCK_BYTES_SIZE = 1 << 21; // make block 2 MB in default
        static constexpr size_t DEFAULT_BLOCK_SIZE = sizeof(ItemType) >= DEFAULT_BLOCK_BYTES_SIZE ? 16 :
                                                     RoundDownPow2(DEFAULT_BLOCK_BYTES_SIZE / sizeof(ItemType));
        using ItemAllocTraits = std::allocator_traits<ItemAllocator>;
        using ItemPtrAllocator = typename std::allocator_traits<ItemAllocator>::template rebind_alloc<ItemType*>;
    public:



        BlockQueue(): item_size_(0), block_num_(0),
                      BLOCK_SIZE(DEFAULT_BLOCK_SIZE),
                      max_block_num_(0), cur_blk_capacity_(0), max_capacity_(0),
                      block_ptr_vec_{}, back_ptr_(nullptr)
//                     BLOCK_SIZE(DEFAULT_BLOCK_BYTES_SIZE <= sizeof(ItemType) ? 16 :
//                               DEFAULT_BLOCK_BYTES_SIZE / sizeof(ItemType))

                       // TODO: Can replace the restriction of power of 2 to use
                       // magic-multiplier technique
                        {}

        // block_size need to be power of 2
        BlockQueue(size_t block_size): item_size_(0), block_num_(0), BLOCK_SIZE(block_size),
                                       max_block_num_(0), cur_blk_capacity_(0),
                                       max_capacity_(0), block_ptr_vec_{},
                                       back_ptr_(nullptr)
                                     {
            if FWS_UNLIKELY(!IsPowerOfTwo(block_size)) {
                throw std::invalid_argument("block_size need to be power of 2!");
            }
        }

        BlockQueue(const BlockQueue&) = delete;
        BlockQueue& operator=(const BlockQueue&) = delete;

        BlockQueue(BlockQueue&& o) noexcept:
            item_size_(std::exchange(o.item_size_, 0)),
            block_num_(std::exchange(o.block_num_, 0)),
            BLOCK_SIZE(std::exchange(o.BLOCK_SIZE, DEFAULT_BLOCK_SIZE)),
            max_block_num_(std::exchange(o.max_block_num_, 0)),
            cur_blk_capacity_(std::exchange(o.cur_blk_capacity_, 0)),
            max_capacity_(std::exchange(o.max_capacity_, 0)),
            block_ptr_vec_(std::exchange(o.block_ptr_vec_, {})),
            back_ptr_(std::exchange(o.back_ptr_, nullptr))
        {}

        BlockQueue& operator=(BlockQueue&& o) noexcept {
            std::swap(item_size_, o.item_size_);
            std::swap(block_num_, o.block_num_);
            std::swap(BLOCK_SIZE, o.BLOCK_SIZE);
            std::swap(max_block_num_, o.max_block_num_);
            std::swap(cur_blk_capacity_, o.cur_blk_capacity_);
            std::swap(max_capacity_, o.max_capacity_);
            std::swap(block_ptr_vec_, o.block_ptr_vec_);
            std::swap(back_ptr_, o.back_ptr_);
            return *this;
        }

        size_t size() const {
            return item_size_;
        }

        bool empty() const {
            return item_size_ == 0;
        }

        size_t capacity() const {
            return cur_blk_capacity_;
        }

        // TODO: may use branch prediction to accelerate when pos < BLOCK_SIZE
        ItemType& operator[] (size_t pos) {
            size_t block_index = DivPow2(pos, BLOCK_SIZE);
            size_t offset = pos - block_index * BLOCK_SIZE;
            return block_ptr_vec_[block_index][offset];
        }

        const ItemType& operator[] (size_t pos) const {
            size_t block_index = DivPow2(pos, BLOCK_SIZE);
            size_t offset = pos - block_index * BLOCK_SIZE;
            return block_ptr_vec_[block_index][offset];
        }

        ItemType* GetPointer(size_t pos) {
            size_t block_index = DivPow2(pos, BLOCK_SIZE);
            size_t offset = pos - block_index * BLOCK_SIZE;
            return &(block_ptr_vec_[block_index][offset]);
        }

        ItemType& back() {
            return *back_ptr_;
        }

        const ItemType& back() const {
            return *back_ptr_;
        }

        void pop_back() {
            std::destroy_at(back_ptr_);
            --item_size_;
            --back_ptr_;

            if FWS_UNLIKELY(item_size_ + BLOCK_SIZE <= cur_blk_capacity_) {
                --block_num_;
                if FWS_LIKELY(item_size_ > 0) {
                    back_ptr_ = block_ptr_vec_[block_num_ - 1] + BLOCK_SIZE - 1;
                }
                else {
                    back_ptr_ = nullptr;
                }
                cur_blk_capacity_ -= BLOCK_SIZE;
            }
        }

        void push_back(const ItemType &value) {
            ItemType *new_ptr = this->add_back();
            ItemAllocTraits::construct(static_cast<ItemAllocator&>(*this), new_ptr, value);
        }

        void push_back(ItemType &&value) {
            ItemType *new_ptr = this->add_back();
            ItemAllocTraits::construct(static_cast<ItemAllocator&>(*this), new_ptr, std::forward<ItemType>(value));
        }

        template<class... Args>
        constexpr ItemType& emplace_back(Args&&... args) {
            ItemType *new_ptr = this->add_back();
            ItemAllocTraits::construct(static_cast<ItemAllocator&>(*this), new_ptr, std::forward<Args>(args)...);
            return *new_ptr;
        }

        // add one item back without construct it
        ItemType* add_back() {
            ++item_size_;
            // TODO: may need to check whether increase null pointer is bad behaviour in the deployment compiler
            if FWS_UNLIKELY(item_size_ > cur_blk_capacity_) {
                cur_blk_capacity_ += BLOCK_SIZE;
//                size_t temp_mul2 = BLOCK_SIZE * max_block_num_;
                if (item_size_ > max_capacity_) {
                    max_capacity_ += BLOCK_SIZE;
                    ItemType *newBlockPtr = static_cast<ItemAllocator*>(this)->allocate(BLOCK_SIZE);
                    block_ptr_vec_.push_back(newBlockPtr);
                    ++max_block_num_;
                }
                back_ptr_ = block_ptr_vec_[block_num_++];
            }
            else {
                ++back_ptr_;
            }
            return back_ptr_;
        }

        void resize(size_t count) {
            size_t newBlockNum = RoundUpDivide(count, BLOCK_SIZE);
            if (newBlockNum > max_block_num_) {
                block_ptr_vec_.resize(newBlockNum);
                for (size_t i = max_block_num_; i < newBlockNum; ++i) {
                    ItemType *newBlockPtr = static_cast<ItemAllocator*>(this)->allocate(BLOCK_SIZE);
                    block_ptr_vec_[i] = newBlockPtr;
                }
                max_block_num_ = newBlockNum;
                max_capacity_ = max_block_num_ * BLOCK_SIZE;
            }
            if (count > item_size_) {
                if constexpr (need_default_construct) {
                    for (size_t i = item_size_; i < count; ++i) {
                        ItemAllocTraits::construct(static_cast<ItemAllocator &>(*this),
                                                   &(*this)[i]);
                    }
                }
            }
            else if (count < item_size_) {
                if constexpr (std::is_class_v<ItemType>) {
                    for (size_t i = count; i < item_size_; ++i) {
                        ItemAllocTraits::destroy(static_cast<ItemAllocator&>(*this), &(*this)[i]);
                    }
                }
            }
            item_size_ = count;
            block_num_ = newBlockNum;
            cur_blk_capacity_ = block_num_ * BLOCK_SIZE;
            if (count == 0) {
                back_ptr_ = nullptr;
            }
            else {
                back_ptr_ = &((*this)[count - 1]);
            }
        }

        ~BlockQueue() {
            if constexpr (std::is_class_v<ItemType>) {
                for (size_t i = 0; i < item_size_; ++i) {
                    ItemAllocTraits::destroy(static_cast<ItemAllocator&>(*this), &(*this)[i]);
                }
            }

            for (size_t i = 0; i < max_block_num_; ++i) {
                ItemAllocTraits::deallocate(static_cast<ItemAllocator&>(*this), block_ptr_vec_[i], BLOCK_SIZE);
            }
        }

    protected:
        size_t item_size_, block_num_;
        size_t BLOCK_SIZE;
        size_t max_block_num_; // the max block_num_ in history
        size_t cur_blk_capacity_, max_capacity_;
        std::vector<ItemType*, ItemPtrAllocator> block_ptr_vec_;
        ItemType *back_ptr_;


        constexpr static inline size_t RoundUpDivide(size_t x, size_t y) {
            return (x + y - 1) / y;
        }
    };

//    static_assert(sizeof(BlockQueue<uint8_t>) <= 80);
}
// namespace

