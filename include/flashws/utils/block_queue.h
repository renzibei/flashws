#pragma once
#include <cstdint>
#include <cstddef>
#include <new>
#include <vector>
#include <stdexcept>
#include "flashws/base/basic_macros.h"
#include "flashws/base/constexpr_math.h"

namespace fws {

    // A block-queue with runtime block size setting, but should be set when
    // it is empty.
    // Won't deallocate until destroyed. Only support op in the back direction
    // Block size should be power of 2 for performance reason
    template<typename ItemType, class ItemAllocator = std::allocator<ItemType>, class ItemPtrAllocator = std::allocator<ItemType*> >
    class BlockQueue {
    private:
        static constexpr bool IsPowerOfTwo(size_t x) {
            return (x & (x - size_t(1UL))) == 0U;
        }
    public:

        constexpr static size_t DEFAULT_BLOCK_BYTES_SIZE = 1 << 21; // make block 2 MB in default

        BlockQueue(): item_size_(0), block_num_(0),
                      BLOCK_SIZE(sizeof(ItemType) >= DEFAULT_BLOCK_BYTES_SIZE ? 16 :
                                 RoundDownPow2(DEFAULT_BLOCK_BYTES_SIZE / sizeof(ItemType))),
                      max_block_num_(0), cur_blk_capacity_(0), max_capacity_(0), back_ptr_(nullptr)
//                     BLOCK_SIZE(DEFAULT_BLOCK_BYTES_SIZE <= sizeof(ItemType) ? 16 :
//                               DEFAULT_BLOCK_BYTES_SIZE / sizeof(ItemType))

                       // TODO: Can replace the restriction of power of 2 to use
                       // magic-multiplier technique
                        {}

        // block_size need to be power of 2
        BlockQueue(size_t block_size): item_size_(0), block_num_(0), BLOCK_SIZE(block_size),
                                       max_block_num_(0), cur_blk_capacity_(0),
                                       max_capacity_(0), back_ptr_(nullptr)
                                     {
            if FWS_UNLIKELY(!IsPowerOfTwo(block_size)) {
                throw std::invalid_argument("block_size need to be power of 2!");
            }
            block_ptr_vec_.resize(1 << 14); // reserve 2^14 block ptr in default
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
//            if FWS_LIKELY(pos < BLOCK_SIZE) {
//                return block_ptr_vec_[0][pos];
//            }
//            else {
//                size_t blockIndex = pos / BLOCK_SIZE;
//                size_t offset = pos - blockIndex * BLOCK_SIZE;
//                return block_ptr_vec_[blockIndex][offset];
//            }
            size_t block_index = DivPow2(pos, BLOCK_SIZE);
//            size_t block_index = pos / BLOCK_SIZE;
            size_t offset = pos - block_index * BLOCK_SIZE;
            return block_ptr_vec_[block_index][offset];
        }

        const ItemType& operator[] (size_t pos) const {
//            if FWS_LIKELY(pos < BLOCK_SIZE) {
//                return block_ptr_vec_[0][pos];
//            }
//            else {
//                size_t blockIndex = pos / BLOCK_SIZE;
//                size_t offset = pos - blockIndex * BLOCK_SIZE;
//                return block_ptr_vec_[blockIndex][offset];
//            }
            size_t block_index = DivPow2(pos, BLOCK_SIZE);
//            size_t block_index = pos / BLOCK_SIZE;
            size_t offset = pos - block_index * BLOCK_SIZE;
            return block_ptr_vec_[block_index][offset];
        }

        ItemType* GetPointer(size_t pos) {
//            if FWS_LIKELY(pos < BLOCK_SIZE) {
//                return &block_ptr_vec_[0][pos];
//            }
//            else {
//                size_t blockIndex = pos / BLOCK_SIZE;
//                size_t offset = pos - blockIndex * BLOCK_SIZE;
//                return &block_ptr_vec_[blockIndex][offset];
//            }
            size_t block_index = DivPow2(pos, BLOCK_SIZE);
//            size_t block_index = pos / BLOCK_SIZE;
            size_t offset = pos - block_index * BLOCK_SIZE;
            return &(block_ptr_vec_[block_index][offset]);
        }

        ItemType& back() {
//            return (*this)[item_size_ - 1];
            return *back_ptr_;
        }

        const ItemType& back() const {
//            return (*this)[item_size_ - 1];
            return *back_ptr_;
        }

        void pop_back() {
            --item_size_;
            --back_ptr_;
//            size_t newBlockNum = RoundUpDivide(item_size_, BLOCK_SIZE);
//            if (newBlockNum < block_num_) {
//                if (item_size_ > 0) {
//                    back_ptr_ = block_ptr_vec_[newBlockNum - 1] + BLOCK_SIZE - 1;
//                }
//                else {
//                    back_ptr_ = nullptr;
//                }
//            }
//            block_num_ = newBlockNum;
//            cur_blk_capacity_ = block_num_ * BLOCK_SIZE;

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
            *(this->add_back()) = value;
        }

        void push_back(ItemType &&value) {
            *(this->add_back()) = std::forward<ItemType>(value);
        }

        template<class... Args>
        constexpr ItemType& emplace_back(Args&&... args) {
            return *(this->add_back()) = ItemType(std::forward<Args>(args)...);
        }

        // add one item back without construct it
        ItemType* add_back() {
            ++item_size_;
            // TODO: may need to check whether increase null pointer is bad behaviour in the deployment compiler
//            ++back_ptr_;
//            size_t newBlockNum = RoundUpDivide(item_size_, BLOCK_SIZE);
//            if FWS_UNLIKELY(newBlockNum > block_num_) {
//                if FWS_UNLIKELY(newBlockNum > max_block_num_) {
//                    ItemAllocator allocator;
//                    ItemType *newBlockPtr = allocator.allocate(BLOCK_SIZE);
//                    block_ptr_vec_.push_back(newBlockPtr);
//                    max_block_num_ = newBlockNum;
//                }
//                back_ptr_ = block_ptr_vec_[block_num_];
//            }
//            block_num_ = newBlockNum;
//            size_t temp_mul = BLOCK_SIZE * block_num_;
            if FWS_UNLIKELY(item_size_ > cur_blk_capacity_) {
                cur_blk_capacity_ += BLOCK_SIZE;
//                size_t temp_mul2 = BLOCK_SIZE * max_block_num_;
                if (item_size_ > max_capacity_) {
                    max_capacity_ += BLOCK_SIZE;
                    ItemAllocator allocator;
                    ItemType *newBlockPtr = allocator.allocate(BLOCK_SIZE);
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
                ItemAllocator allocator;
//                size_t blockNumDiff = newBlockNum - block_num_;
//                ItemType *newBlockBuffer = allocator.allocate(blockNumDiff * BLOCK_SIZE);
                for (size_t i = max_block_num_; i < newBlockNum; ++i) {
                    ItemType *newBlockPtr = allocator.allocate(BLOCK_SIZE);
                    block_ptr_vec_[i] = newBlockPtr;
//                    block_ptr_vec_[i] = newBlockBuffer + BLOCK_SIZE * (i - block_num_);
                }
                max_block_num_ = newBlockNum;
                max_capacity_ = max_block_num_ * BLOCK_SIZE;
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
            ItemAllocator allocator{};
            for (size_t i = 0; i < max_block_num_; ++i) {
                std::allocator_traits<ItemAllocator>::deallocate(allocator, block_ptr_vec_[i], BLOCK_SIZE);
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
}
// namespace

