#pragma once

#include <utility>
#include <cstdint>
#include <cstddef>
#include <limits>
#include <memory>
#include <iterator>
#include <algorithm>

namespace frb {


#ifndef FRB_HAVE_BUILTIN
#ifdef __has_builtin
#define FRB_HAVE_BUILTIN(x) __has_builtin(x)
#else
#define FRB_HAVE_BUILTIN(x) 0
#endif
#endif

#ifndef FRB_HAS_BUILTIN_OR_GCC_CLANG
#if defined(__GNUC__) || defined(__clang__)
#   define FRB_HAS_BUILTIN_OR_GCC_CLANG(x) 1
#else
#   define FRB_HAS_BUILTIN_OR_GCC_CLANG(x) FRB_HAVE_BUILTIN(x)
#endif
#endif


#ifndef FRB_LIKELY
#   if FRB_HAS_BUILTIN_OR_GCC_CLANG(__builtin_expect)
#       define FRB_LIKELY(x) (__builtin_expect((x), 1))
#   else
#       define FRB_LIKELY(x) (x)
#   endif
#endif

#ifndef FRB_UNLIKELY
#   if FRB_HAS_BUILTIN_OR_GCC_CLANG(__builtin_expect)
#       define FRB_UNLIKELY(x) (__builtin_expect((x), 0))
#   else
#       define FRB_UNLIKELY(x) (x)
#   endif
#endif

#ifndef FRB_ALWAYS_INLINE
#   ifdef _MSC_VER
#       define FRB_ALWAYS_INLINE __forceinline
#   else
#       define FRB_ALWAYS_INLINE inline __attribute__((__always_inline__))
#   endif
#endif

#ifndef FRB_NO_INLINE
#ifdef _MSC_VER
#define FRB_NO_INLINE __declspec(noinline)
#else
#define FRB_NO_INLINE __attribute__((__noinline__))
#endif
#endif

#ifndef FRB_RESTRICT
#ifdef _MSC_VER
#   define FRB_RESTRICT
#else
#   define FRB_RESTRICT __restrict
#endif
#endif

#ifndef FRB_FUNC_RESTRICT
#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_COMPILER)
#   define FRB_FUNC_RESTRICT __restrict
#else
#   define FRB_FUNC_RESTRICT
#endif
#endif

    namespace detail {
        constexpr uint64_t RoundUpLog2(uint64_t x) {
            if (x <= 1UL) {
                return 0;
            }
            return 64 - __builtin_clzll(x - 1UL);
        }

        static_assert(RoundUpLog2(1) == 0);
        static_assert(RoundUpLog2(2) == 1);
        static_assert(RoundUpLog2(16) == 4);
        static_assert(RoundUpLog2(30) == 5);
    } // namespace detail

    template<class T, class Allocator>
    class RingBuffer;

    template<class T>
    class SemiRandomIterator {
    public:
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::random_access_iterator_tag;
        using value_type = T;
        using pointer = value_type*;
        using reference = value_type&;

        constexpr SemiRandomIterator() noexcept: buf_(nullptr), pos_(0), mask_(0) {}

        constexpr explicit SemiRandomIterator(T* buf, std::size_t pos, std::size_t mask) noexcept:
            buf_(buf), pos_(pos), mask_(mask) {}

        operator SemiRandomIterator<const T>() const {
            return SemiRandomIterator<const T>(buf_, pos_, mask_);
        }

        reference operator*() const {return buf_[pos_];}

        pointer operator->() const {
            return buf_ + pos_;
        }

        friend constexpr bool operator== (const SemiRandomIterator<T>&a,
                                          const SemiRandomIterator<T>&b) noexcept {
            return a.pos_ == b.pos_;
        }

        friend constexpr bool operator!= (const SemiRandomIterator<T>&a,
                                          const SemiRandomIterator<T>&b) noexcept {
            return a.pos_ != b.pos_;
        }

        SemiRandomIterator<T> &operator++() noexcept {
            pos_ = (pos_ + 1U) & mask_;
            return *this;
        }

        SemiRandomIterator<T> &operator--() noexcept {
            pos_ = (pos_ + mask_) & mask_;
            return *this;
        }

        SemiRandomIterator<T> operator++(int) noexcept {
            auto ret = *this;
            ++(*this);
            return ret;
        }

        SemiRandomIterator<T> operator--(int) noexcept {
            auto ret = *this;
            --(*this);
            return ret;
        }

        SemiRandomIterator<T> &operator+=(difference_type n) noexcept {
            pos_ = (pos_ + n) & mask_;
            return *this;
        }

        SemiRandomIterator<T> &operator-=(difference_type n) noexcept {
            pos_ = (pos_ + mask_ + 1U - n) & mask_;
            return *this;
        }

        SemiRandomIterator<T> operator+(difference_type n) const noexcept {
            auto ret = *this;
            ret += n;
            return ret;
        }

        SemiRandomIterator<T> operator-(difference_type n) const noexcept {
            auto ret = *this;
            ret -= n;
            return ret;
        }

        // We assume that the difference is always positive
        difference_type operator-(const SemiRandomIterator<T>& other) const noexcept {
            return (pos_  + mask_ + 1U - other.pos_ ) & mask_;
        }

        reference operator[](difference_type n) const noexcept {
            return buf_[(pos_ + n) & mask_];
        }


    protected:
        T *buf_;
        std::size_t pos_;
        std::size_t mask_;

        template<class U, class A>
        friend class RingBuffer;
    }; // class ForwardIterator


    template<class T, class Allocator = std::allocator<T>>
    class RingBuffer : protected Allocator {
    protected:
        using AllocTraits = std::allocator_traits<Allocator>;
        static constexpr std::size_t MIN_CAP = 4;
        static constexpr std::size_t INIT_MASK = 0;
//        static constexpr std::size_t INIT_MASK = std::numeric_limits<std::size_t>::max();
//        static_assert(INIT_MASK + 1U == 0U);
    public:
        using value_type = T;
        using allocator_type = Allocator;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = value_type&;
        using const_reference = const value_type&;
        using pointer = typename AllocTraits ::pointer;
        using const_pointer = typename AllocTraits::const_pointer;
        using iterator = SemiRandomIterator<value_type>;
        using const_iterator = SemiRandomIterator<const value_type>;
        using reverse_iterator = std::reverse_iterator<iterator>;
        using const_reverse_iterator = std::reverse_iterator<const_iterator>;

        constexpr RingBuffer() noexcept: buf_(nullptr), mask_(INIT_MASK), head_(0), tail_(0) {}

        constexpr RingBuffer(const Allocator& alloc): Allocator(alloc),
                                                      buf_(nullptr), mask_(INIT_MASK), head_(0), tail_(0){}

        explicit RingBuffer(size_t count, const T& value, const Allocator& alloc = Allocator())
                : Allocator(alloc), buf_(nullptr), mask_(INIT_MASK),
                  head_(0), tail_(0) {
            size_type cap = std::max(size_type(1U) << detail::RoundUpLog2(count), MIN_CAP);
            mask_ = cap - 1U;
            AllocTraits::allocate(*this, cap);
            for (size_type i = 0; i < count; ++i) {
                AllocTraits::construct(*this, buf_ + i, value);
            }
            tail_ = count;
        }

        explicit RingBuffer(size_type count, const Allocator& alloc = Allocator())
                : RingBuffer(count, T(), alloc) {}

        RingBuffer(const RingBuffer& o, const Allocator& alloc)
                : RingBuffer(alloc) {
            if (!o.empty()) {
                size_type new_cap = size_type(1U) << detail::RoundUpLog2(o.size());
                SetNewCap(new_cap);
                for (auto it = o.begin(); it != o.end(); ++it) {
                    push_back(*it);
                }
            }
        }

        RingBuffer(const RingBuffer& o): RingBuffer(o, AllocTraits::select_on_container_copy_construction(o)) {}

        RingBuffer(RingBuffer&& o, const Allocator& alloc) noexcept
                : Allocator(alloc), buf_(std::exchange(o.buf_, nullptr)),
//            size_(std::exchange(o.size_, 0)),
                  mask_(std::exchange(o.mask_, INIT_MASK)),
                  head_(std::exchange(o.head_, 0)),
                  tail_(std::exchange(o.tail_, 0)) {}


        RingBuffer(RingBuffer&& o) noexcept
                : Allocator(std::move(o)),
                  buf_(std::exchange(o.buf_, nullptr)),
//                  size_(std::exchange(o.size_, 0)),
                  mask_(std::exchange(o.mask_, INIT_MASK)),
                  head_(std::exchange(o.head_, 0)),
                  tail_(std::exchange(o.tail_, 0)) {}

        template< class InputIt >
        RingBuffer(InputIt first, InputIt last, const Allocator& alloc = Allocator())
                : RingBuffer(alloc) {
            for (auto it = first; it != last; ++it) {
                emplace_back(*this);
            }
        }

        RingBuffer( std::initializer_list<T> init, const Allocator& alloc = Allocator())
                : RingBuffer(init.begin(), init.end(), alloc) {}

        RingBuffer& operator=(const RingBuffer& o) {
            auto tmp(o);
            this->swap(tmp);
            return *this;
        }

        RingBuffer& operator=(RingBuffer&& o) noexcept {
            this->swap(o);
            return *this;
        }

        ~RingBuffer() {
            if (buf_ != nullptr) {
                for (auto it = begin(); it != end(); ++it) {
                    AllocTraits::destroy(*this, std::addressof(*it));
                }
                AllocTraits::deallocate(*this, buf_, mask_ + 1U);
                buf_ = nullptr;
            }
        }

        template< class... Args >
        reference emplace_back( Args&&... args ) {
            // we keep one empty slot
            size_type cur_mask = mask_;
            size_type cur_cap = cur_mask + 1U;
            size_type cur_size = (tail_ - head_ + cur_cap) & cur_mask;
            if FRB_UNLIKELY(cur_size >= cur_mask) {
                cur_cap = std::max(cur_cap * 2U, MIN_CAP);
                SetNewCap(cur_cap);
                cur_mask = cur_cap - 1U;
            }
            size_type tail = tail_;
            auto* buf = buf_;
            AllocTraits::construct(*this, buf + tail, std::forward<Args>(args)...);
            auto new_tail = (tail + 1U) & cur_mask;
            tail_ = new_tail;
//            ++size_;
            return buf[new_tail];
        }

        void push_back( const T& value ) {
            emplace_back(value);
        }

        void push_back( T&& value ) {
            emplace_back(std::forward<T>(value));
        }

        template< class... Args >
        reference emplace_front( Args&&... args ) {
            // we keep one empty slot
            size_type cur_mask = mask_;
            size_type cur_cap = cur_mask + 1U;
            size_type cur_size = (tail_ - head_ + cur_cap) & cur_mask;
            if FRB_UNLIKELY(cur_size >= cur_mask) {
                cur_cap = std::max(cur_cap * 2U, MIN_CAP);
                SetNewCap(cur_cap);
                cur_mask = cur_cap - 1U;
            }
            auto new_head = (head_ + cur_mask) & cur_mask;
            auto* buf = buf_;
            AllocTraits::construct(*this, buf + new_head, std::forward<Args>(args)...);
            head_ = new_head;
//            ++size_;
            return buf[new_head];
        }

        void push_front( const T& value ) {
            emplace_front(value);
        }

        void push_front( T&& value ) {
            emplace_front(std::forward<T>(value));
        }

        reference front() {
            return buf_[head_];
        }

        const_reference front() const {
            return buf_[head_];
        }

        reference back() {
            auto mask = mask_;
            return buf_[(tail_ + mask) & mask];
        }

        const_reference back() const {
            auto mask = mask_;
            return buf_[(tail_ + mask) & mask];
        }

        T get_pop_front() {
            auto cur_head = head_;
            auto *head_addr = buf_ + cur_head;
            T ret(std::move(*head_addr));
            AllocTraits::destroy(*this, head_addr);
            head_ = (cur_head + 1U) & mask_;
//            --size_;
            return ret;
        }

        void pop_front() {
            auto cur_head = head_;
            AllocTraits::destroy(*this, buf_ + cur_head);
            head_ = (cur_head + 1U) & mask_;
//            --size_;
        }

        T get_pop_back() {
            auto mask = mask_;
            auto new_tail = (tail_ + mask) & mask;
            auto *tail_addr = buf_ + new_tail;
            T ret(std::move(*tail_addr));
            AllocTraits::destroy(*this, tail_addr);
            tail_ = new_tail;
//            --size_;
            return ret;
        }

        void pop_back() {
            auto mask = mask_;
            auto new_tail = (tail_ + mask) & mask;
            AllocTraits::destroy(*this, buf_ + new_tail);
            tail_ = new_tail;
//            --size_;
        }

        template<class... Args>
        iterator emplace(const_iterator pos, Args&&... args) {

            size_type cur_mask = mask_;
            size_type cur_cap = cur_mask + 1U;
            size_type cur_size = (tail_ - head_ + cur_cap) & cur_mask;
            auto idx = pos.pos_; // Assuming pos_ gives the actual index in the buffer
            if FRB_UNLIKELY(cur_size >= cur_mask) {
                size_t to_head_dis = (idx + cur_cap - head_) & cur_mask;
                cur_cap = std::max(cur_cap * 2U, MIN_CAP);
                SetNewCap(cur_cap);
                cur_mask = cur_cap - 1U;
                idx = (head_ + to_head_dis) & cur_mask;
            }


            auto mask = cur_mask;
            auto head = head_;
            auto tail = tail_;
            size_type distance_to_head = (idx + mask + 1 - head) & mask;
            size_type distance_to_tail = (tail + mask + 1 - idx) & mask;
            size_type insert_pos = idx;
            if (distance_to_head <= distance_to_tail + 1) {
                // Move elements from head to idx toward head
                size_t new_head = (head + mask) & mask; // head - 1
                for (size_type i = new_head;;) {
                    size_type next_i = (i + 1) & mask; // similar to ++i
                    if (next_i == idx) {
                        break;
                    }
                    buf_[i] = std::move(buf_[next_i]);
                    i = next_i;
                }
                insert_pos = (idx + mask) & mask; // idx - 1
                AllocTraits::construct(*this, buf_ + insert_pos, std::forward<Args>(args)...);
                head_ = head = new_head;
            } else {
                // Move elements from idx to tail toward tail
                for (size_type i = tail; i != idx;) {
                    size_type next_i = (i + mask) & mask; // similar to --i
                    buf_[i] = std::move(buf_[next_i]);
                    i = next_i;
                }
                AllocTraits::construct(*this, buf_ + insert_pos, std::forward<Args>(args)...);
                tail_ = tail = (tail + 1) & mask;
            }
            return iterator(buf_, insert_pos, mask);
        }

        iterator erase(iterator pos) {

            auto idx = pos.pos_; // Assuming pos_ gives the actual index in the buffer
            auto mask = mask_;
            auto head = head_;
            auto tail = tail_;
            size_type distance_to_head = (idx  + mask + 1 - head) & mask;
            size_type distance_to_tail = (tail + mask - idx) & mask;

            if (distance_to_head < distance_to_tail) {
                // Move elements from head to idx toward idx
                for (size_type i = idx; i != head;) {
                    size_type next_i = (i + mask) & mask; // similar to --i
                    buf_[i] = std::move(buf_[next_i]);
                    i = next_i;
                }
                AllocTraits::destroy(*this, buf_ + head);
                head = (head + 1) & mask;
                idx = (idx + 1) & mask;
            } else {
                // Move elements from idx to tail toward idx
                auto back_pos = (tail + mask) & mask;
                for (size_type i = idx; i != back_pos;) {
                    size_type next_i = (i + 1) & mask; // similar to ++i
                    buf_[i] = std::move(buf_[next_i]);
                    i = next_i;
                }
                tail = (tail + mask) & mask; // This decrements tail
                AllocTraits::destroy(*this, buf_ + back_pos);
            }
            head_ = head;
            tail_ = tail;
            return iterator(buf_, idx, mask);

        }


        iterator begin() noexcept {
            return iterator(buf_, head_, mask_);
        }

        const_iterator begin() const noexcept {
            return const_iterator(buf_, head_, mask_);
        }

        iterator end() noexcept {
            return iterator(buf_, tail_, mask_);
        }

        const_iterator end() const noexcept {
            return const_iterator(buf_, tail_, mask_);
        }

        reverse_iterator rbegin() noexcept {
            return std::make_reverse_iterator(end());
        }

        const_reverse_iterator rbegin() const noexcept {
            return std::make_reverse_iterator(end());
        }

        reverse_iterator rend() noexcept {
            return std::make_reverse_iterator(begin());
        }

        const_reverse_iterator rend() const noexcept {
            return std::make_reverse_iterator(begin());
        }

        FRB_ALWAYS_INLINE bool empty() const noexcept {
//            return size_ == 0U;
            return tail_ == head_;
        }

        FRB_ALWAYS_INLINE size_type size() const noexcept {
//            return size_;
            return (tail_ - head_ + mask_ + 1U) & mask_;
        }

        size_type capacity() const noexcept {
            return mask_ + 1U;
        }

        void reserve( size_type new_cap ) {
            new_cap = std::max(size_type(1UL) << detail::RoundUpLog2(new_cap), MIN_CAP);
            if (new_cap != mask_ + 1U) {
                SetNewCap(new_cap);
            }
        }

        void swap ( RingBuffer& o ) noexcept {
            std::swap(buf_, o.buf_);
//            std::swap(size_, o.size_);
            std::swap(mask_, o.mask_);
            std::swap(head_, o.head_);
            std::swap(tail_, o.tail_);
        }

    protected:

        T *buf_;
//        size_type size_;
        size_type mask_;
        size_type head_;
        size_type tail_;

        // new_cap should be power of 2
        FRB_NO_INLINE void SetNewCap(size_type new_cap) {
            T *new_buf = AllocTraits::allocate(*this, new_cap);
            size_t i = 0;
            if (buf_ != nullptr) {
                for (auto it = begin(); it != end(); ++it, ++i) {
                    if constexpr (std::is_move_constructible_v<T>) {
                        AllocTraits::construct(*this, new_buf + i, std::move(*it));
                    }
                    else {
                        AllocTraits::construct(*this, new_buf + i, *it);
                    }
                    AllocTraits::destroy(*this, std::addressof(*it));
                }
                AllocTraits::deallocate(*this, buf_, mask_ + 1U);
            }
            head_ = 0;
            tail_ = i;
            buf_ = new_buf;
            mask_ = new_cap - 1U;
        }


    }; // class RingBuffer

    template<class Allocator = std::allocator<uint8_t>>
    class ByteRingBuffer : public RingBuffer<uint8_t, Allocator> {
        using Base = RingBuffer<uint8_t, Allocator>;
    public:
        using size_type = typename Base::size_type;

        void insert_back(const void* FRB_RESTRICT data, size_t size) {
            size_type cur_mask = this->mask_;
            size_type cur_cap = cur_mask + 1U;
            size_type cur_size = this->size();
            size_type target_size = cur_size + size;
            if FRB_UNLIKELY(target_size >= cur_mask) {
                cur_cap = size_type(1U) << detail::RoundUpLog2(target_size + 1U);
                cur_cap = std::max(cur_cap, Base::MIN_CAP);
                cur_mask = cur_cap - 1U;

                this->SetNewCap(cur_cap);
            }
            size_type tail = this->tail_;
            auto* FRB_RESTRICT buf = this->buf_;
            auto* FRB_RESTRICT end_addr = buf + cur_cap;
            auto* FRB_RESTRICT tail_addr = buf + tail;
            auto* FRB_RESTRICT theory_end = tail_addr + size;
            if (theory_end <= end_addr) {
                memcpy(tail_addr, data, size);
            }
            else {
                size_type first_size = end_addr - tail_addr;
                memcpy(tail_addr, data, first_size);
                memcpy(buf, (const uint8_t*)data + first_size, size - first_size);
            }
            auto new_tail = (tail + size) & cur_mask;
            this->tail_ = new_tail;
        }

        void read_pop_front(void* FRB_RESTRICT data, size_t size) FRB_FUNC_RESTRICT {
            auto cur_head = this->head_;
            auto *FRB_RESTRICT  head_addr = this->buf_ + cur_head;
            auto *FRB_RESTRICT  end_addr = this->buf_ + this->mask_ + 1U;
            auto *FRB_RESTRICT  theory_end = head_addr + size;

            if (theory_end <= end_addr) {
                memcpy(data, head_addr, size);
            }
            else {
                auto first_size = end_addr - head_addr;
                memcpy(data, head_addr, first_size);
                memcpy((uint8_t* FRB_RESTRICT)data + first_size, this->buf_, size - first_size);
            }
            this->head_ = (cur_head + size) & this->mask_;
        }
    protected:

    };


} // namespace frb