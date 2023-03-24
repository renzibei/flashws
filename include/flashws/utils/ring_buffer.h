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



    template<class T>
    class BidirectionalIterator {
    public:
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type = T;
        using pointer = value_type*;
        using reference = value_type&;

        constexpr BidirectionalIterator() noexcept: buf_(nullptr), pos_(0), mask_(0) {}

        constexpr explicit BidirectionalIterator(T* buf, std::size_t pos, std::size_t mask)
            noexcept: buf_(buf), pos_(pos), mask_(mask) {}

        reference operator*() const {return buf_[pos_];}

        pointer operator->() const {
            return buf_ + pos_;
        }

        friend constexpr bool operator== (const BidirectionalIterator<T>&a,
                const BidirectionalIterator<T>&b) noexcept {
            return a.pos_ == b.pos_;
        }

        friend constexpr bool operator!= (const BidirectionalIterator<T>&a,
                                          const BidirectionalIterator<T>&b) noexcept {
            return a.pos_ != b.pos_;
        }

        BidirectionalIterator<T> &operator++() noexcept {
            pos_ = (pos_ + 1U) & mask_;
            return *this;
        }

        BidirectionalIterator<T> &operator--() noexcept {
            pos_ = (pos_ + mask_) & mask_;
            return *this;
        }

        BidirectionalIterator<T> operator++(int) noexcept {
            auto ret = *this;
            ++(*this);
            return ret;
        }

        BidirectionalIterator<T> operator--(int) noexcept {
            auto ret = *this;
            --(*this);
            return ret;
        }


    protected:
        T *buf_;
        std::size_t pos_;
        std::size_t mask_;
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
        using iterator = BidirectionalIterator<value_type>;
        using const_iterator = BidirectionalIterator<const value_type>;
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


    };


} // namespace frb