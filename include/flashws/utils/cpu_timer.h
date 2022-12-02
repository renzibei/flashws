#pragma once

#include <time.h>
#include <chrono>
#include <limits>
#include <cstdint>
#include <type_traits>
#include <cstring>
#include <algorithm>

#if defined(__x86_64__) || defined(__x86_64) || defined(_M_AMD64) || \
    defined(_M_X64)
#define CPU_T_ARCH_X86_64
#elif defined(__i386) || defined(_M_IX86)
#define CPU_T_ARCH_X86_32
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#define CPU_T_ARCH_AARCH64
#elif defined(__arm__) || defined(__ARMEL__) || defined(_M_ARM)
#define CPU_T_ARCH_ARM
#elif defined(__powerpc64__) || defined(__PPC64__) || defined(__powerpc__) || \
    defined(__ppc__) || defined(__PPC__)
#define CPU_T_ARCH_PPC
#else
#endif

#ifdef _MSC_VER
#define CPU_T_MSC_VER _MSC_VER
#endif

#ifdef __GNUC__
#define CPU_T_GCC
#endif

#ifdef __clang__
#define CPU_T_CLANG
#endif

#ifdef CPU_T_MSC_VER
#include <intrin.h>
#pragma intrinsic(_ReadWriteBarrier)
#define CPU_T_COMPILER_FENCE _ReadWriteBarrier()
#elif  defined(CPU_T_GCC)
#define CPU_T_COMPILER_FENCE asm volatile("":::"memory")
#else
#define CPU_T_COMPILER_FENCE
#endif


#ifndef CPU_T_ALWAYS_INLINE
#   ifdef CPU_T_MSC_VER
#       define CPU_T_ALWAYS_INLINE __forceinline
#   else
#       define CPU_T_ALWAYS_INLINE inline __attribute__((__always_inline__))
#   endif
#endif

#if !defined(CPU_T_GCC) && !defined(CPU_T_CLANG)
#include <atomic>
#endif

namespace cpu_t {




    // from https://github.com/google/benchmark/blob/cd525ae85d4a46ecb2e3bdbdd1df101e48c5195e/include/benchmark/benchmark_api.h#L194
#if defined(CPU_T_GCC) || defined(CPU_T_CLANG)
    template <class Tp>
    CPU_T_ALWAYS_INLINE void DoNotOptimize(Tp&& value) {
        asm volatile("" : "+r" (value));
    }
#else
    template <class Tp>
    CPU_T_ALWAYS_INLINE void DoNotOptimize(const Tp &value) {
        // MSVC does not support inline assembly anymore (and never supported GCC's
        // RTL constraints). Self-assignment with #pragma optimize("off") might be
        // expected to prevent elision, but it does not with MSVC 2015. Type-punning
        // with volatile pointers generates inefficient code on MSVC 2017.
        static std::atomic<Tp> dummy(Tp{});
        dummy.store(value, std::memory_order_relaxed);
    }
#endif

    CPU_T_ALWAYS_INLINE uint64_t Now64() {
        uint64_t t;
#ifdef CPU_T_ARCH_PPC
        asm volatile("mfspr %0, %1" : "=r"(t) : "i"(268));
//#elif defined(CPU_T_ARCH_AARCH64)
//        asm volatile("mrs %0, cntvct_el0" : "=r"(t));
#elif defined(CPU_T_ARCH_X86_64) && defined(CPU_T_MSC_VER)
        CPU_T_COMPILER_FENCE;
        unsigned aux;
        t = __rdtscp(&aux);
        CPU_T_COMPILER_FENCE;
#elif defined(CPU_T_ARCH_X86_64) && (defined(CPU_T_CLANG) || defined(CPU_T_GCC))
        // Use inline asm because __rdtscp generates code to store TSC_AUX (ecx).
        asm volatile(
                "rdtscp\n\t"
                "shl $32, %%rdx\n\t"
                "or %%rdx, %0"
                : "=a"(t)
                :
            // "memory" avoids reordering. rcx = TSC_AUX. rdx = TSC >> 32.
            // "cc" = flags modified by SHL.
                : "rcx", "rdx", "memory", "cc");
#else
        CPU_T_COMPILER_FENCE;
//        timespec ts;
//        clock_gettime(CLOCK_REALTIME, &ts);
//        t = ts.tv_sec * 1000000000LL + ts.tv_nsec;
        auto tp = std::chrono::high_resolution_clock::now();
        t = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch()).count();
        CPU_T_COMPILER_FENCE;
#endif
        return t;
    }

    // from google absl and highwayhash
    // https://github.com/abseil/abseil-cpp/blob/ca80034f59f43eddb6c4c72314572c0e212bf98f/absl/random/internal/nanobenchmark.cc#L215
    CPU_T_ALWAYS_INLINE uint64_t Start64() {
        uint64_t t;
#if defined(CPU_T_ARCH_PPC)
        asm volatile("mfspr %0, %1" : "=r"(t) : "i"(268));
//#elif defined(CPU_T_ARCH_AARCH64)
//        asm volatile("mrs %0, cntvct_el0" : "=r"(t));
#elif defined(CPU_T_ARCH_X86_64) && defined(CPU_T_MSC_VER)
        CPU_T_COMPILER_FENCE;
        _mm_lfence();
        CPU_T_COMPILER_FENCE;
        t = __rdtsc();
        CPU_T_COMPILER_FENCE;
        _mm_lfence();
        CPU_T_COMPILER_FENCE;
#elif defined(CPU_T_ARCH_X86_64) && (defined(CPU_T_CLANG) || defined(CPU_T_GCC))
        asm volatile(
                "lfence\n\t"
                "rdtsc\n\t"
                "shl $32, %%rdx\n\t"
                "or %%rdx, %0\n\t"
                "lfence"
                : "=a"(t)
                :
            // "memory" avoids reordering. rdx = TSC >> 32.
            // "cc" = flags modified by SHL.
                : "rdx", "memory", "cc");
#else
        CPU_T_COMPILER_FENCE;
        // Fall back to OS - cntvct_el0 frequency is low
//        timespec ts;
//        clock_gettime(CLOCK_REALTIME, &ts);
//        t = ts.tv_sec * 1000000000LL + ts.tv_nsec;
        auto tp = std::chrono::high_resolution_clock::now();
        t = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch()).count();
        CPU_T_COMPILER_FENCE;
#endif
        return t;
    }

    CPU_T_ALWAYS_INLINE uint64_t Stop64() {
        uint64_t t;
#ifdef CPU_T_ARCH_PPC
        asm volatile("mfspr %0, %1" : "=r"(t) : "i"(268));
//#elif defined(CPU_T_ARCH_AARCH64)
//        asm volatile("mrs %0, cntvct_el0" : "=r"(t));
#elif defined(CPU_T_ARCH_X86_64) && defined(CPU_T_MSC_VER)
        CPU_T_COMPILER_FENCE;
        unsigned aux;
        t = __rdtscp(&aux);
        _mm_lfence();
        CPU_T_COMPILER_FENCE;
#elif defined(CPU_T_ARCH_X86_64) && (defined(CPU_T_CLANG) || defined(CPU_T_GCC))
        // Use inline asm because __rdtscp generates code to store TSC_AUX (ecx).
        asm volatile(
                "rdtscp\n\t"
                "shl $32, %%rdx\n\t"
                "or %%rdx, %0\n\t"
                "lfence"
                : "=a"(t)
                :
            // "memory" avoids reordering. rcx = TSC_AUX. rdx = TSC >> 32.
            // "cc" = flags modified by SHL.
                : "rcx", "rdx", "memory", "cc");
#else
        CPU_T_COMPILER_FENCE;
//        timespec ts;
//        clock_gettime(CLOCK_REALTIME, &ts);
//        t = ts.tv_sec * 1000000000LL + ts.tv_nsec;
        auto tp = std::chrono::high_resolution_clock::now();
        t = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch()).count();
        CPU_T_COMPILER_FENCE;
#endif
        return t;
    }


    inline uint32_t Start32() {
        uint32_t t;
#if defined(CPU_T_ARCH_X86_64)
#   if defined(CPU_T_MSC_VER)
        _ReadWriteBarrier();
      _mm_lfence();
      _ReadWriteBarrier();
      t = static_cast<uint32_t>(__rdtsc());
      _ReadWriteBarrier();
      _mm_lfence();
      _ReadWriteBarrier();
#   else
        asm volatile(
                "lfence\n\t"
                "rdtsc\n\t"
                "lfence"
                : "=a"(t)
                :
            // "memory" avoids reordering. rdx = TSC >> 32.
                : "rdx", "memory");
#   endif
#else
        t = static_cast<uint32_t>(Start64());
#endif
        return t;
    }

    inline uint32_t Stop32() {
        uint32_t t;
#if defined(CPU_T_ARCH_X86_64)
#   if defined(CPU_T_MSC_VER)
        _ReadWriteBarrier();
      unsigned aux;
      t = static_cast<uint32_t>(__rdtscp(&aux));
      _ReadWriteBarrier();
      _mm_lfence();
      _ReadWriteBarrier();
#   else
        // Use inline asm because __rdtscp generates code to store TSC_AUX (ecx).
        asm volatile(
                "rdtscp\n\t"
                "lfence"
                : "=a"(t)
                :
            // "memory" avoids reordering. rcx = TSC_AUX. rdx = TSC >> 32.
                : "rcx", "rdx", "memory");
#   endif
#else
        t = static_cast<uint32_t>(Stop64());
#endif
        return t;
    }

    template<class T>
    inline T Start();

    template<class T>
    inline T Stop();

    template<>
    CPU_T_ALWAYS_INLINE uint64_t Start<uint64_t>() {
        return Start64();
    }

    template<>
    CPU_T_ALWAYS_INLINE uint64_t Stop<uint64_t>() {
        return Stop64();
    }

    template<>
    CPU_T_ALWAYS_INLINE uint32_t Start<uint32_t>() {
        return Start32();
    }

    template<>
    CPU_T_ALWAYS_INLINE uint32_t Stop<uint32_t>() {
        return Stop32();
    }

    template<class Tick = uint64_t>
    class CpuTimer {
    public:
        using STick = typename std::make_signed<Tick>::type;
        explicit CpuTimer(int64_t init_loop_num = 10000000LL): overhead_cycles_(0), ns_per_tick_(1.0) {
            constexpr size_t BANK_SIZE = 256U;
            constexpr size_t OUTER_LOOP_NUM = 1024U;
            Tick repetitions[OUTER_LOOP_NUM];


            std::fill(repetitions, repetitions + OUTER_LOOP_NUM, 0x328324349377ULL);
            Tick pass_banks[BANK_SIZE];
            std::fill(pass_banks, pass_banks + BANK_SIZE, 0x82472348984ULL);
            for (size_t i = 0; i < OUTER_LOOP_NUM; ++i) {
                for (size_t j = 0; j < BANK_SIZE; ++j) {
                    auto start_t = Start();
                    auto end_t = Stop();
                    auto pass_ticks = end_t - start_t;
                    pass_banks[j] = pass_ticks;
                }
                std::sort(pass_banks, pass_banks + BANK_SIZE);
                auto temp_median = pass_banks[BANK_SIZE / 2UL];
                repetitions[i] = temp_median;
            }
            std::sort(repetitions, repetitions + OUTER_LOOP_NUM);
            // median of median algorithm is an estimation of the median
            auto median_pass_ticks = repetitions[OUTER_LOOP_NUM / 2];
            overhead_cycles_ = static_cast<STick>(median_pass_ticks);

            if (init_loop_num < 0) {
                init_loop_num = 10000000LL;
            }
            auto c_t0 = std::chrono::high_resolution_clock::now();
            auto start_ticks = Start64();
            for (int64_t i = 0; i < init_loop_num; ++i) {
                auto start_t = Start64();
                auto end_t = Stop64();
                (void)start_t;
                (void)end_t;
            }
            auto end_ticks = Stop64();
            auto c_t1 = std::chrono::high_resolution_clock::now();
            int64_t pass_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(c_t1 - c_t0).count();
            auto total_pass_ticks = end_ticks - start_ticks;
            ns_per_tick_ = static_cast<double>(pass_ns) / static_cast<double>(total_pass_ticks);
        }

        template<bool eliminate_overhead=false, class Func, class... Args>
        CPU_T_ALWAYS_INLINE STick Measure(Func &&func, Args&&... args) {
            auto start_t = Start();
            if constexpr(sizeof...(args) != 0) {
                DoNotOptimize(std::forward<Args>(args)...);
            }

            if constexpr(std::is_void_v<decltype(func(std::forward<Args>(args)...))>) {
                func(std::forward<Args>(args)...);
            }
            else {
                auto temp_ret = func(std::forward<Args>(args)...);
                DoNotOptimize(temp_ret);
            }
            auto end_t = Stop();
            auto pass_ticks = end_t - start_t;
            if constexpr (eliminate_overhead) {
                STick real_ticks = static_cast<STick>(pass_ticks) - overhead_cycles_;
                return real_ticks;
            }
            else {
                return static_cast<STick>(pass_ticks);
            }
        }

        CPU_T_ALWAYS_INLINE static Tick Start() {
            return cpu_t::Start<Tick>();
        }

        CPU_T_ALWAYS_INLINE static Tick Stop() {
            return cpu_t::Stop<Tick>();
        }

        inline double ns_per_tick() const {
            return ns_per_tick_;
        }

        inline STick overhead_ticks() const {
            return overhead_cycles_;
        }

    protected:
        STick overhead_cycles_;
        double ns_per_tick_;


    }; // class CpuTimer

} // namespace cpu_t
