#pragma once

namespace fws {


#define FWS_LIKELY(x) (__builtin_expect((x), 1))
#define FWS_UNLIKELY(x) (__builtin_expect((x), 0))

#define FWS_NOINLINE __attribute__((__noinline__))
#define FWS_ALWAYS_INLINE inline __attribute__((__always_inline__))

#ifdef _MSC_VER
#define FWS_RESTRICT
#else
#define FWS_RESTRICT __restrict
#endif

#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_COMPILER)
#   define FWS_FUNC_RESTRICT __restrict
#else
#   define FWS_FUNC_RESTRICT
#endif

#define FWS_PRAGMA(x) _Pragma (#x)

#ifdef __clang__
#define FWS_UNROLL_CNT(n) FWS_PRAGMA(clang loop unroll_count(n))
#elif defined(__GNUC__)
#define FWS_UNROLL_CNT(n) FWS_PRAGMA(GCC unroll n)
#else
#define FWS_UNROLL_CNT(n)
#endif

#ifdef __clang__
#define FWS_NO_LOOP_VEC FWS_PRAGMA(clang loop vectorize(disable))
#else
#define FWS_NO_LOOP_VEC
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define FWS_NO_LOOP_VEC_IN_FUNC __attribute__((optimize("no-tree-vectorize")))
#else
#define FWS_NO_LOOP_VEC_IN_FUNC
#endif

#ifdef _MSC_VER
#define FWS_MSVS
#elif defined(__clang__)
#define FWS_CLANG
#elif defined(__GNUC__)
#define FWS_GCC
#else
//    static_assert(false, "Not supported compiler");
#endif

#ifdef __linux__
#define FWS_LINUX __linux__
#endif

} // namespace fws
