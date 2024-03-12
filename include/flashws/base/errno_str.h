#pragma once
#include "flashws/base/basic_macros.h"
#include <utility>
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <string>

namespace fws {



    namespace detail {
        thread_local inline char error_buf[4096] = {0};
    } // namespace detail

    inline FWS_NOINLINE void SetErrorString(const char* src, size_t len) {
        strncpy(detail::error_buf, src, std::min(len, sizeof(detail::error_buf)));
    }

    inline FWS_NOINLINE void WriteToError(const void* src, size_t len) {
        memcpy(detail::error_buf, src, std::min(len, sizeof(detail::error_buf)));
    }


#ifdef FWS_DEV_DEBUG
    inline FWS_NOINLINE void SetErrorFormatStr(const char* FWS_RESTRICT format, ...) {
        std::va_list arg_list;
        va_start(arg_list, format);
        vsnprintf(detail::error_buf, sizeof(detail::error_buf), format, arg_list);
        va_end(arg_list);
    }
#else
//    template<class... Args>
//    inline FWS_NOINLINE void SetErrorFormatStr(const char* FWS_RESTRICT format, Args... args)  {
//        snprintf(detail::error_buf, sizeof(detail::error_buf), format, std::forward<Args>(args)...);
//    }
    #define  SetErrorFormatStr(format, ...) \
    snprintf(detail::error_buf, sizeof(detail::error_buf), format, ##__VA_ARGS__)
#endif

    inline std::string_view GetErrorStrV() {
        return {detail::error_buf};
    }

    inline std::string GetErrorString() {
        return {detail::error_buf};
    }

    inline const char* GetErrorStrP() {
        return detail::error_buf;
    }

    namespace detail {

        inline FWS_NOINLINE void FwsAssert(const char* exp, int line,
                                    const char* file) {
            fprintf(stderr, "Assert %s failed, line %d in %s\n", exp, line, file);
            std::abort();
        }

        inline FWS_NOINLINE void FwsAssert(const char* exp, const char* msg, int line,
                                    const char* file) {
            fprintf(stderr, "Assert %s failed, %s, line %d in %s\n",
                    exp, msg, line, file);
            std::abort();
        }

    } // namespace detail


#ifdef FWS_DEBUG
#define FWS_ASSERT(EX) \
       {if FWS_UNLIKELY(!(EX))                      \
            fws::detail::FwsAssert(#EX, __LINE__, __FILE__); }

#define FWS_ASSERT_M(EX, MSG) \
        {if FWS_UNLIKELY(!(EX))     \
            fws::detail::FwsAssert(#EX, (MSG), __LINE__, __FILE__); }
#else
#define FWS_ASSERT(EX) ((void)(EX))
#define FWS_ASSERT_M(EX, MSG) ((void)(EX))
#endif

} // namespace fws