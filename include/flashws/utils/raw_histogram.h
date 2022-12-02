#pragma once

#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cmath>

namespace raw_h {

#if defined(__GNUC__) || defined(__clang__)
#define RAW_H_LIKELY(x)   (__builtin_expect(static_cast<bool>(x), 1))
#define RAW_H_UNLIKELY(x) (__builtin_expect(static_cast<bool>(x), 0))
#else
    #define RAW_H_LIKELY(x)   (x)
#define RAW_H_UNLIKELY(x) (x)
#endif

#ifndef RAW_H_ALWAYS_INLINE
#   ifdef _MSC_VER
#       define RAW_H_ALWAYS_INLINE __forceinline
#   else
#       define RAW_H_ALWAYS_INLINE inline __attribute__((__always_inline__))
#   endif
#endif

    template<class T, class Allocator = std::allocator<T>>
    class RawHistogram {
    public:

        explicit RawHistogram(size_t max_call_num = 10000): count_(0), max_call_num_(max_call_num),
                                                            data_vec_(max_call_num, static_cast<T>(1)) {

        }

        RAW_H_ALWAYS_INLINE int AddValue(const T& t) {
            if RAW_H_UNLIKELY(count_ + 1UL > max_call_num_) {
                return -1;
            }
            data_vec_[count_++] = t;
            return 0;
        }

        RAW_H_ALWAYS_INLINE int AddValue(T&& t) {
            if RAW_H_UNLIKELY(count_ + 1UL > max_call_num_) {
                return -1;
            }
            data_vec_[count_++] = std::move(t);
            return 0;
        }

        T Quantile(double q) const {
            if (q < 0.0 || q > 1.0 || count_ == 0) {
                return data_vec_[0];
            }
            size_t index = static_cast<double>(count_ - 1Ul) * q;
            return data_vec_[index];
        }

        /**
         * Call this before Quantile if there is new added values after Print
         */
        void SortForUse() {
            std::sort(data_vec_.data(), data_vec_.data() + count_);
        }

        enum PrintStyle {
            AVERAGE_INTERVAL_STYLE,
            LONG_TAIL_STYLE,
        };

        int Print(size_t show_cnt = 10UL, PrintStyle style = LONG_TAIL_STYLE, FILE *out_fp = stdout) {
            if (show_cnt == 0 || count_ <= 1UL) {
                return -1;
            }
            std::sort(data_vec_.data(), data_vec_.data() + count_);
            size_t print_cnt = std::min(count_ - 1UL, show_cnt);
            double interval_len = static_cast<double>(count_ - 1UL) / static_cast<double>(print_cnt);
            double real_index = 0.0;
            double cur_interval = 0.25;
            fprintf(out_fp, "Value,Percentile,TotalCount\n");
            for (size_t i = 0; i < print_cnt + 1UL; ++i) {
                size_t index = static_cast<size_t>(std::round(real_index));
                double percentile = real_index / static_cast<double>(count_ - 1UL);
                if (i == print_cnt) {
                    index = count_ - 1UL;
                    percentile = 1.0;
                }

                std::stringstream ss;
                ss << data_vec_[index] << "," << std::setprecision(8) << std::fixed << percentile << "," << index + 1ULL << std::endl;
                fprintf(out_fp, "%s", ss.str().c_str());
                if (style == AVERAGE_INTERVAL_STYLE) {
                    real_index += interval_len;
                }
                else {
                    real_index += cur_interval * static_cast<double>(count_ - 1UL);
                    if (i & 1UL) {
                        cur_interval *= 0.5;
                    }
                }
            }
            return 0;
        }

    protected:
        size_t count_;
        size_t max_call_num_;
        std::vector<T, Allocator> data_vec_;
    }; // class raw histogram

} // namespace raw_h
