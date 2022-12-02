#pragma once

#ifdef USE_RAW_HISTOGRAM
#include "raw_histogram.h"
#else
#include "hdr/hdr_histogram.h"
#endif

#include <functional>

namespace hist {

#ifdef USE_RAW_HISTOGRAM
    class HistWrapper: public raw_h::RawHistogram<int64_t> {
        using Base = raw_h::RawHistogram<int64_t>;
    public:
        explicit HistWrapper(size_t max_call_num = 10000, int64_t min_value = 1,
                             int64_t max_value = 1'000'000'000LL):Base(max_call_num) {
            (void)min_value;
            (void)max_value;
        }
        using Base::AddValue;
        using Base::Quantile;
        using Base::SortForUse;

        void PrintHdr(size_t show_cnt = 15UL, FILE *out_fp = stdout, int step = 2) {
            (void)step;
            Print(show_cnt, LONG_TAIL_STYLE, out_fp);
        }

    protected:

    }; // class HistWrapper
#else
    class HistWrapper {
    public:
        explicit HistWrapper(size_t max_call_num = 10000, int64_t min_value = 1,
                             int64_t max_value = 1'000'000'000LL)
                             : hdr_ptr(nullptr) {
            (void)max_call_num;
            hdr_init(min_value, max_value, 2, &hdr_ptr);
        }

        HistWrapper operator==(const HistWrapper&) = delete;
        HistWrapper(const HistWrapper&) = delete;

        constexpr HistWrapper(HistWrapper&& o) noexcept :hdr_ptr(o.hdr_ptr) {
            o.hdr_ptr = nullptr;
        }

        constexpr HistWrapper& operator=(HistWrapper&& o) {
            if (this != &o) {
                hdr_close(hdr_ptr);
                hdr_ptr = std::exchange(o.hdr_ptr, nullptr);
            }
            return *this;
        }

        inline void AddValue(int64_t x) {
            hdr_record_value(hdr_ptr, x);
        }

        int64_t Quantile(double percentile) const {
            return hdr_value_at_percentile(hdr_ptr, percentile * 100.0);
        }

        void SortForUse() {}

        void PrintHdr(size_t /*show_cnt*/, FILE *out_fp = stdout, int step = 2) {
            hdr_percentiles_print(hdr_ptr, out_fp, step, 1.0, CSV);
        }

        ~HistWrapper() {
            hdr_close(hdr_ptr);
            hdr_ptr = nullptr;
        }

    protected:
        hdr_histogram *hdr_ptr;

    }; // class HistWrapper
#endif

}// namespace hist