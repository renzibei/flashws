#pragma once

#include "flashws/base/basic_macros.h"
#include "flashws/utils/singleton.h"
#include <random>

namespace fws {

    class PRNGSecret : public Singleton<PRNGSecret> {
    public:
        PRNGSecret() {
            ReSeed();
        }

        void ReSeed() {
            auto rd = std::random_device{};
            rng0.seed(rd());
            rng1.seed(rd());
        }

        std::tuple<uint64_t, uint64_t> secrets() {
            return {rng0(), rng1()};
        }

    private:
        std::mt19937_64 rng0, rng1;
    };

    // TODO: Not really CSPRNG
    uint32_t SemiSecureRand32() {
        auto [v0, v1] = PRNGSecret::instance().secrets();
        uint64_t product = v0 * v1;
        return product >> 32;
    }

    uint64_t SemiSecureRand64() {
        auto [v0, v1] = PRNGSecret::instance().secrets();
        __uint128_t u0 = static_cast<__uint128_t>(v0);
        __uint128_t u1 = static_cast<__uint128_t>(v1);
        uint64_t half_bits = static_cast<uint64_t>((u0 * u1) >> 64);
        return half_bits;
    }

    std::tuple<uint64_t, uint64_t> SemiSecureRand128() {
        uint64_t v0 = SemiSecureRand64();
        uint64_t v1 = SemiSecureRand64();
        return {v0, v1};
    }



} // namespace fws