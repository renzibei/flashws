#pragma once

namespace test {

    // vu-la01
//    inline constexpr const char* const SERVER_IP = "10.5.96.3";
    // vu-la06
    inline constexpr const char* const SERVER_IP = "10.5.96.7";

    // aws-vi01
//    inline constexpr const char* const SERVER_IP = "172.31.99.99";
//    inline constexpr const char* const SERVER_IP = "172.31.98.130";


    inline constexpr uint16_t SERVER_PORT = 58600;


    inline constexpr size_t TEST_TIMES = 100'000;
    inline constexpr size_t MAX_DATA_LEN = 64;
//    inline constexpr size_t MAX_DATA_LEN = 1UL << 18;

    constexpr size_t MAX_EVENT_NUM = 16;

    inline constexpr bool USE_BUSY_POLL = true;
    inline constexpr int BUSY_POLL_US = 800;

#define ENABLE_NO_DELAY 1

} // namespace test