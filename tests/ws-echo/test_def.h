#pragma once
#include <cstdint>
#include <cstddef>

namespace test {

//    inline constexpr const char* const SERVER_IP = "10.5.96.3";
//    inline constexpr const char* const SERVER_IP = "10.5.96.7";



//    inline constexpr uint16_t SERVER_PORT = 58600;


//    inline constexpr size_t TEST_TIMES = 100'000;
//    inline constexpr size_t MAX_DATA_LEN = 64;
//    inline constexpr size_t MAX_DATA_LEN = 1UL << 18;

    constexpr size_t MAX_CLIENT_EVENT_NUM = 65536;
    constexpr size_t MAX_SERVER_EVENT_NUM = 65536;

    inline constexpr bool USE_BUSY_POLL = true;
    inline constexpr int BUSY_POLL_US = 800;

    inline constexpr int LISTEN_BACKLOG = 128;

#define ENABLE_NO_DELAY 1

} // namespace test