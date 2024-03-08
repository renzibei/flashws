#pragma once


#include <cstdint>
#include <cstddef>

namespace test {
//    const char* host_ip = "104.193.88.77";

    constexpr uint16_t host_port = 443;
#define REAL_HOST "www.google.com"
//#define REAL_HOST "abc123456.com"
//#define REAL_HOST "www.baidu.com"
//#define REAL_HOST "www.cloudflare.com"
//#define REAL_HOST ""
    constexpr const char* host_ip = "172.217.12.132"; // www.google.com
//    constexpr const char* host_ip = "104.193.88.77"; // www.baidu.com
//    constexpr const char* host_ip = "103.126.210.28"; // abc123456.com
//    constexpr const char* host_ip = "104.16.123.96"; // www.cloudflare.com
//    constexpr const char* host_ip = "127.0.0.1";
    constexpr const char* host_name = REAL_HOST;
    constexpr const char https_request[] = "GET / HTTP/1.1\r\n"
                                          "Host: " REAL_HOST "\r\n"
                                         "\r\n";

    constexpr int BUSY_POLL_US = 800;

    constexpr int MAX_EVENT_NUM = 4096;
    constexpr size_t MAX_BUFFER_SIZE = 1UL << 14;

} // namespace test