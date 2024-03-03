#pragma once

//#define SERVER_PORT     58600
#define SERVER_PORT 58600
#define MAX_DATA_LEN    (1 << 18)
//#define MAX_DATA_LEN 64

//#define TEST_TIMES      1'00'000

#define ENABLE_NO_DELAY 1
#define ENABLE_BUSY_POLL 1
#define BUSY_POLL_US 800
#define SET_NON_BLOCK 1
// If the client side have many connections in fstack, it may bring too many TIME_WAIT
// status closed socket. In this case, a linger with zero timeout can be used,
// when the client side close the socket, it will send a RST to the server side, and
// no TIME_WAIT status will be generated.
#define SET_LINGER_ZERO_TIMEOUT 0

#define MAX_WRITE_EVENT_WRITE_SIZE 65536
#define FSTACK_ONE_TIME_FULL_THRES 16384
#define MAX_FSTACK_ONE_TIME_WRITE_SIZE 16384

#define SEND_LATENCY_DATA 0


namespace test {
//inline constexpr const char * SERVER_IP  = "127.0.0.1";

//inline constexpr const char* const SERVER_IP = "10.5.96.3";


    inline constexpr const char *SERVER_IP = "10.5.96.7";

    inline constexpr bool ENABLE_TLS = true;
    inline constexpr bool SHOULD_VERIFY_CERT = true;
    inline constexpr const char* hostname = "";
    inline constexpr const char* cert_file_path = "../certs/server.crt";
    inline constexpr const char* key_file_path = "../certs/server.key";
    inline constexpr const char* ca_file_path = "../certs/ca.pem";


    inline constexpr size_t MSG_LIMIT_PER_CLIENT = 100'000;
//    inline constexpr size_t MSG_LIMIT_PER_CLIENT = 50;

    inline constexpr size_t CON_CLIENT_NUM = 1;

    inline constexpr size_t LISTEN_BACKLOG = 4096;

    inline constexpr size_t REBORN_LIMIT_FOR_CLIENT = 1;

    inline constexpr size_t TOTAL_MSG_CNT = MSG_LIMIT_PER_CLIENT * CON_CLIENT_NUM * REBORN_LIMIT_FOR_CLIENT;

    inline constexpr uint64_t CHECK_TIMEOUT_TICK = 240ULL * 4ULL * 1'000'000'000ULL;

#if SEND_LATENCY_DATA
    inline constexpr size_t LATENCY_DATA_SIZE = sizeof(uint64_t) * 2;
#else
    inline constexpr size_t LATENCY_DATA_SIZE = 0;
#endif

    static_assert(LATENCY_DATA_SIZE <= MAX_DATA_LEN);


#define MAX_EVENT_NUM 4096

} //namespace test