#pragma once
#include <cstdint>
#include <cstddef>

namespace test {

//    inline constexpr const char* const SERVER_IP = "10.5.96.3";
//    inline constexpr const char* const SERVER_IP = "10.5.96.7";
    inline constexpr const char *SERVER_IP = "172.31.48.241";


    inline constexpr int SERVER_PORT = 58600;


//    inline constexpr size_t MAX_DATA_LEN = 64;
    inline constexpr size_t MAX_DATA_LEN = 512;
//    inline constexpr size_t MAX_DATA_LEN = 1UL << 12;
//    inline constexpr size_t MAX_DATA_LEN = 1 << 21;

    inline constexpr size_t MSG_LIMIT_PER_CLIENT = 300'000;
    inline constexpr int REBORN_LIMIT_FOR_CLIENT = 1;
    inline constexpr size_t CON_CLIENT_NUM = 1;
    inline constexpr size_t TOTAL_MSG_CNT = MSG_LIMIT_PER_CLIENT * CON_CLIENT_NUM * REBORN_LIMIT_FOR_CLIENT;

    inline constexpr int LISTEN_BACKLOG = 128;

    inline constexpr bool ENABLE_TLS = true;
    inline constexpr bool SHOULD_VERIFY_CERT = true;
    inline constexpr const char* hostname = "";
    inline constexpr const char* cert_file_path = "../../new-ws-echo/certs/server.crt";
    inline constexpr const char* key_file_path = "../../new-ws-echo/certs/server.key";
    inline constexpr const char* ca_file_path = "../../new-ws-echo/certs/ca.pem";

    inline constexpr const char* log_data_file_path = "./log_data.csv";

#define ENABLE_NO_DELAY 1

} // namespace test