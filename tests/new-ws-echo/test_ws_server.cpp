#include "flashws/flashws.h"
#include "flashws/net/ws_server_socket.h"
#include "flashws/net/floop.h"
#include "test_def.h"
#include <deque>
#include <chrono>

namespace test {



    using WSSocket = fws::WSServerSocket<ENABLE_TLS>;


    struct BufferStatus {
        uint8_t opcode;
        uint8_t is_msg_end;
    };
    struct ConnectCtx {
        fws::IOBuffer io_buf;
        BufferStatus status;
    };

    struct Context {
        fws::FLoop<fws::FlashAllocator<char>> loop;

        uint64_t last_interval_send_bytes = 0;
        uint64_t last_interval_recv_bytes = 0;
        uint64_t last_interval_recv_msg_cnt = 0;
        uint64_t last_interval_send_msg_cnt = 0;
        size_t last_msg_size = 0;
        int64_t interval_start_ns = 0;
        FILE* output_fp = nullptr;



        void CountStats() {
            if FWS_LIKELY(((last_interval_recv_msg_cnt & 0x3fffUL)
//                && (last_interval_recv_bytes <= MAX_DATA_LEN * 4096UL)
                          ) || last_interval_recv_msg_cnt == 0) {
                return;
            }
            int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            int64_t interval_ns = now_ns - interval_start_ns;
            constexpr int64_t BITS_PER_BYTE = 8;
            double interval_sec = double(interval_ns) / (1e+9);
            double recv_throughput_mbps = double((last_interval_recv_bytes) *
                                                 BITS_PER_BYTE) / (1e+6) / interval_sec;
            double send_throughput_mbps = double((last_interval_send_bytes) *
                                                 BITS_PER_BYTE) / (1e+6) / interval_sec;

            double recv_mm_msg_per_sec = double(last_interval_recv_msg_cnt)
                                         / (1e+6) / interval_sec;
            double send_mm_msg_per_sec = double(last_interval_send_msg_cnt)
                                         / (1e+6) / interval_sec;
//            if (last_interval_send_msg_cnt != last_interval_recv_msg_cnt) {
//                printf("Warning, last interval recv: %zu msg, send %zu msg\n",
//                       last_interval_recv_msg_cnt, last_interval_send_msg_cnt);
//            }
            printf("last_msg_size: %zu, avg rx+tx goodput: %.2lf Mbps, %.4lf 10^6 msg/sec,"
                   "active_client_cnt: %zu\n",
                   last_msg_size,
                   recv_throughput_mbps + send_throughput_mbps,
                   recv_mm_msg_per_sec + send_mm_msg_per_sec,
                   loop.socket_count() - 1U);
            if (output_fp != nullptr) {
                // msg_size, rx goodput, tx goodput, rx mm mps, tx mm mps, connection cnt
                fprintf(output_fp, "%zu,%.3lf,%.3lf,%lf,%lf,%zu\n",
                        last_msg_size,
                        recv_throughput_mbps,
                        send_throughput_mbps,
                        recv_mm_msg_per_sec,
                        send_mm_msg_per_sec,
                        loop.socket_count() - 1U
                );
                fflush(output_fp);
            }

            last_interval_recv_bytes = 0;
            last_interval_send_bytes = 0;
            last_interval_recv_msg_cnt = 0;
            last_interval_send_msg_cnt = 0;
            interval_start_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::high_resolution_clock::now().time_since_epoch()).count();

        }


    };




    int TestWsServer(int argc, char** argv) {
        printf("Prepare to init fws env\n");
        {
            int code = fws::InitEnv(argc, argv);
            if (code < 0) {
                printf("Error in Init Env\n");
                return code;
            }
        }

//        if (argc < 5) {
//            printf("Invalid parameters!\nUsage: ./echo_server ip_address port max_msg_len export_filename\n");
//            return -1;
//        }
//
//        const char* SERVER_IP = argv[1];
//
//        int SERVER_PORT = atoi(argv[2]);
//        if (SERVER_PORT <= 0) {
//            printf("Invalid port: %s\n", argv[2]);
//            return -1;
//        }
//        long long max_msg_len = atoll(argv[3]);
//        if (max_msg_len <= 0) {
//            printf("invalid max_msg_len: %s\n", argv[3]);
//            return -1;
//        }
//        MAX_DATA_LEN = size_t(max_msg_len);
//
//        const char* export_file_path = argv[4];
//
//
//        fws::InitEnv(argc - 3, argv + 3);
        Context ctx{};
        ctx.loop = fws::FLoop{};
        if (ctx.loop.Init<ENABLE_TLS>() < 0) {
            printf("Failed to init loop\n");
            return -1;
        }

//        ctx.loop.SetOnEventFunc([](fws::FLoop<fws::FlashAllocator<char>>& loop){
//            printf("OnEventFunc called, cur sock count: %zu\n", loop.socket_count());
//
//        });

        if constexpr (ENABLE_TLS) {
            if (fws::SSLManager::instance().Init(SHOULD_VERIFY_CERT, cert_file_path, key_file_path,
                                                 nullptr) < 0) {
                printf("Failed to init ssl manager, %s\n", fws::GetErrorStrP());
                std::abort();
            }
        }

        const char* export_file_path = log_data_file_path;

        ctx.output_fp = fopen(export_file_path, "w");
        if (ctx.output_fp == nullptr) {
            printf("Cannot create file at %s\n", export_file_path);
            return -1;
        }
        printf("Will output to %s\n", export_file_path);
        // msg_size, rx goodput, tx goodput, rx mm mps, tx mm mps
        fprintf(ctx.output_fp, "msg_size,rx_goodput,tx_goodput,rx_mm_mps,tx_mm_mps,connection_cnt\n");

        WSSocket ws_socket{};
        if (ws_socket.Init() < 0) {
            printf("Failed to init ws_socket\n");
            return -1;
        }

        ws_socket.SetOnNewConnection([](WSSocket &w_socket, std::string_view req_uri,
                                        std::string_view host, std::string_view origin,
                                        std::string_view sub_protocols,
                                        std::string_view extensions,
                                        std::string_view &resp_sub_protocol,
                                        std::string_view &resp_extensions, void *user_data) {
//            printf("OnNewWsConnection called, req_uri: %s, host: %s\n",
//                   std::string(req_uri).c_str(), std::string(host).c_str());
            auto new_buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
            new_buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
            ConnectCtx *con_ctx = (ConnectCtx*)user_data;
            new (con_ctx) ConnectCtx{std::move(new_buf), {}};
            std::string sub_protocols_str(sub_protocols);
            std::string extensions_str(extensions);
//            printf("Client provide protocols: %s, extensions: %s\n",
//                   sub_protocols_str.c_str(),
//                   extensions_str.c_str());
            return 0;
        });

        ws_socket.SetOnRead([&](WSSocket &ws_socket, uint32_t opcode, fws::IOBuffer io_buf,
                               bool is_frame_end, bool is_msg_end, bool is_control_msg, void *user_data) {


//            printf("OnRecvWSPart called, fd: %d, opcode: %u, start_pos: %zu, size: %zu, cap: %zu,"
//                   "is_frame_end: %d, is_msg_end: %d, is_control_msg: %d\n",
//                   ws_socket.tcp_socket().fd(), opcode, io_buf.start_pos, io_buf.size, io_buf.capacity,
//                   is_frame_end, is_msg_end, is_control_msg);
            if (!is_control_msg) {
//                constexpr size_t MAX_DISPLAY_LEN = 128;
//                std::string str((char*)(io_buf.data + io_buf.start_pos), std::min(MAX_DISPLAY_LEN, io_buf.size));
//                if (io_buf.size > 0) {
//                    printf("data:\n%s\n", str.c_str());
//                    if (io_buf.size > MAX_DISPLAY_LEN) {
//                        printf("......\n");
//                    }
//                }
                char* FWS_RESTRICT data = (char*)(io_buf.data + io_buf.start_pos);
                auto &con_ctx = *(ConnectCtx*)user_data;
                auto &io_buf_ = con_ctx.io_buf;
                memcpy(io_buf_.data + io_buf_.start_pos + io_buf_.size, data, io_buf.size);
                io_buf_.size += io_buf.size;
                if FWS_UNLIKELY(ctx.interval_start_ns == 0) {
                    ctx.interval_start_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
                }

                ctx.last_interval_recv_bytes += io_buf.size;

                con_ctx.status = {uint8_t(opcode), uint8_t(is_msg_end)};
                if (is_msg_end) {
                    ++ctx.last_interval_recv_msg_cnt;
                    ctx.last_msg_size = io_buf_.size;
                    size_t target_size = io_buf_.size;
                    {
                        ssize_t write_ret = ws_socket.WriteFrame(std::move(io_buf_),
                                                                 (fws::WSTxFrameType)con_ctx.status.opcode, true);
                        FWS_ASSERT(write_ret >= 0);
                    }
                    ctx.last_interval_send_bytes += target_size;

                    ++ctx.last_interval_send_msg_cnt;
                    ctx.CountStats();
                    io_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                    io_buf_.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;


                }

            }
            else {
                if (opcode == fws::WS_OPCODE_PONG) {
                    FWS_ASSERT(is_frame_end);
                    FWS_ASSERT(is_msg_end);
                }
            }

        });

        ws_socket.SetOnClose([&](WSSocket &w_socket, uint32_t status_code, std::string_view reason, void *user_data) {

            if (status_code != 1000U) {
                std::string reason_str(reason);
                printf("OnCloseConnection called, fd: %d, status_code %u, reason: %s\n",
                       w_socket.under_socket().fd(), status_code, reason_str.c_str());
            }
            ConnectCtx *con_ctx = (ConnectCtx*)user_data;
            std::destroy_at(con_ctx);
        });

        if (ws_socket.StartListen(SERVER_IP, SERVER_PORT, LISTEN_BACKLOG, fws::TCPSocket::REUSE_ADDR_MODE) < 0) {
            printf("Failed to start listen\n");
            return -1;
        }

        auto [add_ret, new_sock_ptr] = ctx.loop.AddSocket(std::move(ws_socket), sizeof(ConnectCtx), true);
        if (add_ret < 0) {
            printf("Failed to add ws_socket to loop\n");
            return -1;
        }
        printf("start to run loop\n");
        ctx.loop.Run();
        return 0;

    }

} // namespace test


int main(int argc, char** argv) {
    return test::TestWsServer(argc, argv);
}