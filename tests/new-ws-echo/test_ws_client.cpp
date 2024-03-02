#include "flashws/net/ws_client_socket.h"
#include "flashws/flashws.h"
#include "flashws/utils/histogram_wrapper.h"
#include "flashws/utils/cpu_timer.h"
#include "flashws/net/floop.h"
#include "test_def.h"
#include <deque>
#include <thread>
namespace test {


//    static size_t MAX_DATA_LEN = 0;
//    static size_t TOTAL_MSG_CNT = 0;
//    static size_t MSG_LIMIT_PER_CLIENT = 0;
//    static int REBORN_LIMIT_FOR_CLIENT = 0;
//    static size_t CON_CLIENT_NUM = 0;
////    size_t TEST_TIMES = 0;
//    static constexpr size_t MAX_EVENT_NUM = MAX_CLIENT_EVENT_NUM;

    template<class WSSocket>
    struct ContextClass {
        hist::HistWrapper rtt_hist;
        fws::FLoop<fws::FlashAllocator<char>> loop;
        cpu_t::CpuTimer<uint64_t> cpu_timer{};

        struct ClientCtx{
            int reborn_cnt = 1;
            uint64_t msg_cnt = 0;
            fws::IOBuffer temp_buf;
            uint64_t start_write_tick = 0;
        };
        size_t data_hash;
        uint64_t loop_cnt = 0;
        int64_t send_bytes_sum = 0;
        int64_t recv_bytes_sum = 0;


        int64_t start_ns_from_epoch = 0;
        int64_t last_record_ns = 0;
        bool wait_shutdown = false;

        std::string server_ip;
        std::string request_uri;
        std::string host;
        uint16_t server_port;

        FILE *out_fp = nullptr;

        static size_t HashArr(const uint8_t* FWS_RESTRICT data, size_t size) {
            size_t hash_value = 0;
            for (size_t i = 0; i < size; ++i) {
                hash_value ^= data[i];
                hash_value = fws::RotateR(hash_value, 5);
            }
            return hash_value;
        }

        // New WS connection established




        void EndClient() {
            loop.StopRun();
            auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            auto to_now_ns = now_ns_from_epoch - start_ns_from_epoch;
            printf("INFO! write read finish! per msg len = %zu times=%zu sendsum=%ld recvsum=%ld cost=%.3lf ms\n",
                   MAX_DATA_LEN, TOTAL_MSG_CNT, send_bytes_sum, recv_bytes_sum,
                   (double)to_now_ns / (1e+6));
            printf("INFO! round trip latency histogram (ns)\n");
            rtt_hist.PrintHdr(30UL);


            wait_shutdown = true;
            if (out_fp != nullptr) {
                // msg_size, avg throughput, P0 latency, P50 latency, P99 latency, P999 latency, P100 latency
                constexpr size_t BITS_PER_BYTE = 8;
                double avg_goodput_mbps = double((recv_bytes_sum + send_bytes_sum) *
                                                 BITS_PER_BYTE) / (1e+6) / (double(to_now_ns) / (1e+9));
                double p0_t = rtt_hist.Quantile(0.0), p50_t = rtt_hist.Quantile(0.5),
                        p99_t = rtt_hist.Quantile(0.99), p999_t = rtt_hist.Quantile(0.999),
                        p100_t = rtt_hist.Quantile(1.0);
                printf("Msg size(bytes): %zu\n"
                       "avg (rx+tx) goodput: %.4lf Mbps\nLatency (us): min: %.3lf, "
                       "P50: %.3lf, P99: %.3lf, P999: %.3lf, P100: %.3lf\n",
                       MAX_DATA_LEN,
                       avg_goodput_mbps, p0_t / 1000.0, p50_t / 1000.0, p99_t / 1000.0,
                       p999_t / 1000.0, p100_t / 1000.0);
                fprintf(out_fp, "%zu,%.4lf,%.3lf,%.3lf,%.3lf,%.3lf,%.3lf\n",
                        MAX_DATA_LEN, avg_goodput_mbps, p0_t / 1000.0, p50_t / 1000.0, p99_t / 1000.0,
                        p999_t / 1000.0, p100_t / 1000.0);
                fclose(out_fp);
            }
        }




        int WriteFirstMsg(WSSocket &w_socket, ClientCtx &client_ctx) {

            auto& buf = client_ctx.temp_buf;
            size_t target_size = buf.size;

            if (size_t(buf.size) == MAX_DATA_LEN) {
                if FWS_UNLIKELY(send_bytes_sum == 0) {
                    start_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                }
                client_ctx.start_write_tick = cpu_timer.Start();
            }
            FWS_ASSERT(buf.data != nullptr);
            ssize_t write_ret = w_socket.WriteFrame(std::move(buf),
                                                    static_cast<fws::WSTxFrameType>(2U), true);
            if FWS_UNLIKELY(write_ret < 0) {
                printf("Error, write return %zd, %s\n", write_ret, fws::GetErrorStrP());
                std::abort();
            }
            send_bytes_sum += target_size;
            client_ctx.temp_buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
            client_ctx.temp_buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
            return 0;
        }



        std::optional<WSSocket> NewWSClient() {
            WSSocket ws_client{};
            int init_ret = 0;
            if constexpr (ENABLE_TLS) {
                init_ret = ws_client.Init(hostname);
            }
            else {
                init_ret = ws_client.Init();
            }
            if FWS_UNLIKELY(init_ret < 0) {
                printf("ws_client init return %d, %s\n",
                       init_ret, std::string(fws::GetErrorStrV()).c_str());
                return std::nullopt;
            }


            {

                int con_ret = ws_client.Connect(server_ip.c_str(), server_port, request_uri, host);
                if (con_ret < 0 && errno != EINPROGRESS) {
                    printf("Error in connect, return %d, %s\n",
                           con_ret, std::string(fws::GetErrorStrV()).c_str());

                    return std::nullopt;
                }
            }

            // If the client is added to the floop by the user, the user_data will
            // be the moved user_data object. But if the socket is created by
            // `accept` method, then the user_data memory is not initialized and
            // need to be constructed by the user in on_open.
            ws_client.SetOnOpen([&](WSSocket &w_socket,
                                   std::string_view resp_sub_protocol,
                                   std::string_view resp_extensions, void *user_data) {
//            printf("OnConnected called fd: %d\n", w_socket.under_socket().fd());
                std::string sub_protocols_str(resp_sub_protocol);
                std::string extensions_str(resp_extensions);
                auto *client_ctx= static_cast<ClientCtx*>(user_data);
//            printf("Write first msg\n");
                FWS_ASSERT(this->WriteFirstMsg(w_socket, *client_ctx) == 0);
//            printf("accept protocols: %s, extensions: %s\n",
//                   sub_protocols_str.c_str(),
//                   extensions_str.c_str());
            });

            // Both client and server should destroy the user_data in on_close callback
            ws_client.SetOnClose([&](WSSocket &w_socket, uint32_t status_code, std::string_view reason, void* user_data) {
                auto &client_ctx = *static_cast<ClientCtx*>(user_data);
                if (status_code != 1000U) {
                    std::string reason_str(reason);
                    printf("OnCloseConnection called, fd: %d, status_code %u, reason: %s\n",
                           w_socket.under_socket().fd(), status_code, reason_str.c_str());
                }
                std::destroy_at(&client_ctx);
                if (loop_cnt >= TOTAL_MSG_CNT) {
                    printf("loop cnt reach TOTAL_MSG_CNT, prepare to end\n");
                    EndClient();
                    return ;
                }
            });

            ws_client.SetOnRead([&](WSSocket &ws_socket, uint32_t opcode, fws::IOBuffer io_buf,
                                    bool is_frame_end, bool is_msg_end, bool is_control_msg, void *user_data) {


//            printf("OnRecvWSPart called, opcode: %u, start_pos: %zu, size: %zu, cap: %zu,"
//                   "is_frame_end: %d, is_msg_end: %d, is_control_msg: %d\n",
//                   opcode, io_buf.start_pos, io_buf.size, io_buf.capacity,
//                   is_frame_end, is_msg_end, is_control_msg);
//                auto *cur_sock_p = &ws_socket;
                if (!is_control_msg) {
                    auto &client_ctx = *static_cast<ClientCtx*>(user_data);
                    auto* temp_buf_ = &client_ctx.temp_buf;

                    uint8_t* FWS_RESTRICT start_data = temp_buf_->data + temp_buf_->start_pos + temp_buf_->size;
                    memcpy(start_data, io_buf.data + io_buf.start_pos, io_buf.size);
                    temp_buf_->size += io_buf.size;
                    recv_bytes_sum += io_buf.size;


                    if (is_msg_end) {


                        auto read_end_tick = cpu_timer.Stop();
                        auto pass_tick = read_end_tick - client_ctx.start_write_tick;
                        int64_t round_trip_ns = std::llround(pass_tick * cpu_timer.ns_per_tick());
                        rtt_hist.AddValue(round_trip_ns);


                        ++loop_cnt;
                        auto client_msg_cnt = ++client_ctx.msg_cnt;
                        if (client_msg_cnt == MSG_LIMIT_PER_CLIENT) {
                            auto old_buf = std::move(*temp_buf_);
                            FWS_ASSERT(old_buf.data != nullptr);
                            FWS_ASSERT(old_buf.size == MAX_DATA_LEN);
                            auto cur_reborn_cnt = client_ctx.reborn_cnt;
                            ws_socket.Close(fws::WS_NORMAL_CLOSE, {});

                            if FWS_LIKELY(cur_reborn_cnt < REBORN_LIMIT_FOR_CLIENT) {
                                auto new_opt_sock = NewWSClient();
                                if FWS_UNLIKELY(!new_opt_sock.has_value()) {
                                    std::abort();
                                }
                                auto& new_sock = new_opt_sock.value();
                                ++cur_reborn_cnt;

                                auto new_ctx = ClientCtx{cur_reborn_cnt, 0,
                                                          std::move(old_buf), read_end_tick};

                                auto [add_sock_ret, new_sock_ptr] = loop.AddSocket(std::move(new_sock), sizeof(ClientCtx), false, std::move(new_ctx));
                                if FWS_UNLIKELY(add_sock_ret < 0) {
                                    printf("Failed to add new socket to loop, %s\n", fws::GetErrorStrP());
                                    std::abort();
                                }

                            }
                            else {
                                if (loop.socket_count() == 0) {
                                    EndClient();
                                }
                            }
                            return ;
                        }


                        if (loop_cnt >= TOTAL_MSG_CNT) {
                            printf("loop cnt reach TOTAL_MSG_CNT, prepare to end\n");
                            EndClient();
                            return ;
                        }

                        if FWS_UNLIKELY(!(loop_cnt & 0x3fffUL)) {
                            size_t temp_hash = HashArr(temp_buf_->data + temp_buf_->start_pos, temp_buf_->size);
//                        size_t temp_hash = HashBufArr(buf_deque.begin(), buf_deque.end());
                            double round_trip_us = double(round_trip_ns) / 1000.0;
                            constexpr int64_t BITS_PER_BYTE = 8;
                            auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                            last_record_ns = now_ns_from_epoch;
                            auto to_now_ns = now_ns_from_epoch - start_ns_from_epoch;
                            double avg_recv_throughput_mbps = double((recv_bytes_sum) *
                                                                     BITS_PER_BYTE) / (1e+6) / (double(to_now_ns) / (1e+9));
                            double avg_send_throughput_mbps = double((send_bytes_sum) *
                                                                     BITS_PER_BYTE) / (1e+6) / (double(to_now_ns) / (1e+9));

                            if FWS_UNLIKELY(temp_hash != data_hash) {
                                printf("Hash not the same, original: %zu, now: %zu\n", data_hash, temp_hash);
                                std::abort();
                            }
                            printf("Avg round trip latency: %.3lf us, throughput "
                                   "rx + tx: %.2lf Mbit/s, hash value: %zu, active fd cnt: %zu\n",
                                   round_trip_us, avg_recv_throughput_mbps +
                                                  avg_send_throughput_mbps,temp_hash,
                                   loop.socket_count());
                        }
                        FWS_ASSERT(is_msg_end);



                        client_ctx.start_write_tick = cpu_timer.Start();
                        size_t target_size = temp_buf_->size;
                        {
                            ssize_t write_ret = ws_socket.WriteFrame(std::move(*temp_buf_),
                                                                     static_cast<fws::WSTxFrameType>(2U), true);
//                        FWS_ASSERT(write_ret >= 0);
                            if FWS_UNLIKELY(write_ret < 0) {
                                printf("WriteFrame return %zd, %s\n",
                                       write_ret, std::strerror(errno));
                                std::abort();
                            }

                        }
                        // We add target_size directly because unsent message will be buffered by
                        // ws_socket
                        send_bytes_sum += target_size;
                        *temp_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                        temp_buf_->start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;




                    }
                    if (is_msg_end) {
                    }

                }
                else {
                    if (opcode == fws::WS_OPCODE_PONG) {
                        FWS_ASSERT(is_frame_end);
                        FWS_ASSERT(is_msg_end);
                    }
//                fws::ReclaimBuf(io_buf);
                }
//
//            fws::ReclaimBuf(io_buf);
                return ;
            }); // SetOnRead








            return ws_client;
        }
    };

    using ClientContext = ContextClass<fws::WSClientSocket<ENABLE_TLS>>;


    int TestWsClient(int argc, char** argv) {
        printf("Prepare to init fws env\n");
        {
            int code = fws::InitEnv(argc, argv);
            if (code < 0) {
                printf("Error in Init Env\n");
                return code;
            }
        }
        setbuf(stdout, 0);
        setbuf(stderr, 0);
//        if (argc < 8) {
//            printf("Invalid parameters!\nUsage: ./echo_client ip_addr port"
//                   " msg_len msg_cnt_per_client client_cnt client_reborn_cnt"
//                   " output_data_filename\n");
//            return -1;
//        }

//        const char* SERVER_IP = argv[1];


//        int SERVER_PORT = atoi(argv[2]);
//        if (SERVER_PORT <= 0) {
//            printf("Invalid port: %s\n", argv[2]);
//            return -1;
//        }
//        long long max_msg_len = atoll(argv[3]);
//        if (max_msg_len <= 0) {
//            printf("invalid msg_len: %s\n", argv[3]);
//            return -1;
//        }
//        MAX_DATA_LEN = size_t(max_msg_len);

//        long long msg_cnt_per_c = atoll(argv[4]);
//        if (msg_cnt_per_c <= 0) {
//            printf("invalid msg_cnt_per_client: %s\n", argv[4]);
//            return -1;
//        }

//        MSG_LIMIT_PER_CLIENT = msg_cnt_per_c;
//        TEST_TIMES = size_t(msg_cnt_per_c);


//        int client_cnt = atoi(argv[5]);
//        if (client_cnt <= 0) {
//            printf("invalid client_cnt: %s\n", argv[5]);
//            return -1;
//        }

//        CON_CLIENT_NUM = client_cnt;

//        int client_reborn_time = atoi(argv[6]);
//        if (client_reborn_time <= 0) {
//            printf("invalid client_reborn_cnt: %s\n", argv[6]);
//            return -1;
//        }
//        REBORN_LIMIT_FOR_CLIENT = client_reborn_time;

//        TOTAL_MSG_CNT = msg_cnt_per_c * client_cnt * client_reborn_time;

//        const char* data_file_path = argv[7];

//        printf("Set host: %s, port: %d, msg_size: %zu, msg_cnt_per_client: %lld,"
//               "data file path: %s\n",
//               SERVER_IP, SERVER_PORT, MAX_DATA_LEN, msg_cnt_per_c, data_file_path);

//        FWS_ASSERT(fws::InitEnv(argc - 7, argv + 7) >= 0);
//        const char* SERVER_IP = argv[1];

        int64_t msg_cnt_per_c = MSG_LIMIT_PER_CLIENT;
        int client_cnt = CON_CLIENT_NUM;
        const char* data_file_path = log_data_file_path;

        printf("Set host: %s, port: %d, msg_size: %zu, msg_cnt_per_client: %ld,"
               "data file path: %s\n",
               SERVER_IP, SERVER_PORT, MAX_DATA_LEN, msg_cnt_per_c, data_file_path);

        FILE* output_fp = fopen(data_file_path, "a");
        if (output_fp == nullptr) {
            printf("Failed to open %s, %s\n", data_file_path, std::strerror(errno));
            return -1;
        }

        std::string request_uri = "/";
        std::string host = std::string(SERVER_IP) + ":" + std::to_string(SERVER_PORT);

        ContextClass<fws::WSClientSocket<ENABLE_TLS>> ctx{
                hist::HistWrapper(TOTAL_MSG_CNT + 2, 1LL, 10000000LL)};
        printf("CpuTimer overhead cycles: %lu cycles, tick per ns: %lf\n",
               ctx.cpu_timer.overhead_ticks(), 1.0 / ctx.cpu_timer.ns_per_tick());

        ctx.server_ip = SERVER_IP;
        ctx.server_port = SERVER_PORT;
        ctx.request_uri = request_uri;
        ctx.host = host;

//        fws::WsServer ws_server{};
//        const char* const listen_addr = "10.5.96.3";
//        const char* const listen_addr = "10.5.96.7";
//        uint16_t port = 58600;
//        auto fq = fws::CreateFQueue();
//        ctx.fq = std::move(fq);

//        ctx.no_delay = false;
//        ctx.busy_poll_us = 0;
//#if ENABLE_NO_DELAY
//        ctx.no_delay = true;
//#endif
//        if (USE_BUSY_POLL) {
//            ctx.busy_poll_us = BUSY_POLL_US;
//        }

        ctx.loop = fws::FLoop{};
        if (ctx.loop.Init<ENABLE_TLS>() < 0) {
            printf("Failed to init loop, %s\n", fws::GetErrorStrP());
            return -1;
        }

        if constexpr (ENABLE_TLS) {
            if (fws::SSLManager::instance().Init(SHOULD_VERIFY_CERT, nullptr, nullptr,
                                                 ca_file_path) < 0) {
                printf("Failed to init ssl manager, %s\n", fws::GetErrorStrP());
                std::abort();
            }
        }

        for (int k = 0; k < client_cnt; ++k) {
            auto opt_ws_client = ctx.NewWSClient();
            if FWS_UNLIKELY(!opt_ws_client.has_value()) {
                return -1;
            }
            fws::WSClientSocket<ENABLE_TLS> ws_client = std::move(opt_ws_client.value());




            constexpr size_t RESERVE_SIZE = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
            auto temp_buf = fws::RequestBuf(MAX_DATA_LEN + RESERVE_SIZE);
            temp_buf.start_pos = RESERVE_SIZE;
            std::srand(1);
            for (size_t i = 0; i < MAX_DATA_LEN; ++i) {
                temp_buf.data[RESERVE_SIZE + i] = rand() % 10 + '0';
            }
            temp_buf.size = MAX_DATA_LEN;
            ctx.data_hash = ctx.HashArr(temp_buf.data + temp_buf.start_pos, temp_buf.size);
//            ctx.temp_buf_ = std::move(temp_buf);
//        ctx.data_hash = ctx.HashBufArr(&temp_buf, &temp_buf + 1);
//        ctx.buf_deque.push_back(std::move(temp_buf));
//        ctx.status_deque.push_back({1U, 1U});
//
            if (k == 0) {
                printf("data hash: %lu\n", ctx.data_hash);
            }
//            int client_fd = ws_client.under_socket().fd();

            ClientContext::ClientCtx client_ctx{ 1, 0, std::move(temp_buf), 0U};
            auto [add_sock_ret, new_sock_ptr] = ctx.loop.AddSocket(std::move(ws_client), sizeof(ClientContext::ClientCtx), false, std::move(client_ctx));
            if FWS_UNLIKELY(add_sock_ret < 0) {
                printf("Failed to add socket to loop, %s\n", fws::GetErrorStrP());
                return -1;
            }
//            ctx.fd_to_socks.emplace(client_fd, ClientContext::ClientCtx{
//                    std::move(ws_client),
//                    1, 0, std::move(temp_buf) });

        }
//        ctx.client_fd = client_fd;

//        ctx.fd_to_socks[client_fd] = std::move(ws_client);
//        ctx.wait_evs = {MAX_EVENT_NUM, fws::FEvent()};
//        ctx.recv_status_ = {uint8_t(2), uint8_t(1)};
        ctx.out_fp = output_fp;
        printf("start to run loop\n");
        ctx.loop.Run();
//        fws::StartRunLoop(OneLoop, &ctx);
        return 0;

    }

} // namespace test


int main(int argc, char** argv) {
    return test::TestWsClient(argc, argv);
}