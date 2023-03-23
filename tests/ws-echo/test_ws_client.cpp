#include "flashws/net/ws_client_socket.h"
#include "flashws/flashws.h"
#include "flashws/utils/histogram_wrapper.h"
#include "flashws/utils/cpu_timer.h"
#include "test_def.h"
#include <deque>
#include <thread>
namespace test {


    static size_t MAX_DATA_LEN = 0;
    static size_t TOTAL_MSG_CNT = 0;
    static size_t MSG_LIMIT_PER_CLIENT = 0;
    static int REBORN_LIMIT_FOR_CLIENT = 0;
    static size_t CON_CLIENT_NUM = 0;
//    size_t TEST_TIMES = 0;
    static constexpr size_t MAX_EVENT_NUM = MAX_CLIENT_EVENT_NUM;

    template<class WSSocket>
    struct ContextClass {
        hist::HistWrapper rtt_hist;
        fws::FQueue fq;
        cpu_t::CpuTimer<uint64_t> cpu_timer{};

        struct ClientCtx{
            WSSocket sock;
            int reborn_cnt = 1;
            uint64_t msg_cnt = 0;
            fws::IOBuffer temp_buf;
        };

        ska::flat_hash_map<int, ClientCtx> fd_to_socks;

//        size_t cur_read_pos = 0;

//        fws::IOBuffer temp_buf_;
//        fws::IOBuffer io_buf;
//        std::deque<fws::IOBuffer, fws::FlashAllocator<fws::IOBuffer>> buf_deque;
        struct BufferStatus {
            uint8_t opcode;
            uint8_t is_msg_end;
        };
//        BufferStatus recv_status_;

//        int client_fd = 0;

//        bool has_requested_write = false;
        size_t data_hash;
        uint64_t loop_cnt = 0;
        int64_t send_bytes_sum = 0;
        int64_t recv_bytes_sum = 0;

        uint64_t start_write_tick;

        int64_t start_ns_from_epoch = 0;
        int64_t last_record_ns = 0;
        bool wait_shutdown = false;
        std::vector<fws::FEvent> wait_evs;

        std::string server_ip;
        std::string request_uri;
        std::string host;
        uint16_t server_port;
        bool no_delay;
        int busy_poll_us;
        // 5 sec timeout
//        timespec timeout_ = {5, 0LL};

        FILE *out_fp = nullptr;
//        std::deque<BufferStatus, fws::FlashAllocator<uint32_t>> status_deque;


//        template<class ForwardIt>
//        static size_t HashBufArr(ForwardIt begin, ForwardIt end) {
//            size_t hash_value = 0;
//            for (auto it = begin; it != end; ++it) {
//                auto& buf = *it;
//                const uint8_t* FWS_RESTRICT data = (const uint8_t*)(buf.data +buf.start_pos );
//                for (size_t i = 0; i < buf.size; ++i) {
//                    hash_value ^= data[i];
//                    hash_value = fws::RotateR(hash_value, 5);
//                }
//            }
//            return hash_value;
//        }

        static size_t HashArr(const uint8_t* FWS_RESTRICT data, size_t size) {
            size_t hash_value = 0;
            for (size_t i = 0; i < size; ++i) {
                hash_value ^= data[i];
                hash_value = fws::RotateR(hash_value, 5);
            }
            return hash_value;
        }

        // New WS connection established

        int OnConnected(WSSocket &w_socket,
                        std::string_view resp_sub_protocol,
                        std::string_view resp_extensions) {
//            printf("OnConnected called fd: %d\n", w_socket.tcp_socket().fd());
            std::string sub_protocols_str(resp_sub_protocol);
            std::string extensions_str(resp_extensions);
//            printf("accept protocols: %s, extensions: %s\n",
//                   sub_protocols_str.c_str(),
//                   extensions_str.c_str());
            FWS_ASSERT(w_socket.RequestWriteEvent(fq) == 0);
//            FWS_ASSERT(w_socket.StopReadRequest(fq) == 0);
            return 0;
        }

        int OnFailToConnect(WSSocket &w_socket, std::string_view http_resp) {
            printf("OnFailToConnect called, http resp:\n%s\n",
                   std::string(http_resp).c_str());
            return 0;
        }

        int OnNeedStopWriteRequest(WSSocket &w_socket) {
//            printf("OnNeedStopWriteRequest called\n");
            return w_socket.StopWriteRequest(fq);
        }

        int OnNeedRequestWrite(WSSocket &w_socket) {
            return w_socket.RequestWriteEvent(fq);
        }



        void EndClient() {
            auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            auto to_now_ns = now_ns_from_epoch - start_ns_from_epoch;
            printf("INFO! write read finish! per msg len = %zu times=%zu sendsum=%ld recvsum=%ld cost=%.3lf ms\n",
                   MAX_DATA_LEN, TOTAL_MSG_CNT, send_bytes_sum, recv_bytes_sum,
                   (double)to_now_ns / (1e+6));
//            fws::ReclaimBuf(temp_buf_);
            printf("INFO! round trip latency histogram (ns)\n");
            rtt_hist.PrintHdr(30UL);

            for (auto it = fd_to_socks.begin(); it != fd_to_socks.end(); ) {

                auto &socket = it->second.sock;
                socket.Close(fws::WS_NORMAL_CLOSE, {});
                it = fd_to_socks.erase(it);
            }

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

        int OnRecvWsPart(WSSocket &ws_socket, uint32_t opcode, fws::IOBuffer io_buf,
                         bool is_frame_end, bool is_msg_end, bool is_control_msg) {


//            printf("OnRecvWSPart called, opcode: %u, start_pos: %zu, size: %zu, cap: %zu,"
//                   "is_frame_end: %d, is_msg_end: %d, is_control_msg: %d\n",
//                   opcode, io_buf.start_pos, io_buf.size, io_buf.capacity,
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
                int client_fd = ws_socket.tcp_socket().fd();
                auto *client_ctx = &fd_to_socks[client_fd];
                auto* temp_buf_ = &client_ctx->temp_buf;

                uint8_t* FWS_RESTRICT start_data = temp_buf_->data + temp_buf_->start_pos + temp_buf_->size;
                memcpy(start_data, io_buf.data + io_buf.start_pos, io_buf.size);
                temp_buf_->size += io_buf.size;
//                cur_read_pos += io_buf.size;
                recv_bytes_sum += io_buf.size;


//                recv_status_ = {uint8_t(opcode), uint8_t(is_msg_end)};
//                buf_deque.push_back(std::move(io_buf));
//                status_deque.push_back({uint8_t(opcode), uint8_t(is_msg_end)});

                if (is_msg_end) {

                    auto read_end_tick = cpu_timer.Stop();
                    auto pass_tick = read_end_tick - start_write_tick;
                    int64_t round_trip_ns = std::llround(pass_tick * cpu_timer.ns_per_tick());
                    rtt_hist.AddValue(round_trip_ns);



                    auto client_msg_cnt = ++client_ctx->msg_cnt;
                    bool this_client_finish_all_connection = false;
                    if (client_msg_cnt == MSG_LIMIT_PER_CLIENT) {
                        int old_fd = ws_socket.tcp_socket().fd();

                        ws_socket.Close(fws::WS_NORMAL_CLOSE, {});

                        auto cur_reborn_cnt = client_ctx->reborn_cnt;
                        if FWS_LIKELY(cur_reborn_cnt < REBORN_LIMIT_FOR_CLIENT) {
                            auto new_opt_sock = NewWSClient();
                            if FWS_UNLIKELY(!new_opt_sock.has_value()) {
                                std::abort();
                            }
                            auto& new_sock = new_opt_sock.value();
                            int new_fd = new_sock.tcp_socket().fd();
//                            printf("create new client, new_fd: %d, old_fd: %d\n",
//                                   new_fd, old_fd);



                            auto old_buf = std::move(*temp_buf_);
                            fd_to_socks.erase(old_fd);

                            ++cur_reborn_cnt;

                            fd_to_socks[new_fd] = ClientCtx{std::move(new_sock),
                                                            cur_reborn_cnt, 0,
                                                            std::move(old_buf)};

                            client_ctx = &fd_to_socks[new_fd];
                            temp_buf_ = &(client_ctx->temp_buf);
                        }
                        else {
                            fd_to_socks.erase(old_fd);
                            this_client_finish_all_connection = true;
                            client_ctx = nullptr;
                        }
                    }

                    ++loop_cnt;
                    if (loop_cnt >= TOTAL_MSG_CNT) {
                        printf("loop cnt reach TOTAL_MSG_CNT, prepare to end\n");
                        EndClient();
                        return 0;
                    }
                    if (this_client_finish_all_connection) {
                        return 0;
                    }

//                    cur_read_pos = 0;

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
                               fd_to_socks.size());
                    }
                    FWS_ASSERT(is_msg_end);



                    start_write_tick = cpu_timer.Start();
                    auto &cur_sock = client_ctx->sock;
                    int writable_size = cur_sock.tcp_socket().GetWritableBytes();
                    if FWS_UNLIKELY(writable_size < 0) {
                        printf("Failed to get writable bytes, %s\n", fws::GetErrorStrP());
                        std::abort();
                    }
//                    writable_size = 0;
//                    printf("writable size: %d\n", writable_size);
//                    size_t target_size = temp_buf_->size;
//                    size_t written_size = 0;
//                    if (writable_size > 0) {
//
//                        ssize_t write_ret = cur_sock.WriteFrame(*temp_buf_, writable_size,
//                                                                 (fws::WSTxFrameType)recv_status_.opcode, true);
////                        FWS_ASSERT(write_ret >= 0);
//                        if FWS_UNLIKELY(write_ret < 0) {
//                            printf("WriteFrame return %zd, %s\n",
//                                   write_ret, fws::GetErrorStrP());
//                            std::abort();
//                        }
//                        written_size = size_t(write_ret);
//                    }
//                    send_bytes_sum += written_size;
//                    if (written_size < target_size) {
                    int request_write_ret = cur_sock.RequestWriteEvent(fq);
                    if FWS_UNLIKELY(request_write_ret < 0) {
                        printf("request write return %d, fq %d, fd %d, %s\n",
                               request_write_ret,  fq.fd,
                               cur_sock.tcp_socket().fd(), fws::GetErrorStrP());
                        std::abort();
                    }
//                        FWS_ASSERT(request_write_ret == 0);
//                    printf("Request write ret: %d\n", request_write_ret);
//                        FWS_ASSERT(cur_sock.StopReadRequest(fq) == 0);
//                    }
//                    else {
//                        *temp_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
//                        temp_buf_->start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
//
//                    }



                }
//                fws::ReclaimBuf(io_buf);
//                opcode_deque.push_back(opcode);
                if (is_msg_end) {
//                    int request_write_ret = ws_socket.RequestWriteEvent(fq);
//                    printf("Request write ret: %d\n", request_write_ret);
//                    FWS_ASSERT(ws_socket.StopReadRequest(fq) == 0);
//                    has_requested_write = true;
                }

//                ssize_t write_ret = ws_socket.WriteFrame(io_buf, io_buf.capacity, static_cast<fws::WSTxFrameType>(opcode),
//                                     is_msg_end);
//                printf("write frame return: %zd\n", write_ret);
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
            return 0;
        }



        int OnCloseConnection(WSSocket &w_socket, uint32_t status_code, std::string_view reason) {
            std::string reason_str(reason);
            printf("OnCloseConnection called, fd: %d, status_code %u, reason: %s\n",
                   w_socket.tcp_socket().fd(), status_code, reason_str.c_str());
            return 0;
        }

        int OnCleanSocket(int fd) {
            auto find_it = fd_to_socks.find(fd);
            FWS_ASSERT(find_it != fd_to_socks.end());
            fd_to_socks.erase(find_it);
            if (fd_to_socks.empty()) {
                printf("fd_to_socks empty after EOF, to end\n");
                EndClient();
            }
            return 0;
        }

        int OnWritable(WSSocket &w_socket, size_t available_size) {
//            printf("OnWritable called\n");
//            auto& buf = buf_deque.front();
            int fd = w_socket.tcp_socket().fd();
            FWS_ASSERT(fd_to_socks.find(fd) != fd_to_socks.end());
            auto& client_ctx = fd_to_socks[fd];

            auto& buf = client_ctx.temp_buf;
//            auto status = recv_status_;
//            auto status = status_deque.front();
            size_t target_size = buf.size;
//            bool fin = false;

            if (size_t(buf.size) == MAX_DATA_LEN) {
                if FWS_UNLIKELY(send_bytes_sum == 0) {
                    start_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                }
                start_write_tick = cpu_timer.Start();
            }

//            if (available_size >= target_size + fws::GetTxWSFrameHdrSize<false>(target_size)
//                && status.is_msg_end) {
//                fin = true;
//            }
//            char dis_buf[5] = {0};
//            if (buf.size > 4) {
//                memcpy(dis_buf, buf.data + buf.start_pos + buf.size - 4LL, 4);
//            }
            ssize_t write_ret = w_socket.WriteFrame(buf, available_size,
                                                    static_cast<fws::WSTxFrameType>(2U), true);
            if FWS_UNLIKELY(write_ret < 0) {
                printf("Error, write return %zd\n", write_ret);
                std::abort();
            }
            send_bytes_sum += write_ret;

//            printf("Write %zd of %zu bytes, ava size: %zu, last 4 bytes: %s\n",
//                   write_ret, target_size, available_size, dis_buf);
            if (size_t(write_ret) == target_size) {
//                buf_deque.pop_front();
//                status_deque.pop_front();
//                if (buf_deque.empty()) {
                buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
//                FWS_ASSERT(status.is_msg_end == 1);
                int stop_ret = w_socket.StopWriteRequest(fq);
                FWS_ASSERT(stop_ret >= 0);
//                FWS_ASSERT(w_socket.RequestReadEvent(fq) == 0);
//                    has_requested_write = false;
//                    if (status.is_msg_end) {
//                        w_socket.CloseCon<true>(1000, "");
//                    }

//                }
            }
            return 0;
        }

        std::optional<WSSocket> NewWSClient() {
            WSSocket ws_client{};
            int init_ret = ws_client.Init(no_delay, busy_poll_us);
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


            int client_fd = ws_client.tcp_socket().fd();
            int add_ret = fws::AddFEvent(fq, client_fd, fws::FEVAC_READ | fws::FEVAC_WRITE);

            FWS_ASSERT(add_ret == 0);

            return ws_client;
        }
    };

    using ClientContext = ContextClass<fws::WSClientSocket>;

    int OneLoop(void* FWS_RESTRICT arg) {
        ClientContext * FWS_RESTRICT ctx = (ClientContext *)arg;
        if FWS_UNLIKELY(ctx->wait_shutdown) {
            // wait for secondary process to exit
            // TODO: Add this in multiprocess test
//            std::this_thread::sleep_for(std::chrono::seconds(10));
            std::exit(0);
        }
        int num_event = fws::FEventWait(ctx->fq, nullptr, 0, ctx->wait_evs.data(), MAX_EVENT_NUM, nullptr);
        if FWS_UNLIKELY(num_event < 0) {
            printf("Feventwait ret %d, %s\n",
                   num_event, std::string(fws::GetErrorStrV()).c_str());
        }
//        if (num_event == 0) {
//            printf("Timeout!\n");
//            ctx->EndClient();
//        }
        FWS_ASSERT(num_event >= 0);
        for (int k = 0; k < num_event; ++k) {
            auto &event = ctx->wait_evs[k];
            int cur_fd = event.fd();
            auto &handler = *ctx;
//            if FWS_UNLIKELY(event.has_error()) {
//                printf("event error, flags: %u, fd: %d\n",
//                       event.socket_err_code(), cur_fd);
//                std::abort();
//            }
//            else if(event.is_eof()) {
//                // TODO: handle eof in Event Handler
////                FWS_ASSERT(cur_fd != ctx->ws_server.tcp_socket().fd());
//                int error_code = event.socket_err_code();
//                printf("Client exit. fd=%d for eof, errno = %d\n",
//                       cur_fd, error_code);
//                auto find_it = ctx->fd_to_socks.find(cur_fd);
//                if (find_it != ctx->fd_to_socks.end()) {
//                    find_it->second.sock.Close(fws::WS_ABNORMAL_CLOSE, {});
//                    ctx->fd_to_socks.erase(find_it);
//                }
//                if (ctx->fd_to_socks.empty()) {
//                    printf("fd_to_socks empty after EOF, to end\n");
//                    ctx->EndClient();
//                }
//
////                ctx->EndClient();
////                std::exit(0);
//            }
//            else
            {
//                if (event.filter == fws::FEVFILT_READ) {
//#ifdef FWS_DEV_DEBUG
//                    size_t available_size = size_t(event.data);
//                    fprintf(stderr, "read event, readable size: %zu\n",
//                            available_size);
//#endif
//                }
                auto find_it = ctx->fd_to_socks.find(cur_fd);
                if FWS_UNLIKELY(find_it == ctx->fd_to_socks.end()) {
                    printf("Didnt find fd %d in fd_to_socks, maybe in the end,"
                           "map has %zu elements\n",
                           cur_fd, ctx->fd_to_socks.size());
                    continue;
                }
                auto& FWS_RESTRICT ws_socket = find_it->second.sock;

                int ret = ws_socket.HandleFEvent(event, handler);
                if (ret < 0) {
                    printf("socket handle event return %d\n", ret);
                    printf("%s\n", fws::GetErrorStrV().data());
                    std::abort();
                }
            }
        }
        return 0;
    }


    int TestWsServer(int argc, char** argv) {

        if (argc < 8) {
            printf("Invalid parameters!\nUsage: ./echo_client ip_addr port"
                   " msg_len msg_cnt_per_client client_cnt client_reborn_cnt"
                   " output_data_filename\n");
            return -1;
        }

        const char* SERVER_IP = argv[1];


        int SERVER_PORT = atoi(argv[2]);
        if (SERVER_PORT <= 0) {
            printf("Invalid port: %s\n", argv[2]);
            return -1;
        }
        long long max_msg_len = atoll(argv[3]);
        if (max_msg_len <= 0) {
            printf("invalid msg_len: %s\n", argv[3]);
            return -1;
        }
        MAX_DATA_LEN = size_t(max_msg_len);

        long long msg_cnt_per_c = atoll(argv[4]);
        if (msg_cnt_per_c <= 0) {
            printf("invalid msg_cnt_per_client: %s\n", argv[4]);
            return -1;
        }

        MSG_LIMIT_PER_CLIENT = msg_cnt_per_c;
//        TEST_TIMES = size_t(msg_cnt_per_c);


        int client_cnt = atoi(argv[5]);
        if (client_cnt <= 0) {
            printf("invalid client_cnt: %s\n", argv[5]);
            return -1;
        }

        CON_CLIENT_NUM = client_cnt;

        int client_reborn_time = atoi(argv[6]);
        if (client_reborn_time <= 0) {
            printf("invalid client_reborn_cnt: %s\n", argv[6]);
            return -1;
        }
        REBORN_LIMIT_FOR_CLIENT = client_reborn_time;

        TOTAL_MSG_CNT = msg_cnt_per_c * client_cnt * client_reborn_time;

        const char* data_file_path = argv[7];

//        printf("Set host: %s, port: %d, msg_size: %zu, msg_cnt_per_client: %lld,"
//               "data file path: %s\n",
//               SERVER_IP, SERVER_PORT, MAX_DATA_LEN, msg_cnt_per_c, data_file_path);

        FWS_ASSERT(fws::InitEnv(argc - 7, argv + 7) >= 0);

        printf("Set host: %s, port: %d, msg_size: %zu, msg_cnt_per_client: %lld,"
               "data file path: %s\n",
               SERVER_IP, SERVER_PORT, MAX_DATA_LEN, msg_cnt_per_c, data_file_path);

        FILE* output_fp = fopen(data_file_path, "a");
        if (output_fp == nullptr) {
            printf("Failed to open %s, %s\n", data_file_path, std::strerror(errno));
            return -1;
        }

        std::string request_uri = "/";
        std::string host = std::string(SERVER_IP) + ":" + std::to_string(SERVER_PORT);

        ContextClass<fws::WSClientSocket> ctx{
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
        auto fq = fws::CreateFQueue();
        ctx.fq = std::move(fq);

        ctx.no_delay = false;
        ctx.busy_poll_us = 0;
#if ENABLE_NO_DELAY
        ctx.no_delay = true;
#endif
        if (USE_BUSY_POLL) {
            ctx.busy_poll_us = BUSY_POLL_US;
        }

        for (int k = 0; k < client_cnt; ++k) {
            auto opt_ws_client = ctx.NewWSClient();
            if FWS_UNLIKELY(!opt_ws_client.has_value()) {
                return -1;
            }
            fws::WSClientSocket ws_client = std::move(opt_ws_client.value());




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
            printf("data hash: %lu\n", ctx.data_hash);
            int client_fd = ws_client.tcp_socket().fd();
            ctx.fd_to_socks.emplace(client_fd, ClientContext::ClientCtx{
                    std::move(ws_client),
                    1, 0, std::move(temp_buf) });

        }
//        ctx.client_fd = client_fd;

//        ctx.fd_to_socks[client_fd] = std::move(ws_client);
        ctx.wait_evs = {MAX_EVENT_NUM, fws::FEvent()};
//        ctx.recv_status_ = {uint8_t(2), uint8_t(1)};
        ctx.out_fp = output_fp;
        printf("start to run loop\n");
        fws::StartRunLoop(OneLoop, &ctx);
        return 0;

    }

} // namespace test


int main(int argc, char** argv) {
    return test::TestWsServer(argc, argv);
}