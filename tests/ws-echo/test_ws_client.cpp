#include "flashws/net/ws_client_socket.h"
#include "flashws/flashws.h"
#include "flashws/utils/histogram_wrapper.h"
#include "flashws/utils/cpu_timer.h"
#include "test_def.h"
#include <deque>

namespace test {




    template<class WSSocket>
    struct ContextClass {
        hist::HistWrapper rtt_hist;
        fws::FQueue fq;
        cpu_t::CpuTimer<uint64_t> cpu_timer{};
        ska::flat_hash_map<int, WSSocket> fd_to_socks;

        size_t cur_read_pos = 0;

        fws::IOBuffer temp_buf_;
//        fws::IOBuffer io_buf;
//        std::deque<fws::IOBuffer, fws::FlashAllocator<fws::IOBuffer>> buf_deque;
        struct BufferStatus {
            uint8_t opcode;
            uint8_t is_msg_end;
        };
        BufferStatus recv_status_;

        int client_fd = 0;

//        bool has_requested_write = false;
        size_t data_hash;
        uint64_t loop_cnt = 0;
        int64_t send_bytes_sum = 0;
        int64_t recv_bytes_sum = 0;
        uint64_t start_write_tick;

        int64_t start_ns_from_epoch = 0;
        bool wait_shutdown = false;
        fws::FEvent wait_evs[MAX_EVENT_NUM];
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
            printf("OnConnected called\n");
            std::string sub_protocols_str(resp_sub_protocol);
            std::string extensions_str(resp_extensions);
            printf("Server accept protocols: %s, extensions: %s\n",
                   sub_protocols_str.c_str(),
                   extensions_str.c_str());
            FWS_ASSERT(w_socket.RequestWriteEvent(fq) == 0);
            FWS_ASSERT(w_socket.StopReadRequest(fq) == 0);
            return 0;
        }

        int OnFailToConnect(WSSocket &w_socket, std::string_view http_resp) {
            printf("OnFailToConnect called, http resp:\n%s\n",
                   std::string(http_resp).c_str());
            return 0;
        }

        int OnNeedStopWriteRequest(WSSocket &w_socket) {
            printf("OnNeedStopWriteRequest called\n");
            return w_socket.StopWriteRequest(fq);
        }

        void EndClient() {
            auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            auto to_now_ns = now_ns_from_epoch - start_ns_from_epoch;
            printf("INFO! write read finish! per msg len = %zu times=%zu sendsum=%ld recvsum=%ld cost=%.3lf ms\n",
                   MAX_DATA_LEN, TEST_TIMES, send_bytes_sum, recv_bytes_sum,
                   (double)to_now_ns / (1e+6));
//            fws::ReclaimBuf(temp_buf_);
            printf("INFO! round trip latency histogram (ns)\n");
            rtt_hist.PrintHdr(30UL);

            auto &socket = fd_to_socks[client_fd];
            socket.Close(fws::WS_NORMAL_CLOSE, {});
            wait_shutdown = true;
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


                uint8_t* FWS_RESTRICT start_data = temp_buf_.data + temp_buf_.start_pos + temp_buf_.size;
                memcpy(start_data, io_buf.data + io_buf.start_pos, io_buf.size);
                temp_buf_.size += io_buf.size;
                cur_read_pos += io_buf.size;
                recv_bytes_sum += io_buf.size;


                recv_status_ = {uint8_t(opcode), uint8_t(is_msg_end)};
//                buf_deque.push_back(std::move(io_buf));
//                status_deque.push_back({uint8_t(opcode), uint8_t(is_msg_end)});

                if (cur_read_pos == MAX_DATA_LEN) {

                    auto read_end_tick = cpu_timer.Stop();
                    auto pass_tick = read_end_tick - start_write_tick;
                    int64_t round_trip_ns = std::llround(pass_tick * cpu_timer.ns_per_tick());
                    rtt_hist.AddValue(round_trip_ns);

                    cur_read_pos = 0;
                    ++loop_cnt;
                    if FWS_UNLIKELY(!(loop_cnt & 0xfffUL)) {
                        size_t temp_hash = HashArr(temp_buf_.data + temp_buf_.start_pos, temp_buf_.size);
//                        size_t temp_hash = HashBufArr(buf_deque.begin(), buf_deque.end());
                        double round_trip_us = double(round_trip_ns) / 1000.0;
                        constexpr int64_t BITS_PER_BYTE = 8;
                        auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
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
                               "rx + tx: %.2lf Mbit/s, hash value: %zu\n",
                               round_trip_us, avg_recv_throughput_mbps +
                               avg_send_throughput_mbps,temp_hash);
                    }
                    FWS_ASSERT(is_msg_end);

                    start_write_tick = cpu_timer.Start();
                    int writable_size = ws_socket.tcp_socket().GetWritableBytes();
                    if FWS_UNLIKELY(writable_size < 0) {
                        printf("Failed to get writable bytes, %s\n", fws::GetErrorStrP());
                        std::abort();
                    }
//                    printf("writable size: %d\n", writable_size);
                    size_t target_size = temp_buf_.size;
                    size_t written_size = 0;
                    if (writable_size > 0) {

                        ssize_t write_ret = ws_socket.WriteFrame(temp_buf_, writable_size,
                                         (fws::WSTxFrameType)recv_status_.opcode, true);
                        FWS_ASSERT(write_ret >= 0);
                        written_size = size_t(write_ret);
                    }
                    send_bytes_sum += target_size;
                    if (written_size < target_size) {
                        int request_write_ret = ws_socket.RequestWriteEvent(fq);
                        FWS_ASSERT(request_write_ret == 0);
//                    printf("Request write ret: %d\n", request_write_ret);
                        FWS_ASSERT(ws_socket.StopReadRequest(fq) == 0);
                    }
                    else {
                        temp_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                        temp_buf_.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;

                    }


                    if (loop_cnt >= TEST_TIMES) {
                        EndClient();
                        return 0;
                    }
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

        int OnWritable(WSSocket &w_socket, size_t available_size) {
//            printf("OnWritable called\n");
//            auto& buf = buf_deque.front();
            auto& buf = temp_buf_;
            auto status = recv_status_;
//            auto status = status_deque.front();
            size_t target_size = buf.size;
            bool fin = false;

            if (temp_buf_.size == MAX_DATA_LEN) {
                if FWS_UNLIKELY(send_bytes_sum == 0) {
                    start_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                }
                start_write_tick = cpu_timer.Start();
            }

            if (available_size >= target_size + fws::GetTxWSFrameHdrSize<false>(target_size)
                    && status.is_msg_end) {
                fin = true;
            }
//            char dis_buf[5] = {0};
//            if (buf.size > 4) {
//                memcpy(dis_buf, buf.data + buf.start_pos + buf.size - 4LL, 4);
//            }
            ssize_t write_ret = w_socket.WriteFrame(buf, available_size,
                                static_cast<fws::WSTxFrameType>(status.opcode), fin);
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
                temp_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                temp_buf_.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
                    FWS_ASSERT(status.is_msg_end == 1);
                    int stop_ret = w_socket.StopWriteRequest(fq);
                    FWS_ASSERT(stop_ret >= 0);
                    FWS_ASSERT(w_socket.RequestReadEvent(fq) == 0);
//                    has_requested_write = false;
//                    if (status.is_msg_end) {
//                        w_socket.CloseCon<true>(1000, "");
//                    }

//                }
            }
            return 0;
        }
    };

    using ClientContext = ContextClass<fws::WSClientSocket>;

    int OneLoop(void* FWS_RESTRICT arg) {
        ClientContext * FWS_RESTRICT ctx = (ClientContext *)arg;
        if FWS_UNLIKELY(ctx->wait_shutdown) {
            std::exit(0);
        }
        int num_event = fws::FEventWait(ctx->fq, nullptr, 0, ctx->wait_evs, MAX_EVENT_NUM, nullptr);
        if FWS_UNLIKELY(num_event < 0) {
            printf("Feventwait ret %d, %s\n",
                   num_event, std::string(fws::GetErrorStrV()).c_str());
        }
        FWS_ASSERT(num_event >= 0);
        for (int k = 0; k < num_event; ++k) {
            auto &event = ctx->wait_evs[k];
            int cur_fd = (int)event.ident;
            auto &handler = *ctx;
            if FWS_UNLIKELY(event.flags & fws::FEV_ERROR) {
                printf("event error, flags: %u, fd: %d\n",
                       event.flags, cur_fd);
                std::abort();
            }
            else if(event.flags & fws::FEV_EOF) {
//                FWS_ASSERT(cur_fd != ctx->ws_server.tcp_socket().fd());
                printf("Client exit. fd=%d\n", cur_fd);

                ctx->fd_to_socks[cur_fd].Close(fws::WS_ABNORMAL_CLOSE, {});
            }
            else {
//                if (event.filter == fws::FEVFILT_READ) {
//#ifdef FWS_DEV_DEBUG
//                    size_t available_size = size_t(event.data);
//                    fprintf(stderr, "read event, readable size: %zu\n",
//                            available_size);
//#endif
//                }
                auto& FWS_RESTRICT ws_socket = ctx->fd_to_socks[cur_fd];
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
        FWS_ASSERT(fws::InitEnv(argc, argv) >= 0);
//        fws::WsServer ws_server{};
//        const char* const listen_addr = "10.5.96.3";
//        const char* const listen_addr = "10.5.96.7";
//        uint16_t port = 58600;
        fws::WSClientSocket ws_client{};
        bool no_delay = false;
        int busy_poll_us = 0;
#if ENABLE_NO_DELAY
        no_delay = true;
#endif
        if (USE_BUSY_POLL) {
            busy_poll_us = BUSY_POLL_US;
        }
        int init_ret = ws_client.Init(no_delay, busy_poll_us);
        if FWS_UNLIKELY(init_ret < 0) {
            printf("ws_client init return %d, %s\n",
                   init_ret, std::string(fws::GetErrorStrV()).c_str());
            return -1;
        }


        {
            std::string request_uri = "/";
            std::string host = std::string(SERVER_IP) + ":" + std::to_string(SERVER_PORT);
            int con_ret = ws_client.Connect(SERVER_IP, SERVER_PORT, request_uri, host);
            if (con_ret < 0 && errno != EINPROGRESS) {
                printf("Error in connect, return %d, %s\n",
                       con_ret, std::string(fws::GetErrorStrV()).c_str());

                return -1;
            }
        }

        ContextClass<fws::WSClientSocket> ctx{hist::HistWrapper(TEST_TIMES + 2, 1LL, 10000000LL)};
        printf("CpuTimer overhead cycles: %lu cycles, tick per ns: %lf\n",
               ctx.cpu_timer.overhead_ticks(), 1.0 / ctx.cpu_timer.ns_per_tick());
        constexpr size_t RESERVE_SIZE = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
        auto temp_buf = fws::RequestBuf(MAX_DATA_LEN + RESERVE_SIZE);
        temp_buf.start_pos = RESERVE_SIZE;
        for (size_t i = 0; i < MAX_DATA_LEN; ++i) {
            temp_buf.data[RESERVE_SIZE + i] = rand() % 10 + '0';
        }
        temp_buf.size = MAX_DATA_LEN;
        ctx.data_hash = ctx.HashArr(temp_buf.data + temp_buf.start_pos, temp_buf.size);
        ctx.temp_buf_ = std::move(temp_buf);
//        ctx.data_hash = ctx.HashBufArr(&temp_buf, &temp_buf + 1);
//        ctx.buf_deque.push_back(std::move(temp_buf));
//        ctx.status_deque.push_back({1U, 1U});
        printf("data hash: %lu\n", ctx.data_hash);
        int client_fd = ws_client.tcp_socket().fd();
        fws::FEvent temp_events[2] = {
                fws::FEvent(client_fd, fws::FEVFILT_WRITE, fws::FEV_ADD, fws::FEFFLAG_NONE, MAX_EVENT_NUM, nullptr),
                fws::FEvent(client_fd, fws::FEVFILT_READ, fws::FEV_ADD, fws::FEFFLAG_NONE, MAX_EVENT_NUM, nullptr),
        };

        auto fq = fws::CreateFQueue();
        if (fws::FEventWait(fq, temp_events, 2, nullptr, 0, nullptr) < 0) {
            printf("Failed to add read event, %s\n",
                   std::string(fws::GetErrorStrV()).c_str());
            return -1;
        }
        ctx.client_fd = client_fd;
        ctx.fq = std::move(fq);
        ctx.fd_to_socks[client_fd] = std::move(ws_client);
        ctx.recv_status_ = {uint8_t(1), uint8_t(1)};
        printf("start to run loop\n");
        fws::StartRunLoop(OneLoop, &ctx);
        return 0;

    }

} // namespace test


int main(int argc, char** argv) {
    return test::TestWsServer(argc, argv);
}