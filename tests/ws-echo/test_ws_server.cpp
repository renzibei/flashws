#include "flashws/net/ws_server.h"
#include "flashws/flashws.h"
#include "test_def.h"
#include <deque>
#include <chrono>

namespace test {


    size_t MAX_DATA_LEN = 0;
    constexpr size_t MAX_EVENT_NUM = MAX_SERVER_EVENT_NUM;

    struct Context {
        fws::FQueue fq;
        fws::WsServer ws_server;

        struct BufferStatus {
            uint8_t opcode;
            uint8_t is_msg_end;
        };

        struct ConnectCtx {
            fws::WSServerSocket socket;
            fws::IOBuffer io_buf;
            BufferStatus status;
        };

        ska::flat_hash_map<int, ConnectCtx> fd_to_socks;

//        fws::IOBuffer io_buf_;

//        std::deque<fws::IOBuffer, fws::FlashAllocator<fws::IOBuffer>> buf_deque;

//        bool has_requested_write = false;
//        BufferStatus recv_status_;
//        std::deque<BufferStatus, fws::FlashAllocator<uint32_t>> status_deque;
        std::vector<fws::FEvent> wait_evs;
        uint64_t last_interval_send_bytes = 0;
        uint64_t last_interval_recv_bytes = 0;
        uint64_t last_interval_recv_msg_cnt = 0;
        uint64_t last_interval_send_msg_cnt = 0;
        size_t last_msg_size = 0;
        int64_t interval_start_ns = 0;
        FILE* output_fp = nullptr;

        // New tcp connection accepted
        int OnNewTcpConnection(fws::WSServerSocket &w_socket) {
            int fd =  w_socket.tcp_socket().fd();
//            printf("OnNewTcpConnection called, fd: %d\n", fd);
            auto new_buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
            new_buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
            fd_to_socks[fd] = {std::move(w_socket), std::move(new_buf), {}};
#ifdef FWS_DEV_DEBUG
            fprintf(stderr, "OnNewTcpConnection called, now fd map have %zu fds\n",
                    fd_to_socks.size());

#endif
            return 0;
        }

        // New WS connect request, return 0 if approve

        int OnNewWsConnection(fws::WSServerSocket &w_socket, std::string_view req_uri,
                              std::string_view host, std::string_view origin,
                              std::string_view sub_protocols,
                              std::string_view extensions,
                              std::string_view &resp_sub_protocol,
                              std::string_view &resp_extensions) {
//            printf("OnNewWsConnection called, req_uri: %s, host: %s\n",
//                   std::string(req_uri).c_str(), std::string(host).c_str());
            std::string sub_protocols_str(sub_protocols);
            std::string extensions_str(extensions);
//            printf("Client provide protocols: %s, extensions: %s\n",
//                   sub_protocols_str.c_str(),
//                   extensions_str.c_str());
            return 0;
        }

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
                   fd_to_socks.size());
            if (output_fp != nullptr) {
                // msg_size, rx goodput, tx goodput, rx mm mps, tx mm mps, connection cnt
                fprintf(output_fp, "%zu,%.3lf,%.3lf,%lf,%lf,%zu\n",
                        last_msg_size,
                        recv_throughput_mbps,
                        send_throughput_mbps,
                        recv_mm_msg_per_sec,
                        send_mm_msg_per_sec,
                        fd_to_socks.size()
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

        int OnRecvWsPart(fws::WSServerSocket &ws_socket, uint32_t opcode, fws::IOBuffer io_buf,
                         bool is_frame_end, bool is_msg_end, bool is_control_msg) {


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
//                for (size_t i = 0; i < io_buf.size; ++i) {
//                    FWS_ASSERT(std::isalnum(data[i]))
//                }
                auto find_it = fd_to_socks.find(ws_socket.tcp_socket().fd());
                FWS_ASSERT(find_it != fd_to_socks.end());
                auto& FWS_RESTRICT con_ctx = find_it->second;
                auto & FWS_RESTRICT io_buf_ = con_ctx.io_buf;
                memcpy(io_buf_.data + io_buf_.start_pos + io_buf_.size, data, io_buf.size);
                io_buf_.size += io_buf.size;
                if FWS_UNLIKELY(interval_start_ns == 0) {
                    interval_start_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
                }

                last_interval_recv_bytes += io_buf.size;

//                fws::ReclaimBuf(io_buf);

                fd_to_socks[ws_socket.tcp_socket().fd()].status = {uint8_t(opcode), uint8_t(is_msg_end)};
//                recv_status_ = {uint8_t(opcode), uint8_t(is_msg_end)};
//                buf_deque.push_back(std::move(io_buf));
//                status_deque.push_back({uint8_t(opcode), uint8_t(is_msg_end)});
//                opcode_deque.push_back(opcode);
//                if (!has_requested_write) {
                if (is_msg_end) {
                    ++last_interval_recv_msg_cnt;
                    last_msg_size = io_buf_.size;
//                    if FWS_UNLIKELY(io_buf_.size != MAX_DATA_LEN) {
//                        printf("io_buf_.size = %zu, MAX_DATA_LEN = %zu\n",
//                               io_buf_.size, MAX_DATA_LEN);
////                        std::abort();
//                    }
//                    FWS_ASSERT(io_buf_.size == MAX_DATA_LEN);

                    int writable_size = ws_socket.tcp_socket().GetWritableBytes();
                    if FWS_UNLIKELY(writable_size < 0) {
                        printf("Failed to get writable bytes, %s\n", fws::GetErrorStrP());
                        std::abort();
                    }
                    size_t target_size = io_buf_.size;
                    size_t written_size = 0;
                    if (writable_size > 0) {
                        ssize_t write_ret = ws_socket.WriteFrame(*this, io_buf_, writable_size,
                                                                 (fws::WSTxFrameType)con_ctx.status.opcode, true);
                        FWS_ASSERT(write_ret >= 0);
                        written_size = size_t(write_ret);
                    }
                    last_interval_send_bytes += written_size;

                    if (written_size < target_size) {
                        int request_write_ret = ws_socket.RequestWriteEvent(fq);
                        FWS_ASSERT(request_write_ret == 0);
//                    printf("Request write ret: %d\n", request_write_ret);
//                        has_requested_write = true;
                    }
                    else {
                        ++last_interval_send_msg_cnt;
                        CountStats();
                        io_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                        io_buf_.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
                    }

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



        int OnCloseConnection(fws::WSServerSocket &w_socket, uint32_t status_code, std::string_view reason) {
            if (status_code != 1000U) {
                std::string reason_str(reason);
                printf("OnCloseConnection called, fd: %d, status_code %u, reason: %s\n",
                       w_socket.tcp_socket().fd(), status_code, reason_str.c_str());
            }
            int fd = w_socket.tcp_socket().fd();
            auto find_it = fd_to_socks.find(fd);
            FWS_ASSERT(find_it != fd_to_socks.end());
//            fd_to_socks.erase(find_it);
            return 0;
        }

        int OnCleanSocket(int fd) {
            auto find_it = fd_to_socks.find(fd);
            FWS_ASSERT(find_it != fd_to_socks.end());
            fd_to_socks.erase(find_it);
            return 0;
        }

//        int OnWritable(fws::WSServerSocket &w_socket, size_t available_size) {
////            printf("Shouldn't be called\n");
////            auto find_it = fd_to_socks.find(w_socket.tcp_socket().fd());
////            FWS_ASSERT(find_it != fd_to_socks.end());
//////            printf("OnWritable called, fd %d\n", w_socket.tcp_socket().fd());
////            auto& con_ctx = find_it->second;
//////            auto &buf = io_buf_;
////            auto &buf = con_ctx.io_buf;
//////            auto& buf = buf_deque.front();
//////            auto status = status_deque.front();
////            size_t target_size = buf.size;
//////            bool fin = false;
//////            if (available_size >= target_size + fws::GetTxWSFrameHdrSize<false>(target_size)
////////                && status.is_msg_end
//////                ) {
//////                fin = true;
//////            }
////            // TODO: Test the hash of client
//////            buf.data[buf.start_pos + buf.size - 4] = 0x8a;
////            ssize_t write_ret = w_socket.WriteFrame(*this, buf, available_size,
////                                                    static_cast<fws::WSTxFrameType>(con_ctx.status.opcode), true);
////            if (write_ret < 0) {
////                printf("Error, write return %zd\n", write_ret);
////                std::abort();
////            }
////
////            last_interval_send_bytes += write_ret;
////
//////            printf("Write %zd of %zu bytes, ava size: %zu\n",
//////                   write_ret, target_size, available_size);
////
////            if (size_t(write_ret) == target_size) {
////
//////                buf_deque.pop_front();
//////                status_deque.pop_front();
//////                if (buf_deque.empty()) {
////                ++last_interval_send_msg_cnt;
////                CountStats();
////                buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
////                buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
////                int stop_ret = w_socket.StopWriteRequest(fq);
////                FWS_ASSERT(stop_ret >= 0);
//////                has_requested_write = false;
//////                    if (status.is_msg_end) {
//////                        w_socket.CloseCon<true>(1000, "");
//////                    }
////
//////                }
////            }
//            return 0;
//        }

        int OnNeedRequestWrite(fws::WSServerSocket &w_socket) {
            return w_socket.RequestWriteEvent(fq);
        }

        int OnNeedStopWriteRequest(fws::WSServerSocket &w_socket) {
//            printf("OnNeedStopWriteRequest called\n");
            return w_socket.StopWriteRequest(fq);
        }
    };

    int OneLoop(void* arg) {
        Context* FWS_RESTRICT ctx = (Context*)arg;
        int num_event = fws::FEventWait(ctx->fq, nullptr, 0, ctx->wait_evs.data(), MAX_EVENT_NUM, nullptr);
        if FWS_UNLIKELY(num_event < 0) {
            printf("feventwait return %d, %s\n",
                   num_event, std::string(fws::GetErrorStrV()).c_str());
        }
        FWS_ASSERT(num_event >= 0);
        for (int k = 0; k < num_event; ++k) {
            auto &event = ctx->wait_evs[k];
            int cur_fd = event.fd();
            auto &handler = *ctx;
//            if FWS_UNLIKELY(event.has_error()) {
//                int error_code = event.socket_err_code();
//                printf("event error, flags: %u, fd: %d\n",
//                       error_code, cur_fd);
//                printf("%s\n", std::strerror(error_code));
//                std::abort();
//            }
//            else if(event.is_eof()) {
//                // TODO: handle close in EventHandler
//                FWS_ASSERT(cur_fd != ctx->ws_server.tcp_socket().fd());
//                auto find_it = ctx->fd_to_socks.find(cur_fd);
//                FWS_ASSERT(find_it != ctx->fd_to_socks.end());
//                int error_code = event.socket_err_code();
//                printf("Client exit. fd=%d error=%d, for eof\n",
//                       cur_fd, error_code);
//                find_it->second.socket.Close(*ctx, fws::WS_ABNORMAL_CLOSE, {});
//                ctx->fd_to_socks.erase(find_it);
//            }
            if (cur_fd == ctx->ws_server.tcp_socket().fd()) {
//                printf("One event with ws server fd\n");
                int ret = ctx->ws_server.HandleFEvent(ctx->fq, event, handler);
                if (ret < 0) {
                    printf("WS server handle event return %d\n, %s",
                           ret, fws::GetErrorStrP());
                }
            }
            else {
#ifdef FWS_DEV_DEBUG
                //                size_t available_size = size_t(event.data);
//                fprintf(stderr, "fd %d read event, readable size: %zu\n",
//                        cur_fd, available_size);
#endif
                auto find_it = ctx->fd_to_socks.find(cur_fd);
                FWS_ASSERT(find_it != ctx->fd_to_socks.end());
                auto& FWS_RESTRICT ws_socket = find_it->second.socket;
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

        if (argc < 5) {
            printf("Invalid parameters!\nUsage: ./echo_server ip_address port max_msg_len export_filename\n");
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
            printf("invalid max_msg_len: %s\n", argv[3]);
            return -1;
        }
        MAX_DATA_LEN = size_t(max_msg_len);

        const char* export_file_path = argv[4];


        fws::InitEnv(argc - 3, argv + 3);
#if ENABLE_NO_DELAY
        constexpr bool no_delay = true;
#else
        constexpr bool no_delay = false;
#endif
        int busy_poll_us = 0;
        if constexpr(USE_BUSY_POLL) {
            busy_poll_us = BUSY_POLL_US;
        }
        fws::WsServer ws_server{no_delay, busy_poll_us};
//        const char* const listen_addr = "10.5.96.7";
        int listen_ret = ws_server.StartListen(SERVER_IP, SERVER_PORT,
                                               LISTEN_BACKLOG, fws::TcpSocket::REUSE_ADDR_MODE);
        if (listen_ret < 0) {
            printf("Failed to listen, return %d, %s\n", listen_ret,
                   std::string(fws::GetErrorStrV()).c_str());
            return listen_ret;
        }
        auto fq = fws::CreateFQueue();
        int add_read_ret = fws::AddFEvent(fq, ws_server.tcp_socket().fd(), fws::FEVAC_READ);
        FWS_ASSERT(add_read_ret == 0);
//        fws::FEvent read_ev(ws_server.tcp_socket().fd(), fws::FEVFILT_READ,
//                            fws::FEV_ADD,
//                            fws::FEFFLAG_NONE, 0, nullptr);
//        if (fws::FEventWait(fq, &read_ev, 1, nullptr, 0, nullptr) < 0) {
//            printf("Failed to add read event\n");
//            return -1;
//        }
        Context ctx{};

        ctx.output_fp = fopen(export_file_path, "w");
        if (ctx.output_fp == nullptr) {
            printf("Cannot create file at %s\n", export_file_path);
            return -1;
        }
        printf("Will output to %s\n", export_file_path);
        // msg_size, rx goodput, tx goodput, rx mm mps, tx mm mps
        fprintf(ctx.output_fp, "msg_size,rx_goodput,tx_goodput,rx_mm_mps,tx_mm_mps,connection_cnt\n");

        ctx.ws_server = std::move(ws_server);
        ctx.fq = std::move(fq);
        ctx.wait_evs = {MAX_EVENT_NUM, fws::FEvent()};
//        ctx.io_buf_ = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
//        ctx.io_buf_.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
//        ctx.recv_status_ = {1U, 1U};
        printf("start to run loop\n");
        fws::StartRunLoop(OneLoop, &ctx);
        return 0;

    }

} // namespace test


int main(int argc, char** argv) {
    return test::TestWsServer(argc, argv);
}