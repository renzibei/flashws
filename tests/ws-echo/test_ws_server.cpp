#include "flashws/net/ws_server.h"
#include "flashws/flashws.h"
#include "test_def.h"
#include <deque>

namespace test {




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

        bool has_requested_write = false;
//        BufferStatus recv_status_;
//        std::deque<BufferStatus, fws::FlashAllocator<uint32_t>> status_deque;
        std::vector<fws::FEvent> wait_evs;

        // New tcp connection accepted
        int OnNewTcpConnection(fws::WSServerSocket &w_socket) {
            int fd = w_socket.tcp_socket().fd();
            printf("OnNewTcpConnection called, fd: %d\n", fd);
            auto new_buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
            new_buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;

            fd_to_socks[fd] = {std::move(w_socket), std::move(new_buf), {}};
            return 0;
        }

        // New WS connect request, return 0 if approve

        int OnNewWsConnection(fws::WSServerSocket &w_socket, std::string_view req_uri,
                              std::string_view host, std::string_view origin,
                              std::string_view sub_protocols,
                              std::string_view extensions,
                              std::string_view &resp_sub_protocol,
                              std::string_view &resp_extensions) {
            printf("OnNewWsConnection called, req_uri: %s, host: %s\n",
                   std::string(req_uri).c_str(), std::string(host).c_str());
            std::string sub_protocols_str(sub_protocols);
            std::string extensions_str(extensions);
            printf("Client provide protocols: %s, extensions: %s\n",
                   sub_protocols_str.c_str(),
                   extensions_str.c_str());
            return 0;
        }



        int OnRecvWsPart(fws::WSServerSocket &ws_socket, uint32_t opcode, fws::IOBuffer io_buf,
                         bool is_frame_end, bool is_msg_end, bool is_control_msg) {


//            printf("OnRecvWSPart called, fd: %d, opcode: %u, start_pos: %zu, size: %zu, cap: %zu,"
//                   "is_frame_end: %d, is_msg_end: %d, is_control_msg: %d\n",
//                   ws_socket.tcp_socket().fd(), opcode, io_buf.start_pos, io_buf.size, io_buf.capacity,
//                   is_frame_end, is_msg_end, is_control_msg);
            if (!is_control_msg) {
                constexpr size_t MAX_DISPLAY_LEN = 128;
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
                auto& FWS_RESTRICT con_ctx = fd_to_socks[ws_socket.tcp_socket().fd()];
                auto & FWS_RESTRICT io_buf_ = con_ctx.io_buf;
                memcpy(io_buf_.data + io_buf_.start_pos + io_buf_.size, data, io_buf.size);
                io_buf_.size += io_buf.size;
//                fws::ReclaimBuf(io_buf);

                fd_to_socks[ws_socket.tcp_socket().fd()].status = {uint8_t(opcode), uint8_t(is_msg_end)};
//                recv_status_ = {uint8_t(opcode), uint8_t(is_msg_end)};
//                buf_deque.push_back(std::move(io_buf));
//                status_deque.push_back({uint8_t(opcode), uint8_t(is_msg_end)});
//                opcode_deque.push_back(opcode);
//                if (!has_requested_write) {
                if (is_msg_end) {
                    if FWS_UNLIKELY(io_buf_.size != MAX_DATA_LEN) {
                        printf("io_buf_.size = %zu, MAX_DATA_LEN = %zu\n",
                               io_buf_.size, MAX_DATA_LEN);
//                        std::abort();
                    }
                    FWS_ASSERT(io_buf_.size == MAX_DATA_LEN);
                    int writable_size = ws_socket.tcp_socket().GetWritableBytes();
                    if FWS_UNLIKELY(writable_size < 0) {
                        printf("Failed to get writable bytes, %s\n", fws::GetErrorStrP());
                        std::abort();
                    }
                    size_t target_size = io_buf_.size;
                    size_t written_size = 0;
                    if (writable_size > 0) {
                        ssize_t write_ret = ws_socket.WriteFrame(io_buf_, writable_size,
                                         (fws::WSTxFrameType)con_ctx.status.opcode, true);
                        FWS_ASSERT(write_ret >= 0);
                        written_size = size_t(write_ret);
                    }
                    if (written_size < target_size) {
                        int request_write_ret = ws_socket.RequestWriteEvent(fq);
                        FWS_ASSERT(request_write_ret == 0);
//                    printf("Request write ret: %d\n", request_write_ret);
                        has_requested_write = true;
                    }
                    else {
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
            std::string reason_str(reason);
            printf("OnCloseConnection called, fd: %d, status_code %u, reason: %s\n",
                   w_socket.tcp_socket().fd(), status_code, reason_str.c_str());
            return 0;
        }

        int OnWritable(fws::WSServerSocket &w_socket, size_t available_size) {
//            printf("OnWritable called, fd %d\n", w_socket.tcp_socket().fd());
            auto& con_ctx = fd_to_socks[w_socket.tcp_socket().fd()];
//            auto &buf = io_buf_;
            auto &buf = con_ctx.io_buf;
//            auto& buf = buf_deque.front();
//            auto status = status_deque.front();
            size_t target_size = buf.size;
//            bool fin = false;
//            if (available_size >= target_size + fws::GetTxWSFrameHdrSize<false>(target_size)
////                && status.is_msg_end
//                ) {
//                fin = true;
//            }
            // TODO: Test the hash of client
//            buf.data[buf.start_pos + buf.size - 4] = 0x8a;
            ssize_t write_ret = w_socket.WriteFrame(buf, available_size,
                                static_cast<fws::WSTxFrameType>(con_ctx.status.opcode), true);
            if (write_ret < 0) {
                printf("Error, write return %zd\n", write_ret);
                std::abort();
            }
//            printf("Write %zd of %zu bytes, ava size: %zu\n",
//                   write_ret, target_size, available_size);

            if (size_t(write_ret) == target_size) {

//                buf_deque.pop_front();
//                status_deque.pop_front();
//                if (buf_deque.empty()) {
                buf = fws::RequestBuf(MAX_DATA_LEN + fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                buf.start_pos = fws::constants::SUGGEST_RESERVE_WS_HDR_SIZE;
                int stop_ret = w_socket.StopWriteRequest(fq);
                FWS_ASSERT(stop_ret >= 0);
                has_requested_write = false;
//                    if (status.is_msg_end) {
//                        w_socket.CloseCon<true>(1000, "");
//                    }

//                }
            }
            return 0;
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
            int cur_fd = (int)event.ident;
            auto &handler = *ctx;
            if FWS_UNLIKELY(event.flags & fws::FEV_ERROR) {
                printf("event error, flags: %u, fd: %d\n",
                       event.flags, cur_fd);
                std::abort();
            }
            else if(event.flags & fws::FEV_EOF) {
                FWS_ASSERT(cur_fd != ctx->ws_server.tcp_socket().fd());
                printf("Client exit. fd=%d\n", cur_fd);
                ctx->fd_to_socks[cur_fd].socket.Close(fws::WS_ABNORMAL_CLOSE, {});
            }
            else if (cur_fd == ctx->ws_server.tcp_socket().fd()) {
                printf("One event with ws server fd\n");
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
                auto& FWS_RESTRICT ws_socket = ctx->fd_to_socks[cur_fd].socket;
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
        fws::InitEnv(argc, argv);
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
        int listen_ret = ws_server.StartListen(SERVER_IP, SERVER_PORT, 10, fws::TcpSocket::REUSE_ADDR_MODE);
        if (listen_ret < 0) {
            printf("Failed to listen, return %d, %s\n", listen_ret,
                   std::string(fws::GetErrorStrV()).c_str());
            return listen_ret;
        }
        auto fq = fws::CreateFQueue();
        fws::FEvent read_ev(ws_server.tcp_socket().fd(), fws::FEVFILT_READ,
                            fws::FEV_ADD,
                            fws::FEFFLAG_NONE, 0, nullptr);
        if (fws::FEventWait(fq, &read_ev, 1, nullptr, 0, nullptr) < 0) {
            printf("Failed to add read event\n");
            return -1;
        }
        Context ctx{};
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