#include "flashws/flashws.h"
#include "flashws/net/tcp_socket.h"
#include "flashws/utils/flat_hash_map.h"
#include "flashws/utils/cpu_timer.h"
#include "flashws/net/floop.h"
#include "test_def.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <chrono>

namespace test {

    struct Context {
        fws::FLoop<fws::FlashAllocator<char>> floop;
        struct ClientCtx{
            fws::IOBuffer io_buf;
            size_t rx_msg_cnt = 0;
            size_t tx_msg_cnt = 0;
        };

        uint64_t last_interval_send_bytes = 0;
        uint64_t last_interval_recv_bytes = 0;
        uint64_t last_interval_recv_msg_cnt = 0;
        uint64_t last_interval_send_msg_cnt = 0;

        int64_t interval_start_ns = 0;

        int server_fd = 0;



        void CountStats() {
            if FWS_LIKELY(((last_interval_recv_msg_cnt & 0xffffUL)
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
            printf("avg rx+tx goodput: %.2lf Mbps, %.4lf 10^6 msg/sec,"
                   "active_client_cnt: %zd\n",
                   recv_throughput_mbps + send_throughput_mbps,
                   recv_mm_msg_per_sec + send_mm_msg_per_sec,
                   floop.socket_count() - 1);

            last_interval_recv_bytes = 0;
            last_interval_send_bytes = 0;
            last_interval_recv_msg_cnt = 0;
            last_interval_send_msg_cnt = 0;
            interval_start_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::high_resolution_clock::now().time_since_epoch()).count();

        }
    };

    using SockType = std::conditional<ENABLE_TLS, fws::TLSSocket, fws::TCPSocket>::type;

    template<typename Sock>
    static int InitClient(Sock& sock) {
        if constexpr(ENABLE_TLS) {
            return sock.template Init<true>(hostname);
        }
        else {
            return sock.Init();
        }
    }


    int DoTest(int argc, char* argv[]) {
        printf("Prepare to init fws env\n");
        {
            int code = fws::InitEnv(argc, argv);
            if (code < 0) {
                printf("Error in Init Env\n");
                return code;
            }
        }
        printf("Init Env end\n");
        Context context{};
        Context *ctx= &context;

        fws::FLoop floop{};
        if (floop.Init<ENABLE_TLS>() < 0) {
            printf("Error in init floop\n");
            std::abort();
        }

        if constexpr (ENABLE_TLS) {
            if (fws::SSLManager::instance().Init(SHOULD_VERIFY_CERT, cert_file_path, key_file_path,
                                                 nullptr) < 0) {
                printf("Failed to init ssl manager, %s\n", fws::GetErrorStrP());
                std::abort();
            }
        }

//        ctx.wait_evs = {MAX_EVENT_NUM, fws::FEvent{}};
        auto tcp_socket = SockType{};
        if (InitClient(tcp_socket) < 0) {
            printf("Error when init first tcpsocket, %s\n", std::strerror(errno));
            std::abort();
        }

        if (tcp_socket.Bind(SERVER_IP, SERVER_PORT, fws::TCPSocket::REUSE_ADDR_MODE) < 0) {
            printf("Error in bind to %s:%d\n%s\n",
                   SERVER_IP, SERVER_PORT, std::string(fws::GetErrorStrV()).c_str());
            std::abort();
        }
        if (tcp_socket.Listen(LISTEN_BACKLOG) < 0) {
            printf("Error in listen, %s\n", fws::GetErrorStrP());
            std::abort();
        }


        // We need to construct the user_data in on_open event. But we do not have
        // to do so if we use moved object in `AddTcpSocket`in the client case.
        // We should always construct it in SetOnOpen in the server case, as the
        // memory for user_data is allocated after a new socket is accepted.
        // Every socket have its own user_data.
        tcp_socket.SetOnOpen([&](SockType &sock, void* user_data) {
            Context::ClientCtx *client_ctx = (Context::ClientCtx*)user_data;
            // placement enw
            ::new(client_ctx) Context::ClientCtx{fws::RequestBuf(MAX_DATA_LEN), 0, 0};
//            printf("OnOpen, fd: %d\n", sock.fd());
        });

        tcp_socket.SetOnReadable([&](SockType &sock, fws::IOBuffer &buf, void* user_data) {

            auto &FWS_RESTRICT client_ctx = *(Context::ClientCtx*)user_data;
            auto &FWS_RESTRICT io_buf = client_ctx.io_buf;
            memcpy(io_buf.data + io_buf.start_pos + io_buf.size, buf.data + buf.start_pos, buf.size);
            ssize_t read_len = buf.size;
            FWS_ASSERT(read_len > 0);
            io_buf.size += read_len;
            ctx->last_interval_recv_bytes += read_len;
//            printf("fd: %d, on_readable, read_len: %zu bytes, io_buf size: %ld\n",
//                   sock.fd(), size_t(read_len), io_buf.size);
            if FWS_UNLIKELY(ctx->interval_start_ns == 0) {
                ctx->interval_start_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            }

            if (io_buf.size == MAX_DATA_LEN) {
                ++ctx->last_interval_recv_msg_cnt;
                ++client_ctx.rx_msg_cnt;
                int writable_size = sock.GetWritableBytes();
                FWS_ASSERT(writable_size >= 0);
                size_t written_size = 0;
                size_t target_size = io_buf.size;
                if (writable_size > 0) {
                    ssize_t send_len = sock.Write(io_buf, writable_size);
                    if FWS_UNLIKELY(send_len < 0) {
                        printf("Failed to send\n");
                        std::abort();
                    }
                    written_size = size_t(send_len);
//                    printf("fd: %d, on_readable, to_write_size: %zu bytes, written_size: %zu bytes\n",
//                           sock.fd(), target_size, written_size);
                }
                ctx->last_interval_send_bytes += written_size;

                if (written_size == target_size) {
                    io_buf = fws::RequestBuf(MAX_DATA_LEN);
                    ++ctx->last_interval_send_msg_cnt;
                    ++client_ctx.tx_msg_cnt;
//                    printf("fd: %d, on_readable, to_write_size: %zu bytes, ++tx_msg_cnt = %lu\n",
//                           sock.fd(), target_size, client_ctx.tx_msg_cnt);
                    ctx->CountStats();
                }
            }

        });

        tcp_socket.SetOnWritable([&](SockType &sock, size_t writable_size, void* user_data) {
            size_t buf_size = writable_size;

            auto &client_ctx = *(Context::ClientCtx*)user_data;
            auto &io_buf = client_ctx.io_buf;
            size_t to_write_size = io_buf.size;
            if (to_write_size == 0) {
                return;
            }
            size_t write_size = std::min(buf_size, to_write_size);
            write_size = std::min(write_size, (size_t) MAX_WRITE_EVENT_WRITE_SIZE);
            ssize_t send_len = sock.Write(io_buf, write_size);
            if FWS_UNLIKELY(send_len < 0) {
                printf("Failed to send\n");
                std::abort();
            }
//            printf("fd: %d, on_writable, to_write_size: %zu bytes, written_size: %zu bytes\n",
//                   sock.fd(), to_write_size, size_t(send_len));
            ctx->last_interval_send_bytes += send_len;
            if (size_t(send_len) == to_write_size) {
                ++client_ctx.tx_msg_cnt;
                ctx->last_interval_send_msg_cnt++;

                io_buf = fws::RequestBuf(MAX_DATA_LEN);
//                printf("fd: %d, on_writable, to_write_size: %zu bytes, ++tx_msg_cnt = %lu, io_buf size after Write: %ld\n",
//                       sock.fd(), to_write_size, client_ctx.tx_msg_cnt, io_buf.size);

                ctx->CountStats();
            }
        });

        // We need to destroy the user_data in on_close event
        tcp_socket.SetOnClose([&](SockType &sock, void* user_data) {
            int cur_fd = sock.fd();
            FWS_ASSERT(cur_fd != ctx->server_fd);
            auto &client_ctx = *(Context::ClientCtx*)user_data;
//                printf("Client exit. fd=%d\n", cur_fd);
//                printf("fd %d closed, detect event eof\n", cur_fd);
            if (client_ctx.tx_msg_cnt != MSG_LIMIT_PER_CLIENT) {
                int error_code = errno;
                printf("At %ld fd %d close with rx msg %zu, tx msg %zu for eof, error=%d, %s\n",
                       cpu_t::NowNsFromEpoch(),
                       cur_fd, client_ctx.rx_msg_cnt, client_ctx.tx_msg_cnt,
                       error_code, std::strerror(error_code));
                (void)0;
            }
//            client_ctx.~ClientCtx();
            std::destroy_at(&client_ctx);
        });

        tcp_socket.SetOnError([&](SockType &sock, int error_code, std::string_view error_msg, void* user_data) {
            int socket_err = error_code;
            int cur_fd = sock.fd();
            printf("event error, flags: %u, fd: %d, %s\n",
                   socket_err, cur_fd, error_msg.data());
            if (socket_err == ECONNRESET || socket_err == ETIMEDOUT) {}
            else {
                std::abort();
            }

        });

        context.server_fd = tcp_socket.fd();
        auto [add_socket_ret, sock_ptr] = floop.AddSocket(std::move(tcp_socket), sizeof(Context::ClientCtx), true);
        if (add_socket_ret < 0) {
            printf("Error in add socket to floop\n");
            std::abort();
        }
        context.floop = std::move(floop);
        context.floop.Run();
        return 0;
    }

}// namespace test

int main(int argc, char *argv[]) {


    return test::DoTest(argc, argv);
}