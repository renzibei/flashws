#include "flashws/flashws.h"

#include "flashws/utils/histogram_wrapper.h"
#include "flashws/utils/cpu_timer.h"
#include "flashws/net/tcp_socket.h"
#include "flashws/net/floop.h"
#include "flashws/net/ws_client_socket.h"
#include "test_def.h"
#include <functional>

namespace test {

    static size_t HashArr(const uint8_t* FWS_RESTRICT data, size_t size) {
        size_t hash_value = 0;
        for (size_t i = 0; i < size; ++i) {
            hash_value ^= data[i];
            hash_value = fws::RotateR(hash_value, 5);
        }
        return hash_value;
    }

    using SockType = std::conditional<ENABLE_TLS, fws::TLSSocket, fws::TCPSocket>::type;

    struct Context {
        hist::HistWrapper rtt_hist;
        cpu_t::CpuTimer<uint64_t> cpu_timer{};
        fws::FLoop<fws::FlashAllocator<char>> floop{};
        struct ClientCtx {
            int fd = -1;
            int reborn_cnt = 1;
            uint64_t msg_cnt = 0;
            uint64_t start_write_tick = 0;
            fws::IOBuffer io_buf;
            int vec_index = -1;
        };
        ska::flat_hash_map<int, ClientCtx> fd_to_socks;
        std::vector<int> fd_vec;
        int now_check_vec_index = 0;
        bool wait_shutdown = false;
        int64_t send_bytes_sum = 0;
        int64_t recv_bytes_sum = 0;

        uint64_t tx_msg_cnt = 0;
        uint64_t rx_msg_cnt = 0;
        size_t data_hash = 0;
        uint64_t loop_cnt = 0;
        int64_t start_ns_from_epoch = 0;
        int64_t total_round_trip_ns = 0;

        template<typename Sock>
        static int InitClient(Sock& sock) {
            if constexpr(ENABLE_TLS) {
                return sock.template Init<false>(hostname);
            }
            else {
                return sock.Init();
            }
        }

        int NewTcpClient() {
            SockType client{};
            int init_ret = InitClient<SockType>(client);


            if FWS_UNLIKELY(init_ret < 0) {
                printf("Error in init tcp client, %s\n",
                       std::strerror(errno));
                std::abort();
            }
//            FWS_ASSERT(init_ret >= 0);


#if SET_LINGER_ZERO_TIMEOUT
            {
                linger linger_opt{1, 0};
                if FWS_UNLIKELY(client.SetSockOpt(SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)) < 0) {
                    printf("Error in set SO_LINGER, %s\n", std::strerror(errno));
                    std::abort();
                }
            };

#endif
            int con_ret = client.Connect(SERVER_IP, SERVER_PORT);
            if FWS_UNLIKELY(con_ret < 0 && errno != EINPROGRESS) {
                printf("Error in connect, return %d, %s\n",
                       con_ret, fws::GetErrorStrP());
                std::abort();
            }

            client.SetOnOpen([&](SockType& sock, void *user_data){
//                printf("fd: %d, on_open\n", sock.fd());
            });

            client.SetOnReadable([&](SockType& sock, fws::IOBuffer &&io_buf, void *user_data){
//
                int cur_fd = sock.fd();
                auto find_it = fd_to_socks.find(cur_fd);
                FWS_ASSERT(find_it != fd_to_socks.end());
                auto *client_ctx = &(find_it->second);
                auto* FWS_RESTRICT temp_buf = &client_ctx->io_buf;
                uint8_t* FWS_RESTRICT start_data = temp_buf->data + temp_buf->start_pos + temp_buf->size;
                ssize_t recv_len = io_buf.size;
                FWS_ASSERT(recv_len > 0);
                if (io_buf.size == MAX_DATA_LEN) {
                    FWS_ASSERT(temp_buf->size == 0);
                    *temp_buf = std::move(io_buf);
                }
                else {
                    memcpy(start_data, io_buf.data + io_buf.start_pos, io_buf.size);
                    temp_buf->size += recv_len;
                }
                auto *sock_ptr = &sock;

                recv_bytes_sum += recv_len;

//                printf("fd: %d, on_read, recv_len: %zd, io_buf.size: %ld\n",
//                       cur_fd, recv_len, temp_buf->size);

                if (temp_buf->size == MAX_DATA_LEN) {
                    auto read_end_tick = this->cpu_timer.Stop();
                    auto pass_tick = read_end_tick - client_ctx->start_write_tick;
                    int64_t round_trip_ns = std::llround(pass_tick * this->cpu_timer.ns_per_tick());
                    this->rtt_hist.AddValue(round_trip_ns);
                    ++this->rx_msg_cnt;
                    this->total_round_trip_ns += round_trip_ns;
                    auto client_msg_cnt = ++client_ctx->msg_cnt;
                    bool this_client_finish_all_connection = false;
                    bool is_new_born_client = false;
                    if FWS_UNLIKELY(client_msg_cnt == MSG_LIMIT_PER_CLIENT) {
//                        int old_fd = sock_ptr->fd();
                        sock_ptr->Shutdown();
//                        sock_ptr->Close();
//                        floop.DeleteSocket(cur_fd, true);
//                        printf("fd %d closed\n", old_fd);
                        auto cur_reborn_cnt = client_ctx->reborn_cnt;
                        if (size_t(cur_reborn_cnt) < REBORN_LIMIT_FOR_CLIENT) {
                            is_new_born_client = true;

                            auto old_buf = std::move(*temp_buf);
                            floop.DeleteSocket(sock_ptr, true);
//
                            ++cur_reborn_cnt;

                            int new_fd = this->NewTcpClient();

                            this->fd_to_socks[new_fd] = Context::ClientCtx{
                                    new_fd,
                                    cur_reborn_cnt, 0, read_end_tick,
                                    std::move(old_buf),
                                    (int)this->fd_vec.size(),
                            };
                            this->fd_vec.push_back(new_fd);

                        }
                        else {
                            floop.DeleteSocket(sock_ptr, true);
                            this_client_finish_all_connection = true;
                            client_ctx  = nullptr;
                            if (this->fd_to_socks.empty()) {
                                EndClient(*this);
                                return ;
                            }
                        }
                        // Should wait for next on_open event
                        return ;
                    }

                    ++(this->loop_cnt);
                    if FWS_UNLIKELY(this->loop_cnt >= TOTAL_MSG_CNT) {
                        EndClient(*this);
                        return ;
                    }
                    if FWS_UNLIKELY(this_client_finish_all_connection) {
                        return ;
                    }
                    if FWS_UNLIKELY(!(this->loop_cnt & 0x3fffUL)) {
                        double round_trip_us = double(total_round_trip_ns) / rx_msg_cnt / 1000.0;
                        constexpr int64_t BITS_PER_BYTE = 8;
                        auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                        auto to_now_ns = now_ns_from_epoch - this->start_ns_from_epoch;
                        double pass_sec = double(to_now_ns) / 1e+9;
                        double avg_recv_throughput_mbps = double((this->recv_bytes_sum) *
                                                                 BITS_PER_BYTE) / (1e+6) / pass_sec;
                        double avg_send_throughput_mbps = double((this->send_bytes_sum) *
                                                                 BITS_PER_BYTE) / (1e+6) / pass_sec;
                        double rx_mm_msg_per_sec = double(this->rx_msg_cnt) / (1e+6) / pass_sec;
                        double tx_mm_msg_per_sec = double(this->tx_msg_cnt) / (1e+6) / pass_sec;

                        size_t recv_hash = HashArr(temp_buf->data + temp_buf->start_pos, temp_buf->size);
                        if (recv_hash != this->data_hash) {
                            printf("Hash not the same, original: %zu, now: %zu\n", this->data_hash, recv_hash);
                            exit(-1);
                        }
                        printf("Avg round trip latency: %.3lf us, throughput rx+tx: %.2lf Mbit/s, tx+rx %.4lf 10^6 msg/s"
                               " active fd: %zu, hash value: %zu\n",
                               round_trip_us, avg_recv_throughput_mbps +
                                              avg_send_throughput_mbps,
                               rx_mm_msg_per_sec + tx_mm_msg_per_sec,
                               this->fd_to_socks.size(),
                               recv_hash);
                    }
                    // Not writable yet
                    if FWS_UNLIKELY(is_new_born_client) {
                        return ;
                    }
                    if (true) {
                        client_ctx->start_write_tick = this->cpu_timer.Start();
                        size_t target_size = temp_buf->size;
                        ssize_t send_len = sock.Write(*temp_buf, target_size);
                        if FWS_UNLIKELY(send_len < 0) {
                            printf("Failed to send, writable_size: %ld, target_size: %zu %s\n",
                                   target_size, target_size, fws::GetErrorStrP());
                            std::abort();
                        }
//                        printf("fd: %d, write in on_read, send_len: %zd\n",
//                               cur_fd, send_len);
                        this->send_bytes_sum += send_len;
                        if (size_t(send_len) == target_size) {
                            ++this->tx_msg_cnt;
                            *temp_buf = fws::RequestBuf(MAX_DATA_LEN);
                        }
                    }

                }


            });

            client.SetOnWritable([&](SockType& sock, size_t writable_size, void *user_data){
                int cur_fd = sock.fd();
                auto find_it = this->fd_to_socks.find(cur_fd);
                if FWS_UNLIKELY(find_it == this->fd_to_socks.end()) {
                    printf("Didnt find fd %d in fd_to_socks, maybe in the end,"
                           "map has %zu elements\n",
                           cur_fd, this->fd_to_socks.size());
                    return ;
                }
                auto& client_ctx = find_it->second;
//                auto &tcp_sock = client_ctx.sock;
                auto &tcp_sock = sock;
                auto& buf = client_ctx.io_buf;
                size_t target_size = buf.size;
//                assert(this->cur_read_pos == MAX_DATA_LEN);
                if (target_size == MAX_DATA_LEN) {
                    if (this->send_bytes_sum == 0) {
                        this->start_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                    }
                    client_ctx.start_write_tick = this->cpu_timer.Start();
                }
//                size_t buf_size = (size_t) event.send_buf_size();
                size_t buf_size = writable_size;
                size_t to_write_size = target_size;

                size_t write_size = std::min(buf_size, to_write_size);
                write_size = std::min(write_size, size_t(MAX_WRITE_EVENT_WRITE_SIZE));

                ssize_t send_len = tcp_sock.Write(buf, write_size);
                if (send_len < 0) {
                    printf("Failed to send, %s\n", strerror(errno));
                    std::abort();
                }
                this->send_bytes_sum += send_len;
                if (size_t(send_len) == target_size) {
                    ++this->tx_msg_cnt;
                    buf = fws::RequestBuf(MAX_DATA_LEN);
                }

            });

            client.SetOnClose([&](SockType &sock, void* user_data) {
                int cur_fd = sock.fd();
                auto find_it = this->fd_to_socks.find(cur_fd);
                bool should_print = false;

                if (should_print) {
                    printf("On Close, fd: %d", cur_fd);
                }

                // it is possible for both write and read eof events to occur for
                // the same fd
//                FWS_ASSERT(find_it != this->fd_to_socks.end());
                if (find_it != this->fd_to_socks.end()) {
                    if (should_print) {
                        printf(", reborn_cnt: %d, msg_cnt: %zu\n",
                               find_it->second.reborn_cnt, find_it->second.msg_cnt);
                    }

                    // update vec index
                    this->DeleteFdFromVec(find_it);
                    this->fd_to_socks.erase(find_it);
                }
                else {
                    if (should_print) {
                        printf("\n");
                    }

                }

            });


            client.SetOnError([&](SockType &sock, int error_code, std::string_view reason, void* user_data) {


                printf("Error in fd %d, error code: %d, reason: %s\n",
                       sock.fd(), error_code, std::string(reason).c_str());
                return;
            });

            int fd = client.fd();
            FWS_ASSERT(fd_to_socks.find(fd) == fd_to_socks.end());
            auto [add_ret, sock_ptr] = floop.AddSocket(std::move(client), 0, false);
            if FWS_UNLIKELY(add_ret < 0) {
                printf("Failed to add read event, %s\n",
                       fws::GetErrorStrP());
                std::abort();
            }
            FWS_ASSERT(add_ret == 0);

            return fd;
        }

        template<class FindIt>
        void DeleteFdFromVec(FindIt find_it) {
            int vec_index = find_it->second.vec_index;
            FWS_ASSERT(!fd_to_socks.empty());
            size_t vec_tail_index = fd_vec.size() - 1U;
            int vec_tail_fd = fd_vec[vec_tail_index];
            fd_to_socks[vec_tail_fd].vec_index = vec_index;
            fd_vec[vec_index] = vec_tail_fd;
            fd_vec.pop_back();
        }

        void EndClient(Context &ctx) {
            floop.StopRun();
            auto now_ns_from_epoch = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            auto to_now_ns = now_ns_from_epoch - ctx.start_ns_from_epoch;
            printf("INFO! write read finish! packetlen=%d times=%zu sendsum=%ld recvsum=%ld cost=%.3lf ms\n",
                   MAX_DATA_LEN, TOTAL_MSG_CNT, ctx.send_bytes_sum, ctx.recv_bytes_sum,
                   (double)to_now_ns / (1e+6));
            printf("INFO! round trip latency histogram (ns)\n");
            ctx.rtt_hist.PrintHdr(30UL);
            printf("active fds in EndClient is %zu\n", ctx.fd_to_socks.size());
            for (auto it = ctx.fd_to_socks.begin(); it != ctx.fd_to_socks.end(); ) {

                // update vec index
                ctx.DeleteFdFromVec(it);
                it = ctx.fd_to_socks.erase(it);
            }

            ctx.wait_shutdown = true;
        }
    };







    void CheckAndUpdateSocketConnection(Context* FWS_RESTRICT ctx) {
        auto& FWS_RESTRICT fd_vec = ctx->fd_vec;
        if (fd_vec.empty()) {
            return;
        }

        if ((size_t)ctx->now_check_vec_index >= fd_vec.size()) {
            ctx->now_check_vec_index = 0;
        }
        int check_fd = fd_vec[ctx->now_check_vec_index];
        auto find_it = ctx->fd_to_socks.find(check_fd);
        FWS_ASSERT(find_it != ctx->fd_to_socks.end());
        auto now_tick = cpu_t::Now64();
        auto pass_tick = now_tick - find_it->second.start_write_tick;
        if FWS_UNLIKELY(pass_tick > CHECK_TIMEOUT_TICK) {
            printf("try to detect timeout after %lf seconds for fd %d, reborn cnt: %d, this round msg cnt: %zu, active fd num: %zu\n",
                   pass_tick * ctx->cpu_timer.ns_per_tick() / (1e+9), check_fd,
                   find_it->second.reborn_cnt, find_it->second.msg_cnt,
                   ctx->fd_to_socks.size());
            FWS_ASSERT(ctx->fd_to_socks.size() == ctx->fd_vec.size());
        }


        ctx->now_check_vec_index++;
    }


    int TestClient(int argc, char* argv[]) {
        Context ctx{hist::HistWrapper(TOTAL_MSG_CNT + 2, 2LL, 1000000000LL),
//                    hist::HistWrapper(TOTAL_MSG_CNT + 2, 1LL, 1000000LL),
//                    hist::HistWrapper(TEST_TIMES + 2, 1LL, MAX_DATA_LEN + 2)
        };
        printf("CpuTimer overhead cycles: %lu cycles, tick per ns: %lf\n",
               ctx.cpu_timer.overhead_ticks(), 1.0 / ctx.cpu_timer.ns_per_tick());

        printf("Prepare to init fws env\n");
        {
            int code = fws::InitEnv(argc, argv);
            if (code < 0) {
                printf("Error in Init Env\n");
                return code;
            }
        }
        printf("Init Env end\n");

        {
            fws::FLoop floop{};
            int init_ret = floop.Init<ENABLE_TLS>();
            if FWS_UNLIKELY(init_ret < 0) {
                printf("Failed to init floop, %s\n", std::strerror(errno));
                std::abort();
            }
            ctx.floop = std::move(floop);
        }

        if constexpr (ENABLE_TLS) {
            if (fws::SSLManager::instance().Init(SHOULD_VERIFY_CERT, nullptr, nullptr,
                                                 ca_file_path) < 0) {
                printf("Failed to init ssl manager, %s\n", fws::GetErrorStrP());
                std::abort();
            }
        }

//        ctx.fq = std::move(fq);
        auto src_buf = fws::RequestBuf(MAX_DATA_LEN);
        for (size_t i = 0; i < MAX_DATA_LEN; ++i) {
            src_buf.data[i] = rand() % 10 + '0';
        }
        src_buf.size = MAX_DATA_LEN;
        ctx.data_hash = HashArr(src_buf.data + src_buf.start_pos + LATENCY_DATA_SIZE,
                                src_buf.size - LATENCY_DATA_SIZE);
        printf("data hash: %lu\n", ctx.data_hash);
        auto temp_tick = cpu_t::Now64();
        for (size_t k = 0; k < CON_CLIENT_NUM; ++k) {
            int client_fd = ctx.NewTcpClient();
            auto temp_buf = fws::RequestBuf(MAX_DATA_LEN);
            memcpy(temp_buf.data, src_buf.data, MAX_DATA_LEN);
            temp_buf.size = MAX_DATA_LEN;
            ctx.fd_to_socks.emplace(client_fd, Context::ClientCtx{
                    client_fd,
                    1, 0, temp_tick, std::move(temp_buf), (int)ctx.fd_vec.size()});
            ctx.fd_vec.push_back(client_fd);
        }
        printf("Start to run loop\n");
        ctx.floop.Run();
        return 0;
    }

} // namespace test

int main(int argc, char* argv[]) {
    return test::TestClient(argc, argv);
}