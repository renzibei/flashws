#pragma once

#include "flashws/base/base_include.h"
#include "flashws/net/fevent.h"
#include <sys/ioctl.h> // FIONBIO
#include <arpa/inet.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <optional>

#ifndef FWS_ENABLE_STACK
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fws {



    class TcpSocket {
    public:

        inline static constexpr int INVALID_FD = -1;

        TcpSocket(): fd_(INVALID_FD) {}

        TcpSocket(const TcpSocket&) = delete;
        TcpSocket& operator=(const TcpSocket&) = delete;
        TcpSocket(TcpSocket&& o) noexcept: fd_(std::exchange(o.fd_, INVALID_FD)) {}

        TcpSocket& operator=(TcpSocket&& o) noexcept {
            std::swap(fd_, o.fd_);
            return *this;
        }

        enum ShutDownMode {
            SHUT_RD_MODE = SHUT_RD,
            SHUT_WR_MODE = SHUT_WR,
            SHUT_RDWR_MODE = SHUT_RDWR,
        };

        ~TcpSocket() {
            if (fd_ != INVALID_FD) {
                // TODO: test whether Close send FIN flag
//                Shutdown(SHUT_RDWR_MODE);
                Close();
                fd_ = INVALID_FD;
            }
        }

        int Init() {
#ifdef FWS_ENABLE_FSTACK
            int fd = ff_socket(AF_INET, SOCK_STREAM, 0);
#else
            int fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
            fd_ = fd;
            return fd;
        }

        int Init(int fd) {
            fd_ = fd;
            return fd;
        }


        int SetBusyPoll(int poll_us) {
            (void)poll_us;
#if !defined(FWS_ENABLE_FSTACK) && defined(FWS_LINUX)
            int ret = SetSockOpt(SOL_SOCKET, SO_BUSY_POLL, &poll_us, sizeof(poll_us));
            if FWS_UNLIKELY(ret < 0) {
                SetErrorFormatStr("Error! Failed to set busy poll! %s\n", strerror(errno));
                return ret;
            }
#endif
            return 0;
        }

        int SetNonBlock() {
            int on = 1;
#ifdef FWS_ENABLE_FSTACK
            int set_ret = ff_ioctl(fd_, FIONBIO, &on);
#else
            int set_ret = ioctl(fd_, FIONBIO, &on);
#endif
            return set_ret;
        }

        int SetNoDelay() {
            int true_flag = 1;
            int no_delay_ret = SetSockOpt(IPPROTO_TCP, TCP_NODELAY,
                                             &true_flag, sizeof(true_flag));
            return no_delay_ret;
        }

        enum BindMode {
            DEFAULT_BIND_MODE = 0,
            REUSE_ADDR_MODE,
        };

        static int GetSockOpt(int fd, int level, int opt_name, void* FWS_RESTRICT option_value,
                       socklen_t *FWS_RESTRICT option_len) {
#ifdef FWS_ENABLE_FSTACK
            return ff_getsockopt(fd, level, opt_name, option_value, option_len);
#else
            return getsockopt(fd, level, opt_name, option_value, option_len);
#endif
        }


        int GetSockOpt(int level, int opt_name, void* FWS_RESTRICT option_value,
                       socklen_t *FWS_RESTRICT option_len) {
#ifdef FWS_ENABLE_FSTACK
            return ff_getsockopt(fd_, level, opt_name, option_value, option_len);
#else
            return getsockopt(fd_, level, opt_name, option_value, option_len);
#endif
        }

        int SetSockOpt(int level, int optname, const void* optval, socklen_t optlen) {
#ifdef FWS_ENABLE_FSTACK
            return ff_setsockopt(fd_, level, optname, optval, optlen);
#else
            return setsockopt(fd_, level, optname, optval, optlen);
#endif
        }

        // This function is not accurate
        int GetWritableBytes() {
#ifdef FWS_ENABLE_FSTACK
            // TODO: not safe
            return 16384;
//            return 0;
#else
            return 1 << 19;
//            int bytes_in_buffer = 0;
//            if FWS_UNLIKELY(ioctl(fd_, TIOCOUTQ, &bytes_in_buffer) < 0) {
//                SetErrorFormatStr("Failed to query TIOCOUTQ using ioctl, %s",
//                                  std::strerror(errno));
//                return -1;
//            }
//            int sock_buffer_size = 0;
//            socklen_t sb_sz = sizeof(sock_buffer_size);
//            int get_ret = GetSockOpt(SOL_SOCKET, SO_SNDBUF, &sock_buffer_size, &sb_sz);
//            int64_t bytes_available = sock_buffer_size - bytes_in_buffer;
//            FWS_ASSERT(bytes_available >= 0);
//            if FWS_UNLIKELY(get_ret < 0) {
//                SetErrorFormatStr("Failed to query SO_SNDBUF using ioctl for fd %d, %s",
//                                  fd_, std::strerror(errno));
//                return get_ret;
//            }
//            size_t ret = std::min(size_t(bytes_available), constants::MAX_WRITABLE_SIZE_ONE_TIME);
//            return ret;
#endif
        }

        int Bind(const char* host_addr, uint16_t port,
                 BindMode mode = REUSE_ADDR_MODE) {
            if (mode == REUSE_ADDR_MODE) {
                const int enable = 1;
                if (SetSockOpt( SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
                    SetErrorFormatStr("Error in Set REUSE ADDR, %s", std::strerror(errno));
                    return -1;
                }
            }
            sockaddr_in bind_addr{};
            int get_addr_in = GetAddrFromStr(host_addr, port, bind_addr);
            if (get_addr_in <= 0) {
                SetErrorFormatStr("Parse addr from string failed");
                return -2;
            }
            int bind_ret = 0;
#ifdef FWS_ENABLE_FSTACK
            bind_ret = ff_bind(fd_, (linux_sockaddr*)&bind_addr, sizeof(bind_addr));
#else
            bind_ret = bind(fd_, (sockaddr*)&bind_addr, sizeof(bind_addr));
#endif
            if FWS_UNLIKELY(bind_ret < 0) {
                SetErrorFormatStr("Failed to bind to %s:%u, bind return %d, errno is %d, %s",
                                  host_addr, port, bind_ret, errno, std::strerror(errno));
            }
            return bind_ret;
        }

        int Connect(const char* host_addr, uint16_t port) {
            sockaddr_in con_addr{};
            if (GetAddrFromStr(host_addr, port, con_addr) <= 0) {
                return -2;
            }
            int ret;
#ifdef FWS_ENABLE_FSTACK
            ret = ff_connect(fd_, (linux_sockaddr*)&con_addr, sizeof(con_addr));
#else
            ret = connect(fd_, (sockaddr*)&con_addr, sizeof(con_addr));
#endif
            if FWS_UNLIKELY(ret < 0 && errno != EINPROGRESS) {
                SetErrorFormatStr("Failed to connect, %s",
                                  std::strerror(errno));
            }
            return ret;
        }

        int Listen(int queue_limit) {
#ifdef FWS_ENABLE_FSTACK
            return ff_listen(fd_, queue_limit);
#else
            return listen(fd_, queue_limit);
#endif
        }

        std::optional<TcpSocket> Accept(sockaddr* addr, socklen_t *addr_len)
                FWS_RESTRICT {
#ifdef FWS_ENABLE_FSTACK
            int new_fd = ff_accept(fd_, (linux_sockaddr*)addr, addr_len);
#else
            int new_fd = accept(fd_, addr, addr_len);
#endif
            if (new_fd < 0 && errno != EWOULDBLOCK) {
                SetErrorFormatStr("Accept failed, %s", std::strerror(errno));
                return std::nullopt;
            }
            TcpSocket ret_sock{};
            if FWS_UNLIKELY(ret_sock.Init(new_fd) < 0) {
                return std::nullopt;
            }
            return ret_sock;
        }

        int fd() const {
            return fd_;
        }

        int Close() FWS_FUNC_RESTRICT {
            if (fd_ == INVALID_FD) {
                return 0;
            }
#ifdef FWS_POLL
            for (auto& [fq_fd, fd_info_map]: detail::queue_to_fd_info_map) {
                auto find_it = fd_info_map.find(fd_);
                if (find_it != fd_info_map.end()) {
                    fd_info_map.erase(find_it);
                }
            }
#elif defined(FWS_EPOLL)
            for (auto& [fq_fd, fd_info_map]: detail::queue_to_fd_info_map) {
                auto find_it = fd_info_map.find(fd_);
                if (find_it != fd_info_map.end()) {
                    find_it->second.cur_evs = 0;
                }
            }
#endif
            int ret = 0;
#ifdef FWS_ENABLE_FSTACK
            ret = ff_close(fd_);
#else
            ret = close(fd_);
#endif


            fd_ = INVALID_FD;
            return ret;
        }

        /**
         *
         * @param max_size
         * @param reserve_size_ahead
         * @return IOBuffer, if error, size of this IOBuffer will be negative.
         */
        IOBuffer Read(size_t max_size, size_t reserve_size_ahead = 0) FWS_FUNC_RESTRICT {
            size_t buf_size = max_size + reserve_size_ahead;
            IOBuffer ret_buf = RequestBuf(buf_size);
#ifdef FWS_ENABLE_FSTACK
            ssize_t read_len = ff_read(fd_, ret_buf.data + reserve_size_ahead, max_size);
#else
            ssize_t read_len = read(fd_, ret_buf.data + reserve_size_ahead, max_size);
#endif
            if FWS_UNLIKELY(read_len < 0) {
//                ReclaimBuf(ret_buf);
                return IOBuffer{nullptr, read_len, 0, 0};
            }
            ret_buf.start_pos = reserve_size_ahead;
            ret_buf.size = read_len;
            return ret_buf;
        }

        ssize_t Read(void *buf, size_t size) {
#ifdef FWS_ENABLE_FSTACK
            return ff_read(fd_, buf, size);
#else
            return read(fd_, buf, size);
#endif
        }

         /**
          *
          * @param io_buf
          * @param max_write_size min(max_write_size, io_buf.size) will be
          * attempted to write
          * @param actual_release_size If set, only when actual written size
          * is equal to actual_release_size will io_buf be reclaimed.
          * @return
          */
        ssize_t Write(IOBuffer& FWS_RESTRICT io_buf, size_t max_write_size,
                      size_t actual_release_size = 0) FWS_FUNC_RESTRICT {
#ifdef FWS_ENABLE_FSTACK
            ssize_t write_len = ff_write(fd_, io_buf.data + io_buf.start_pos,
                                         std::min(max_write_size, (size_t)io_buf.size));
#else
             ssize_t write_len = write(fd_, io_buf.data + io_buf.start_pos,
                                          std::min(max_write_size, (size_t)io_buf.size));
#endif
            bool actual_release_size_set = actual_release_size != 0;
            if ((io_buf.size > 0) & ((!actual_release_size_set & (write_len == io_buf.size))
            || (actual_release_size_set & (actual_release_size == (size_t)io_buf.size)))) {
                ReclaimBuf(io_buf);
            }
            else {
                io_buf.start_pos += write_len;
                io_buf.size -= write_len;
            }

            return write_len;
        }

        ssize_t Write(const void* FWS_RESTRICT buf, size_t size) {
#ifdef FWS_ENABLE_FSTACK
            return ff_write(fd_, buf, size);
#else
            return write(fd_, buf, size);
#endif
        }

        int Shutdown(ShutDownMode how) FWS_FUNC_RESTRICT {
#ifdef FWS_ENABLE_FSTACK
            return ff_shutdown(fd_, how);
#else
            return shutdown(fd_, how);
#endif
        }

    protected:
        int fd_;

        int GetAddrFromStr(const char* addr, uint16_t port, sockaddr_in& sock_addr_in) {
            sock_addr_in.sin_family = AF_INET;
            sock_addr_in.sin_port = htons(port);
            return inet_pton(AF_INET, addr, &sock_addr_in.sin_addr);
        }
    };

} // namespace fws