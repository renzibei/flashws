#pragma once

#include "flashws/base/base_include.h"
#include "flashws/utils/inplace_function.h"
#include "flashws/utils/flash_alloc.h"
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
    template<typename>
    class FLoop;


    enum SocketStatus: int8_t {
        INIT_SOCKET_STATUS = 0,
        SEMI_SOCKET_STATUS = 1,
        NORMAL_SOCKET_STATUS = 2,
        SHUTDOWN_SOCKET_STATUS = 4,
        CLOSED_SOCKET_STATUS = 8,

    };

//    inline int operator&(SocketStatus a, SocketStatus b) {
//        return static_cast<int>(a) & static_cast<int>(b);
//    }
//
//    inline int operator|(SocketStatus a, SocketStatus b) {
//        return static_cast<int>(a) | static_cast<int>(b);
//    }

    class alignas(std::max_align_t) TCPSocket {
    protected:
        template<typename Alloc>
        friend class FLoop;
        friend class TLSSocket;
//        template<typename, bool, bool>
//        friend class WSocket;

    public:

        inline static constexpr int INVALID_FD = -1;

        TCPSocket(): fd_(INVALID_FD) {}

        TCPSocket(const TCPSocket&) = delete;
        TCPSocket& operator=(const TCPSocket&) = delete;
        TCPSocket(TCPSocket&& o) noexcept: fd_(std::exchange(o.fd_, INVALID_FD)),
            is_opened_(std::exchange(o.is_opened_, false)),
            status_(std::exchange(o.status_, INIT_SOCKET_STATUS)),
            last_write_failed_(std::exchange(o.last_write_failed_, false)),
            fq_ptr_(std::exchange(o.fq_ptr_, nullptr)),
            data_ptr_(std::exchange(o.data_ptr_, nullptr)),
            on_readable_(std::exchange(o.on_readable_, [](TCPSocket&, IOBuffer&, void*){})),
            on_writable_(std::exchange(o.on_writable_, [](TCPSocket&, size_t, void*){})),
            on_open_(std::exchange(o.on_open_, [](TCPSocket&, void*){})),
            on_close_(std::exchange(o.on_close_, [](TCPSocket&, void*){})),
            on_eof_(std::exchange(o.on_eof_, [](TCPSocket &s, void*){s.Shutdown(SHUT_WR_MODE);s.Close();})),
            on_error_(std::exchange(o.on_error_, [](TCPSocket&, int, std::string_view, void*){}))
            {}

        TCPSocket& operator=(TCPSocket&& o) noexcept {
            std::swap(fd_, o.fd_);
            std::swap(is_opened_, o.is_opened_);
            std::swap(status_, o.status_);
            std::swap(last_write_failed_, o.last_write_failed_);
            std::swap(fq_ptr_, o.fq_ptr_);
            std::swap(data_ptr_, o.data_ptr_);
            std::swap(on_readable_, o.on_readable_);
            std::swap(on_writable_, o.on_writable_);
            std::swap(on_open_, o.on_open_);
            std::swap(on_close_, o.on_close_);
            std::swap(on_eof_, o.on_eof_);
            std::swap(on_error_, o.on_error_);
            return *this;
        }

        enum ShutDownMode {
            SHUT_RD_MODE = SHUT_RD,
            SHUT_WR_MODE = SHUT_WR,
            SHUT_RDWR_MODE = SHUT_RDWR,
        };

        ~TCPSocket() {
            if (fd_ != INVALID_FD) {
                // TODO: test whether Close send FIN flag
//                Shutdown(SHUT_RDWR_MODE);
                Close();
                fd_ = INVALID_FD;
            }
        }



        int Init(int fd, bool is_opened, SocketStatus status, FQueue *fq_ptr,
                 bool nonblock = constants::ENABLE_NON_BLOCK_BY_DEFAULT,
                 bool no_delay = constants::ENABLE_NO_DELAY_BY_DEFAULT,
                 bool busy_poll= constants::ENABLE_NO_DELAY_BY_DEFAULT,
                 int poll_us = constants::BUSY_POLL_US_IF_ENABLED) {
            fd_ = fd;
            is_opened_ = is_opened;
            status_ = status;
            last_write_failed_ = false;
            fq_ptr_ = fq_ptr;
            data_ptr_ = nullptr;
            on_readable_ = [](TCPSocket&, IOBuffer&, void*){};
            on_writable_ = [](TCPSocket&, size_t, void*){};
            on_open_ = [](TCPSocket&, void*){};
            on_close_ = [](TCPSocket&, void*){};
            on_eof_ = [](TCPSocket &s, void*){s.Shutdown(SHUT_WR_MODE);s.Close();};
            on_error_ = [](TCPSocket&, int, std::string_view, void*){};
            if FWS_LIKELY(fd_ != INVALID_FD) {
                if (nonblock) {
                    if FWS_UNLIKELY(SetNonBlock() < 0) {
                        return -1;
                    }
                }
                if (no_delay) {
                    if FWS_UNLIKELY(SetNoDelay() < 0) {
                        return -2;
                    }
                }
                if (busy_poll) {
                    if FWS_UNLIKELY(SetBusyPoll(poll_us) < 0) {
                        return -3;
                    }
                }
            }
            return fd;
        }

        int Init(bool nonblock = constants::ENABLE_NON_BLOCK_BY_DEFAULT,
                 bool no_delay = constants::ENABLE_NO_DELAY_BY_DEFAULT,
                 bool busy_poll= constants::ENABLE_NO_DELAY_BY_DEFAULT,
                 int poll_us = constants::BUSY_POLL_US_IF_ENABLED) {
#ifdef FWS_ENABLE_FSTACK
            int fd = ff_socket(AF_INET, SOCK_STREAM, 0);
#else
            int fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
            return this->Init(fd, false, INIT_SOCKET_STATUS, nullptr, nonblock, no_delay, busy_poll, poll_us);
        }

        bool is_open() const {
            return is_opened_;
        }

        int status() const {
            return status_;
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
                return ret;
            }
//            if (fq_ptr_ != nullptr) {
//                AddFEvent(*fq_ptr_, fd_, FEventAction::FEVAC_WRITE);
//            }
            status_ = SEMI_SOCKET_STATUS;
            return ret;
        }

        int Listen(int queue_limit) {
            int ret = 0;
#ifdef FWS_ENABLE_FSTACK
            ret = ff_listen(fd_, queue_limit);
#else
            ret = listen(fd_, queue_limit);
#endif
            if FWS_UNLIKELY(ret < 0) {
                SetErrorFormatStr("Listen failed, %s", std::strerror(errno));
            }
            status_ = SEMI_SOCKET_STATUS;
            return ret;
        }

        std::optional<TCPSocket> Accept(sockaddr* addr, socklen_t *addr_len)
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
            TCPSocket ret_sock{};
            if FWS_UNLIKELY(ret_sock.Init(new_fd, true, NORMAL_SOCKET_STATUS, fq_ptr_) < 0) {
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
            on_close_(*this, data_ptr_);
            if (fq_ptr_ != nullptr) {
                DeleteFEvent(*fq_ptr_, fd_, FEVAC_READ | FEVAC_WRITE, (void*)this);
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

            is_opened_ = false;
            status_ =  status_ | CLOSED_SOCKET_STATUS;
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
            if (write_len != io_buf.size) {
                last_write_failed_ = true;
                if (fq_ptr_ != nullptr) {
                    AddFEvent(*fq_ptr_, fd_, FEventAction::FEVAC_WRITE, (void*)this);
                }
            }
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
            ssize_t write_len = ff_write(fd_, buf, size);
#else
            ssize_t write_len = write(fd_, buf, size);
#endif
            if (write_len != ssize_t(size)) {
                last_write_failed_ = true;
                if (fq_ptr_ != nullptr) {
                    AddFEvent(*fq_ptr_, fd_, FEventAction::FEVAC_WRITE, (void*)this);
                }
            }
            return write_len;
        }

        int Shutdown(ShutDownMode how = SHUT_WR_MODE) FWS_FUNC_RESTRICT {
            int ret = 0;
            if (is_opened_ && !(status_ & SHUTDOWN_SOCKET_STATUS)) {
                status_ = status_ | SHUTDOWN_SOCKET_STATUS;
                FEventAction action;
                if (how == SHUT_RD_MODE) {
                    action = FEventAction::FEVAC_READ;
                }
                else if (how == SHUT_WR_MODE) {
                    action = FEventAction::FEVAC_WRITE;
                }
                else {
                    action = FEventAction::FEVAC_READ | FEventAction::FEVAC_WRITE;
                }
                if (fq_ptr_ != nullptr) {
                    DeleteFEvent(*fq_ptr_, fd_, action, (void*)this);
                }
#ifdef FWS_ENABLE_FSTACK
                ret = ff_shutdown(fd_, how);
#else
                ret = shutdown(fd_, how);
#endif
            }
            return ret;
        }

        static constexpr size_t DEFAULT_TCP_FUNCTION_CAP = 8;
        using OnReadableFunc = stdext::inplace_function<void(TCPSocket&, IOBuffer&, void*), DEFAULT_TCP_FUNCTION_CAP>;
        using OnWritableFunc = stdext::inplace_function<void(TCPSocket&, size_t, void*), DEFAULT_TCP_FUNCTION_CAP>;
        using OnOpenFunc = stdext::inplace_function<void(TCPSocket&, void*), DEFAULT_TCP_FUNCTION_CAP>;
        using OnCloseFunc = stdext::inplace_function<void(TCPSocket&, void*), DEFAULT_TCP_FUNCTION_CAP>;
        using OnEofFunc = stdext::inplace_function<void(TCPSocket&, void*), DEFAULT_TCP_FUNCTION_CAP>;
        using OnErrorFunc = stdext::inplace_function<void(TCPSocket&, int, std::string_view, void*), DEFAULT_TCP_FUNCTION_CAP>;

        int SetOnReadable(OnReadableFunc on_readable) {
            on_readable_ = std::move(on_readable);
            return 0;
        }

        int SetOnWritable(OnWritableFunc on_writable) {
            on_writable_ = std::move(on_writable);
            return 0;
        }

        int SetOnOpen(OnOpenFunc on_open) {
            on_open_ = std::move(on_open);
            return 0;
        }

        int SetOnClose(OnCloseFunc on_close) {
            on_close_ = std::move(on_close);
            return 0;
        }

        int SetOnEof(OnEofFunc on_eof) {
            on_eof_ = std::move(on_eof);
            return 0;
        }

        int SetOnError(OnErrorFunc on_error) {
            on_error_ = std::move(on_error);
            return 0;
        }

    protected:
        int fd_;
        bool is_opened_;
        int8_t status_;
        bool last_write_failed_;
        FQueue *fq_ptr_;
        void *data_ptr_;


        OnReadableFunc on_readable_;
        OnWritableFunc on_writable_;
        OnOpenFunc on_open_;
        OnCloseFunc on_close_;
        OnEofFunc on_eof_; // shutdown by peer
        OnErrorFunc on_error_;
        static_assert(sizeof(on_readable_) == 16);
        static_assert(alignof(decltype(on_readable_)) == 8);



        int GetAddrFromStr(const char* addr, uint16_t port, sockaddr_in& sock_addr_in) {
            sock_addr_in.sin_family = AF_INET;
            sock_addr_in.sin_port = htons(port);
            return inet_pton(AF_INET, addr, &sock_addr_in.sin_addr);
        }

        OnReadableFunc& on_readable() {
            return on_readable_;
        }

        OnWritableFunc& on_writable() {
            return on_writable_;
        }

        OnOpenFunc& on_open() {
            return on_open_;
        }

        OnCloseFunc& on_close() {
            return on_close_;
        }

        OnEofFunc& on_eof() {
            return on_eof_;
        }

        OnErrorFunc& on_error() {
            return on_error_;
        }



    };

    static_assert(sizeof(TCPSocket) == 128);
    static_assert(alignof(TCPSocket) == 16);


} // namespace fws