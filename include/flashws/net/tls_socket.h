#pragma once
#include "flashws/net/tcp_socket.h"
#include "flashws/crypto/ssl_manager.h"

namespace fws {

    struct TLSSharedData {
        TCPSocket *cur_sock_ptr;
        IOBuffer buf;
        BIO *shared_rbio;
        BIO *shared_wbio;
        BIO_METHOD *shared_bio_meth;
        TLSSharedData(TCPSocket *cur_sock_ptr, IOBuffer &&buf, BIO *shared_rbio, BIO *shared_wbio, BIO_METHOD *shared_bio_meth):
            cur_sock_ptr(cur_sock_ptr), buf(std::move(buf)), shared_rbio(shared_rbio), shared_wbio(shared_wbio),
            shared_bio_meth(shared_bio_meth) {}
        TLSSharedData() = default;
        TLSSharedData(const TLSSharedData&) = delete;
        TLSSharedData& operator=(const TLSSharedData&) = delete;
        TLSSharedData(TLSSharedData &&) = default;
        TLSSharedData& operator=(TLSSharedData &&) = default;
    };


    namespace detail {



        static int custom_bio_write(BIO* bio, const char* data, int length) {

            auto* custom_bio = static_cast<TLSSharedData*>(BIO_get_data(bio));
//            int target_len = std::min(length, 1 << 14);
            int target_len = length;
            ssize_t written = custom_bio->cur_sock_ptr->Write(data, target_len);
#if defined(FWS_DEV_DEBUG)
            printf("IN custom_bio_write, fd:%d written: %zd\n", custom_bio->cur_sock_ptr->fd(), written);
#endif
            if (!written || (written < 0 && errno == EAGAIN)) {
                BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_WRITE);
                return -1;
            }
            return written;
        }

        static int custom_bio_read(BIO* bio, char* FWS_RESTRICT data, int length) {

            auto* FWS_RESTRICT custom_bio = static_cast<TLSSharedData*>(BIO_get_data(bio));
//            auto & FWS_RESTRICT io_buf = custom_bio->buf;
            auto &bio_read_buf = custom_bio->buf;

            if (bio_read_buf.size == 0) {
                BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ);
                return -1;
            }

            ssize_t target_length = std::min(ssize_t(length), bio_read_buf.size);
            memcpy(data, bio_read_buf.data + bio_read_buf.start_pos, target_length);
            bio_read_buf.start_pos += target_length;
            bio_read_buf.size -= target_length;
            return target_length;

        }

        static long custom_bio_ctrl(BIO*, int cmd, long, void*) {
            switch (cmd) {
                case BIO_CTRL_FLUSH:
                    return 1;
                default:
                    return 0;
            }

        }

        static int custom_bio_create(BIO* bio) {
            BIO_set_init(bio, 1);
            return 1;
        }

        BIO_METHOD* new_BIO_s_custom() {
            BIO_METHOD* method = BIO_meth_new(BIO_TYPE_MEM, "Custom BIO");
            BIO_meth_set_create(method, custom_bio_create);
            BIO_meth_set_write(method, custom_bio_write);
            BIO_meth_set_read(method, custom_bio_read);
            BIO_meth_set_ctrl(method, custom_bio_ctrl);
            return method;
        }


        }; //namespace detail


    class TLSSocket : public TCPSocket {
    protected:
        using Base = TCPSocket;
        template<typename Alloc>
        friend class FLoop;
    public:

        TLSSocket(): Base(), ssl_(nullptr){
            InitBaseCallbacks();
        }

        // Need to call InitSSLPart after move from TCPSocket
        explicit TLSSocket(TCPSocket &&tcp) noexcept:
            Base(std::move(tcp)), ssl_(nullptr) {
            InitBaseCallbacks();
        }

        TLSSocket(TLSSocket &&o) noexcept:
            Base(std::move(o)),
            ssl_(std::exchange(o.ssl_, nullptr)),
//            bio_data_(std::move(o.bio_data_)),
            shared_tls_data_(std::exchange(o.shared_tls_data_, nullptr)),
            read_wants_write_(std::exchange(o.read_wants_write_, false)),
            write_wants_read_(std::exchange(o.write_wants_read_, false)),
            tls_on_readable_(std::move(o.tls_on_readable_)),
            tls_on_writable_(std::move(o.tls_on_writable_)),
            tls_on_open_(std::move(o.tls_on_open_)),
            tls_on_close_(std::move(o.tls_on_close_)),
            tls_on_eof_(std::move(o.tls_on_eof_)),
            tls_on_error_(std::move(o.tls_on_error_))
            // TODO: add move for callbacks
            {}

        TLSSocket& operator=(TLSSocket &&o) noexcept {
            std::swap(static_cast<Base&>(*this), static_cast<Base&>(o));
            std::swap(ssl_, o.ssl_);
            // bio_data_.tcp_socket points to this, so no need to swap
//            std::swap(bio_data_.buf, o.bio_data_.buf);
            std::swap(shared_tls_data_, o.shared_tls_data_);
            std::swap(read_wants_write_, o.read_wants_write_);
            std::swap(write_wants_read_, o.write_wants_read_);
            std::swap(tls_on_readable_, o.tls_on_readable_);
            std::swap(tls_on_writable_, o.tls_on_writable_);
            std::swap(tls_on_open_, o.tls_on_open_);
            std::swap(tls_on_close_, o.tls_on_close_);
            std::swap(tls_on_eof_, o.tls_on_eof_);
            std::swap(tls_on_error_, o.tls_on_error_);
            return *this;
        }

        TLSSocket(const TLSSocket&) = delete;
        TLSSocket& operator=(const TLSSocket&) = delete;

        template<bool is_server>
        int Init(const char* host_name = nullptr, bool nonblock = constants::ENABLE_NON_BLOCK_BY_DEFAULT,
                 bool no_delay = constants::ENABLE_NO_DELAY_BY_DEFAULT,
                 bool busy_poll = constants::ENABLE_BUSY_POLL_BY_DEFAULT,
                 int poll_us = constants::BUSY_POLL_US_IF_ENABLED) {
            int ret = static_cast<Base*>(this)->Init(nonblock, no_delay, busy_poll, poll_us);
            if FWS_UNLIKELY(ret < 0) {
                return ret;
            }

            ret = this->InitSSLPart(is_server, host_name);
            return ret;
        }

        int InitSSLPart(bool is_server, const char* host_name) {
            InitBaseCallbacks();
            ssl_ = nullptr;
            shared_tls_data_ = nullptr;
//            bio_data_.tcp_socket = nullptr;
            read_wants_write_ = false;
            write_wants_read_ = false;
            SetOnWritable([](TLSSocket&, size_t, void*) {});
            SetOnReadable([](TLSSocket&, IOBuffer&&, void*) {});
            SetOnOpen([](TLSSocket&, void*) {});
            SetOnClose([](TLSSocket&, void*) {});
            SetOnEof([](TLSSocket&, void*) {});
            SetOnError([](TLSSocket&, int, std::string_view, void*) {});
            if FWS_UNLIKELY(SSLManager::instance().is_inited() == false) {
                SetErrorFormatStr("SSLManager is not inited, Call SSLManager::instance().Init() first");
                return -1;
            }
            ssl_ = SSL_new(SSLManager::instance().ctx());
            if (is_server) {
                SSL_set_accept_state(ssl_); /* ssl server mode */
            }
            else {
                SSL_set_connect_state(ssl_); /* ssl client mode */
            }
            if (!is_server) {
                if (host_name != nullptr && strlen(host_name) > 0) {
                    SSL_set_tlsext_host_name(ssl_, host_name);
                }

            }
            return 0;
        }

        ~TLSSocket() {
            if (ssl_) {
                SSL_free(ssl_);
                ssl_ = nullptr;
            }
        }

        static constexpr size_t DEFAULT_TLS_FUNCTION_CAP = 8;
        using TLSOnReadbleFunc = stdext::inplace_function<void(TLSSocket&, IOBuffer&&, void*), DEFAULT_TLS_FUNCTION_CAP>;
        using TLSOnWritableFunc = stdext::inplace_function<void(TLSSocket&, size_t, void*), DEFAULT_TLS_FUNCTION_CAP>;
        using TLSOnOpenFunc = stdext::inplace_function<void(TLSSocket&, void*), DEFAULT_TLS_FUNCTION_CAP>;
        using TLSOnCloseFunc = stdext::inplace_function<void(TLSSocket&, void*), DEFAULT_TLS_FUNCTION_CAP>;
        using TLSOnEofFunc = stdext::inplace_function<void(TLSSocket&, void*), DEFAULT_TLS_FUNCTION_CAP>;
        using TLSOnErrorFunc = stdext::inplace_function<void(TLSSocket&, int, std::string_view, void*), DEFAULT_TLS_FUNCTION_CAP>;

        int SetOnReadable(TLSOnReadbleFunc on_readable) {
            tls_on_readable_ = std::move(on_readable);
            return 0;
        }

        int SetOnWritable(TLSOnWritableFunc on_writable) {
            tls_on_writable_ = std::move(on_writable);
            return 0;
        }

        int SetOnOpen(TLSOnOpenFunc on_open) {
            tls_on_open_ = std::move(on_open);
            return 0;
        }

        int SetOnClose(TLSOnCloseFunc on_close) {
            tls_on_close_ = std::move(on_close);

            return 0;
        }

        int SetOnEof(TLSOnEofFunc on_eof) {
            tls_on_eof_ = std::move(on_eof);
            return 0;
        }

        int SetOnError(TLSOnErrorFunc on_error) {
            tls_on_error_ = std::move(on_error);
            return 0;
        }



        template<class Handler, class... Args>
        int HandleReadEvent(Handler& handler, Args&&... args) {

            handler.OnReadable(std::forward<Args>(args)...);
            if (write_wants_read_) {
                write_wants_read_ = false;
                handler.OnWritable(std::forward<Args>(args)...);
            }
            return 0;
        }

        template<class Handler, class... Args>
        int HandleWriteEvent(Handler& handler, Args&&... args) {
            if (read_wants_write_) {
                read_wants_write_ = false;
                handler.OnReadable(std::forward<Args>(args)...);
            }
            handler.OnWritable(std::forward<Args>(args)...);
            return 0;
        }

        /**
         *
         * @param max_size
         * @param reserve_size_ahead
         * @return IOBuffer, if error, size of this IOBuffer will be negative.
         */
        IOBuffer Read(size_t max_size, size_t reserve_size_ahead = 0) {
//            size_t buf_size = max_size + reserve_size_ahead;
#if defined(FWS_DEV_DEBUG)
            printf("TLS Socket Read called\n");
#endif
            max_size = 1UL << 22;
            auto ret_buf = RequestBuf(max_size + reserve_size_ahead);
            ret_buf.start_pos = reserve_size_ahead;
            while (true) {
#if defined(FWS_DEV_DEBUG)
                size_t remain_buf_size = max_size - ret_buf.size;
#endif
                int read_ret = SSL_read(ssl_, ret_buf.data + ret_buf.start_pos + ret_buf.size, max_size - ret_buf.size);
#if defined(FWS_DEV_DEBUG)
                printf("In TLS Socket Read, SSL_read return: %d, remain buf size before: %zu\n",
                       read_ret, remain_buf_size);
#endif
                if FWS_UNLIKELY(read_ret <= 0) {
                    int ssl_err = SSL_get_error(ssl_, read_ret);
                    if (ssl_err == SSL_ERROR_WANT_WRITE) {
#if defined(FWS_DEV_DEBUG)
                        printf("Read wants write\n");
#endif
                        read_wants_write_ = true;
                    }
                    else if (ssl_err == SSL_ERROR_WANT_READ) {
#if defined(FWS_DEV_DEBUG)
                        printf("Read wants read\n");
#endif
                    }
                    else {
                        std::string ori_err_str = GetErrorString();
                        unsigned int ssl_queue_err = ERR_get_error();
                        SetErrorFormatStr("%s\nSSL_read error code: %d, ssl queue error: %d",
                                          ori_err_str.c_str(), ssl_err, ssl_queue_err);
                        return IOBuffer{nullptr, -1, 0, 0};
                    }
                    break;
                }
                else {
                    ret_buf.size += read_ret;
                    if (ssize_t(max_size) == ret_buf.size) {
                        break;
                    }
                }
            }
            return ret_buf;

        }

        bool is_tls_shutdown() const {
            return (status_ & SHUTDOWN_SOCKET_STATUS) || (SSL_get_shutdown(ssl_) & SSL_SENT_SHUTDOWN);
        }

        ssize_t Write(const char* data, size_t size) {
            if FWS_UNLIKELY(!is_open() || is_tls_shutdown()) {
                return 0;
            }
//            bio_data_.buf.size = 0;
            shared_tls_data_->buf.size = 0;
            shared_tls_data_->cur_sock_ptr = static_cast<Base*>(this);
            ssize_t write_len = SSL_write(ssl_, data, size);
            ssize_t ret = 0;
            if FWS_UNLIKELY(write_len <= 0) {
                int ssl_err = SSL_get_error(ssl_, write_len);
                if (ssl_err == SSL_ERROR_WANT_READ) {
                    write_wants_read_ = true;
                }
                else if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                    ERR_print_errors_fp(stdout);
                    ERR_clear_error();
                }
            }
            else {
                ret = write_len;
            }
            return ret;
        }

        ssize_t Write(IOBuffer& io_buf, size_t /*max_write_size*/,
                      size_t actual_release_size = 0) {
            if FWS_UNLIKELY(!is_open() || is_tls_shutdown()) {
                return 0;
            }
//            bio_data_.buf.size = 0;
            shared_tls_data_->buf.size = 0;
            shared_tls_data_->cur_sock_ptr = static_cast<Base*>(this);
//            FWS_ASSERT(ssl_ != nullptr);
//            FWS_ASSERT(io_buf.data != nullptr);
            ssize_t write_len = SSL_write(ssl_, io_buf.data + io_buf.start_pos, io_buf.size);
            ssize_t ret = 0;
            if FWS_UNLIKELY(write_len <= 0) {
                int ssl_err = SSL_get_error(ssl_, write_len);
                if (ssl_err == SSL_ERROR_WANT_READ) {
                    write_wants_read_ = true;
                }
                else if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                    ERR_print_errors_fp(stdout);
                    ERR_clear_error();
                }
            }
            else {
                ret = write_len;
            }

            bool actual_release_size_set = actual_release_size != 0;
            if ((io_buf.size > 0) & ((!actual_release_size_set & (write_len == io_buf.size))
                                     || (actual_release_size_set & (actual_release_size == (size_t)io_buf.size)))) {
                ReclaimBuf(io_buf);
            }
            else if FWS_LIKELY(write_len >= 0) {
                io_buf.start_pos += write_len;
                io_buf.size -= write_len;
            }

            return ret;
        }

        int Shutdown() {
            if (is_open() && !is_tls_shutdown()) {
//                bio_data_.buf.size = 0;
                shared_tls_data_->buf.size = 0;
                shared_tls_data_->cur_sock_ptr = static_cast<Base*>(this);
                int ret = SSL_shutdown(ssl_);
                if (ret == 0) {
                    ret = SSL_shutdown(ssl_);
                }
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_, ret);
                    if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                        ERR_clear_error();
                    }
                    static_cast<Base*>(this)->Shutdown(SHUT_WR_MODE);
                }
            }
            return 0;
        }

        int InitSharedData(TLSSharedData *shared_data_ptr) {
            shared_tls_data_ = shared_data_ptr;
            FWS_ASSERT(shared_data_ptr != nullptr);
            FWS_ASSERT(shared_data_ptr->shared_rbio != nullptr);
            FWS_ASSERT(shared_data_ptr->shared_wbio != nullptr);
            FWS_ASSERT(ssl_ != nullptr);
            SSL_set_bio(ssl_, shared_data_ptr->shared_rbio, shared_data_ptr->shared_wbio);
            BIO_up_ref(shared_data_ptr->shared_rbio);
            BIO_up_ref(shared_data_ptr->shared_wbio);



            return 0;
        }

    protected:
        SSL *ssl_ = nullptr;
//        detail::CustomBioData bio_data_;
        TLSSharedData* shared_tls_data_;
//        BIO *rbio_ = nullptr;
//        BIO *wbio_ = nullptr;
        bool read_wants_write_ = false;
        bool write_wants_read_ = false;



        TLSOnReadbleFunc tls_on_readable_;
        TLSOnWritableFunc tls_on_writable_;
        TLSOnOpenFunc tls_on_open_;
        TLSOnCloseFunc tls_on_close_;
        TLSOnEofFunc tls_on_eof_; // shutdown by peer
        TLSOnErrorFunc tls_on_error_;
        static_assert(sizeof(tls_on_readable_) == 16);
        static_assert(alignof(decltype(tls_on_readable_)) == 8);

        TLSOnReadbleFunc& on_readable() {
            return tls_on_readable_;
        }

        TLSOnWritableFunc& on_writable() {
            return tls_on_writable_;
        }

        TLSOnOpenFunc& on_open() {
            return tls_on_open_;
        }

        TLSOnCloseFunc& on_close() {
            return tls_on_close_;
        }

        TLSOnEofFunc& on_eof() {
            return tls_on_eof_;
        }

        TLSOnErrorFunc& on_error() {
            return tls_on_error_;
        }

        void InitBaseCallbacks() {
            InitBaseOnReadable();
            InitBaseOnWritable();
            InitBaseOnOpen();
            InitBaseOnClose();
            InitBaseOnEof();
            InitBaseOnError();
        }

        void InitBaseOnReadable() {
            Base::SetOnReadable([](TCPSocket& tcp_sock, IOBuffer&& io_buf, void*) {
                auto &sock = static_cast<TLSSocket&>(tcp_sock);
//                sock.bio_data_.buf = std::move(io_buf);
                sock.shared_tls_data_->buf = std::move(io_buf);
                sock.shared_tls_data_->cur_sock_ptr = &tcp_sock;
                void *tls_user_data_ptr = static_cast<TLSSocket*>(&sock) + 1;
                if FWS_UNLIKELY(sock.is_tls_shutdown()) {
                    int ssl_shut_ret = SSL_shutdown(sock.ssl_);
                    if (ssl_shut_ret == 1) {
                        tcp_sock.Close();
                    }
                    else if (ssl_shut_ret < 0) {
                        int ssl_err = SSL_get_error(sock.ssl_, ssl_shut_ret);
                        if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                            ERR_clear_error();
                        }
                        else {
                            ERR_print_errors_fp(stdout);
                        }
                    }
                    return;
                }
                constexpr ssize_t buf_cap = constants::MAX_READABLE_SIZE_ONE_TIME;
                IOBuffer ret_buf = RequestBuf(buf_cap + constants::DEFAULT_READ_BUF_PRE_PADDING_SIZE * 2);
                ret_buf.start_pos = constants::DEFAULT_READ_BUF_PRE_PADDING_SIZE;
                bool should_stop_read = false;
                while (!should_stop_read) {
                    while (true) {
                        int ssl_read_ret = SSL_read(sock.ssl_,
                                                    ret_buf.data + ret_buf.start_pos + ret_buf.size,
                                                    buf_cap - ret_buf.size);
                        if (ssl_read_ret <= 0) {
                            should_stop_read = true;
                            int ssl_err = SSL_get_error(sock.ssl_, ssl_read_ret);
                            if FWS_UNLIKELY(ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE && ssl_err != SSL_ERROR_ZERO_RETURN) {
                                ERR_print_errors_fp(stdout);
                                if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                                    ERR_clear_error();
                                }
                                static_cast<Base *>(&sock)->Close();
                                return;
                            } else {
                                if FWS_UNLIKELY(ssl_err == SSL_ERROR_WANT_WRITE) {
                                    sock.read_wants_write_ = true;
                                }

                                if FWS_UNLIKELY(sock.shared_tls_data_->buf.size > 0) {
                                    static_cast<Base *>(&sock)->Close();
                                }
                                if (ret_buf.size == 0) {
                                    break;
                                }
                                sock.tls_on_readable_(sock, std::move(ret_buf), tls_user_data_ptr);
                                if FWS_UNLIKELY(ssl_err == SSL_ERROR_ZERO_RETURN) {
                                    sock.tls_on_eof_(sock, tls_user_data_ptr);
                                }
                                if FWS_UNLIKELY(!sock.is_open()) {
                                    return;
                                }
                                break;
                            }
                        } // if (ssl_read_ret <= 0)
                        ret_buf.size += ssl_read_ret;
                        if (ret_buf.size == buf_cap) {
                            sock.tls_on_readable_(sock, std::move(ret_buf), tls_user_data_ptr);
                            if FWS_UNLIKELY(!sock.is_open()) {
                                return;
                            }
                            ret_buf = RequestBuf(buf_cap + constants::DEFAULT_READ_BUF_PRE_PADDING_SIZE * 2);
                            ret_buf.start_pos = constants::DEFAULT_READ_BUF_PRE_PADDING_SIZE;
                            break;
                        }
                    } // while (true)
                } // while (!should_stop_read)

                if FWS_UNLIKELY(sock.write_wants_read_) {
                    sock.write_wants_read_ = false;
                    static_cast<Base*>(&sock)->on_writable()(static_cast<Base&>(sock), 0, tls_user_data_ptr);
//                    sock.tls_on_writable_(sock, 0, tls_user_data_ptr);
                    if (!sock.is_open()) {
                        return;
                    }
                }

                if FWS_UNLIKELY(SSL_get_shutdown(sock.ssl_) & SSL_RECEIVED_SHUTDOWN) {
                    static_cast<Base *>(&sock)->Close();
                    return;
                }
            });
        }

        void InitBaseOnWritable() {
            Base::SetOnWritable([](TCPSocket& tcp_sock, size_t max_write_size, void*/*user_data*/) {
                auto &sock = static_cast<TLSSocket&>(tcp_sock);
                void *tls_user_data_ptr = static_cast<TLSSocket*>(&sock) + 1;
                if (sock.read_wants_write_) {
                    sock.read_wants_write_ = false;
                    static_cast<TCPSocket&>(sock).on_readable()(static_cast<TCPSocket&>(sock),
                            IOBuffer{}, tls_user_data_ptr);
//                    sock.tls_on_readable_(sock, empty_buf, tls_user_data_ptr);
                }
                sock.tls_on_writable_(sock, max_write_size, tls_user_data_ptr);
            });
        }

        void InitBaseOnOpen() {
            Base::SetOnOpen([](TCPSocket& tcp_socket, void*/*user_data*/) {
                auto &sock = static_cast<TLSSocket&>(tcp_socket);
                sock.tls_on_open_(sock, static_cast<TLSSocket*>(&sock) + 1);
            });
        }

        void InitBaseOnClose() {
            Base::SetOnClose([](TCPSocket& tcp_socket, void* /*user_data*/) {
                auto &sock = static_cast<TLSSocket&>(tcp_socket);
                sock.tls_on_close_(sock, static_cast<TLSSocket*>(&sock) + 1);
                SSL_free(sock.ssl_);
                sock.ssl_ = nullptr;
            });
        }

        void InitBaseOnEof() {
            Base::SetOnEof([](TCPSocket& tcp_socket, void* /*user_data*/) {
                tcp_socket.Close();
            });
        }

        void InitBaseOnError() {
            Base::SetOnError([](TCPSocket& tcp_socket, int error_code, std::string_view error_msg, void* /*user_data*/) {
                auto &sock = static_cast<TLSSocket&>(tcp_socket);
                sock.tls_on_error_(sock, error_code, error_msg, static_cast<TLSSocket*>(&sock) + 1);
            });
        }

    }; // class TLSSocket

    static_assert(alignof(TLSSocket) == 16);
    static_assert(sizeof(TLSSocket) == 240);


} // namespace fws