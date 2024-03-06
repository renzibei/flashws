#pragma once

#include "flashws/net/fevent.h"
#include "flashws/net/tcp_socket.h"
#include "flashws/net/tls_socket.h"
#include "flashws/net/ws_server_socket.h"
#include "flashws/net/ws_client_socket.h"
#include "flashws/utils/flat_hash_map.h"
#include "flashws/utils/flash_alloc.h"
#include "flashws/utils/inplace_function.h"

namespace fws {

    inline int64_t GetNowNsFromEpoch() {
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        constexpr int64_t NS_PER_SEC = 1'000'000'000LL;
        return static_cast<int64_t>(ts.tv_sec) * NS_PER_SEC + ts.tv_nsec;
    }

    template<typename Allocator=FlashAllocator<char>>
    class FLoop {
    protected:
        FQueue fq_;

        using ByteAllocTraits = std::allocator_traits<Allocator>;
        using TCPAlloc = typename ByteAllocTraits::template rebind_alloc<TCPSocket>;
        using TCPAllocTraits = std::allocator_traits<TCPAlloc>;
        using TLSAlloc = typename ByteAllocTraits::template rebind_alloc<TLSSocket>;
        using TLSAllocTraits = std::allocator_traits<TLSAlloc>;
        using WSTLSServerAlloc = typename ByteAllocTraits::template rebind_alloc<WSServerSocket<true>>;
        using WSTLSServerAllocTraits = std::allocator_traits<WSTLSServerAlloc>;
        using WSPlainServerAlloc = typename ByteAllocTraits::template rebind_alloc<WSServerSocket<false>>;
        using WSPlainServerAllocTraits = std::allocator_traits<WSPlainServerAlloc>;
        using WSTLSClientAlloc = typename ByteAllocTraits::template rebind_alloc<WSClientSocket<true>>;
        using WSTLSClientAllocTraits = std::allocator_traits<WSTLSClientAlloc>;
        using WSPlainClientAlloc = typename ByteAllocTraits::template rebind_alloc<WSClientSocket<false>>;
        using WSPlainClientAllocTraits = std::allocator_traits<WSPlainClientAlloc>;

        bool stop_run_flag_{};
        // Can only be set in PreExit
        bool clean_up_flag_{};
        int64_t last_event_time_ns_{};

        using OnEventFunc = stdext::inplace_function<void(FLoop&)>;
        OnEventFunc on_event_;

        static constexpr size_t MAX_MONITOR_EVENT_NUM = 1024;

        enum SocketType: int {
            SOCKET_TYPE_PLAIN_TCP = 0, // 000
            SOCKET_TYPE_PLAIN_WS = 2,  // 010
            SOCKET_TYPE_TLS_TCP = 4,   // 100
            SOCKET_TYPE_TLS_WS = 6,    // 110

        };

        FWS_ALWAYS_INLINE static constexpr bool is_tls_encrypted(SocketType type) {
            return type & 4;
        }

        FWS_ALWAYS_INLINE static constexpr bool is_ws_socket(SocketType type) {
            return type & 2;
        }

        struct SocketData{
            void *data_ptr;
            size_t user_data_size;
            SocketType type;
            bool is_server;

            SocketData(const SocketData&) = delete;
            SocketData& operator=(const SocketData&) = delete;
            SocketData(SocketData&&) = default;
            SocketData& operator=(SocketData&&) = default;

            SocketData(void *data_ptr, size_t user_data_size, SocketType type, bool is_server):
                data_ptr(data_ptr), user_data_size(user_data_size), type(type), is_server(is_server) {}

            TCPSocket *sock_ptr() {
                return static_cast<TCPSocket*>(data_ptr);
            }

            TLSSocket *tls_sock_ptr() {
                return static_cast<TLSSocket*>(data_ptr);
            }

            void *user_data_ptr() {
                return static_cast<void*>(static_cast<TCPSocket*>(data_ptr) + 1);
            }

            void *tls_user_data_ptr() {
                return static_cast<void*>(static_cast<TLSSocket*>(data_ptr) + 1);
            }

            int fd() const {
                return static_cast<TCPSocket*>(data_ptr)->fd();
            }
        };
        std::vector<FEvent> wait_evs_;
//        using FD_TO_SOCKS_MAP = ska::flat_hash_map<int, SocketData>;
        // key is the address of the socket
        using FD_TO_SOCKS_MAP = ska::flat_hash_map<void*, SocketData>;
//        using FD_TO_SOCKS_MAP = std::unordered_map<int, SocketData>;
        FD_TO_SOCKS_MAP fd_to_socks_;

        static constexpr size_t DEFAULT_TO_DELETE_SOCKS_CAPACITY = 128;
        std::vector<SocketData> to_delete_socks_;

        // Use pointer because other class may have a pointer to it
        TLSSharedData* tls_shared_data_ptr_;
        Allocator byte_alloc_;
        TCPAlloc tcp_alloc_;
        TLSAlloc tls_alloc_;

    public:
        FLoop(const FLoop&) = delete;
        FLoop& operator=(const FLoop&) = delete;

        FLoop(FLoop &&o) noexcept:
            fq_(std::move(o.fq_)),
            stop_run_flag_(o.stop_run_flag_),
            clean_up_flag_(o.clean_up_flag_),
            last_event_time_ns_(o.last_event_time_ns_),
            on_event_(std::move(o.on_event_)),
            wait_evs_(std::move(o.wait_evs_)),
            fd_to_socks_(std::move(o.fd_to_socks_)),
            to_delete_socks_(std::move(o.to_delete_socks_)),
            tls_shared_data_ptr_(std::exchange(o.tls_shared_data_ptr_, nullptr)),
            byte_alloc_(std::move(o.byte_alloc_)),
            tcp_alloc_(std::move(o.tcp_alloc_)),
            tls_alloc_(std::move(o.tls_alloc_))
        {}
        FLoop& operator=(FLoop &&o) noexcept {
            std::swap(fq_, o.fq_);
            std::swap(stop_run_flag_, o.stop_run_flag_);
            std::swap(clean_up_flag_, o.clean_up_flag_);
            std::swap(last_event_time_ns_, o.last_event_time_ns_);
            std::swap(on_event_, o.on_event_),
            std::swap(wait_evs_, o.wait_evs_);
            std::swap(fd_to_socks_, o.fd_to_socks_);
            std::swap(to_delete_socks_, o.to_delete_socks_);
            std::swap(tls_shared_data_ptr_, o.tls_shared_data_ptr_);
            std::swap(byte_alloc_, o.byte_alloc_);
            std::swap(tcp_alloc_, o.tcp_alloc_);
            std::swap(tls_alloc_, o.tls_alloc_);
            return *this;
        }

        FLoop() = default;
        FLoop(FQueue &&fq) : fq_(std::move(fq)), stop_run_flag_(true), last_event_time_ns_(0), tls_shared_data_ptr_(nullptr) {}

        ~FLoop() {
            if (tls_shared_data_ptr_ != nullptr) {
                using TLSDataAlloc = typename ByteAllocTraits::template rebind_alloc<TLSSharedData>;
                using TLSDataAllocTraits = std::allocator_traits<TLSDataAlloc>;
                TLSDataAlloc tls_data_alloc{};
                if (tls_shared_data_ptr_->shared_rbio != nullptr) {
                    BIO_free(tls_shared_data_ptr_->shared_rbio);
                }
                if (tls_shared_data_ptr_->shared_wbio != nullptr) {
                    BIO_free(tls_shared_data_ptr_->shared_wbio);
                }
                if (tls_shared_data_ptr_->shared_bio_meth != nullptr) {
                    BIO_meth_free(tls_shared_data_ptr_->shared_bio_meth);
                }
                TLSDataAllocTraits::destroy(tls_data_alloc, tls_shared_data_ptr_);
                TLSDataAllocTraits::deallocate(tls_data_alloc, tls_shared_data_ptr_, 1);
                tls_shared_data_ptr_ = nullptr;
            }
        }

        template<bool support_tls>
        int Init() {
            fq_ = fws::CreateFQueue();
            if (fq_.fd < 0) {
                SetErrorFormatStr("Failed to create FQueue: %s", std::strerror(errno));
                return -1;
            }
            stop_run_flag_ = true;
            clean_up_flag_ = true;
            last_event_time_ns_ = GetNowNsFromEpoch();
            on_event_ = [](FLoop&){};
            wait_evs_ = {MAX_MONITOR_EVENT_NUM, FEvent{}};
            to_delete_socks_.reserve(DEFAULT_TO_DELETE_SOCKS_CAPACITY);
            tls_shared_data_ptr_ = nullptr;
            if constexpr (support_tls) {
                using TLSDataAlloc = typename ByteAllocTraits::template rebind_alloc<TLSSharedData>;
                using TLSDataAllocTraits = std::allocator_traits<TLSDataAlloc>;
                TLSDataAlloc tls_data_alloc{};
                tls_shared_data_ptr_ = TLSDataAllocTraits::allocate(tls_data_alloc, 1);
                TLSDataAllocTraits::construct(tls_data_alloc, tls_shared_data_ptr_, TLSSharedData{nullptr, IOBuffer{}, nullptr, nullptr, nullptr});
                tls_shared_data_ptr_->shared_bio_meth = detail::new_BIO_s_custom();
                tls_shared_data_ptr_->shared_rbio = BIO_new(tls_shared_data_ptr_->shared_bio_meth);
                tls_shared_data_ptr_->shared_wbio = BIO_new(tls_shared_data_ptr_->shared_bio_meth);
                BIO_set_data(tls_shared_data_ptr_->shared_rbio, tls_shared_data_ptr_);
                BIO_set_data(tls_shared_data_ptr_->shared_wbio, tls_shared_data_ptr_);
            }

            return 0;
        }

        void SetOnEventFunc(OnEventFunc &&on_event) {
            on_event_ = std::move(on_event);
        }

        template<bool enable = constants::ENABLE_FLOOP_EVENT_TIME_UPDATE, typename = std::enable_if_t<enable>>
        int64_t last_event_time_ns() const {
            return last_event_time_ns_;
        }

        FQueue& GetFQueue() {
            return fq_;
        }

        TLSSharedData* shared_tls_data_ptr() {
            return tls_shared_data_ptr_;
        }

        size_t socket_count() const {
            return fd_to_socks_.size();
        }

        template<typename Socket, bool is_ws>
        constexpr static SocketType get_sock_type() {
            if constexpr (is_ws) {
                if constexpr (Socket::tls_enabled()) {
                    return SOCKET_TYPE_TLS_WS;
                }
                else {
                    return SOCKET_TYPE_PLAIN_WS;
                }
            }
            else {
                if constexpr (std::is_same_v<std::decay_t<Socket>, TLSSocket>) {
                    return SOCKET_TYPE_TLS_TCP;
                }
                else {
                    return SOCKET_TYPE_PLAIN_TCP;
                }
            }
        }

        template<class Socket>
        static bool constexpr is_ws_socket() {
            return std::is_same_v<std::decay_t<Socket>, WSServerSocket<true>> ||
                   std::is_same_v<std::decay_t<Socket>, WSServerSocket<false>> ||
                   std::is_same_v<std::decay_t<Socket>, WSClientSocket<true>> ||
                   std::is_same_v<std::decay_t<Socket>, WSClientSocket<false>>;
        }

        struct Unspecified {};

        // If it is a server websocket, you have to construct the UserData of the
        // new accepted socket yourself in on_open callbacks.
        //
        template<typename Socket, typename UserData=Unspecified>
        std::tuple<int, Socket*> AddSocket(Socket &&socket, size_t user_data_size, bool is_server, UserData &&user_data = Unspecified{}) {
            if constexpr(!std::is_same_v<UserData, Unspecified>) {
                // Asset the size of UserData is correct if UserData is used
                FWS_ASSERT(sizeof(UserData) == user_data_size);
            }

            int fd = socket.fd();
            // We consider WSS socket also as tls socket
            constexpr bool is_ws = is_ws_socket<Socket>();
            constexpr SocketType type = get_sock_type<Socket, is_ws>();
            constexpr bool is_tls = is_tls_encrypted(type);

            static_assert(get_sock_type<WSServerSocket<false>, true>() == SOCKET_TYPE_PLAIN_WS);
            static_assert(is_tls_encrypted(SOCKET_TYPE_PLAIN_WS) == false);
            static_assert(is_tls_encrypted(get_sock_type<WSServerSocket<false>, true>()) == false);
            if constexpr (is_tls) {
                if FWS_UNLIKELY(socket.InitSharedData(shared_tls_data_ptr()) < 0) {
                    return {-1, nullptr};
                }
            }

            void *user_data_ptr = nullptr;
            size_t to_allocate_size = sizeof(Socket) + user_data_size;
            // TODO: Need to take care of the alignment of Socket
            void *new_ptr = byte_alloc_.allocate(to_allocate_size);
            auto *new_sock_ptr = static_cast<Socket *>(new_ptr);
            using SockAlloc = typename ByteAllocTraits::template rebind_alloc<Socket>;
            using SockAllocTraits = std::allocator_traits<SockAlloc>;
            SockAlloc sock_alloc{};
            SockAllocTraits::construct(sock_alloc, new_sock_ptr, std::forward<Socket>(socket));
            if (user_data_size > 0) {
                user_data_ptr = new_sock_ptr + 1;
                if constexpr(!std::is_same_v<UserData, Unspecified>) {
                    using UserDataAlloc = typename ByteAllocTraits::template rebind_alloc<UserData>;
                    using UserDataAllocTraits = std::allocator_traits<UserDataAlloc>;
                    UserDataAlloc user_data_alloc{};
                    UserDataAllocTraits::construct(user_data_alloc,
                                                   static_cast<UserData *>(user_data_ptr),
                                                   std::forward<UserData>(user_data));
                }
            }
            new_sock_ptr->fq_ptr_ = &fq_;
            new_sock_ptr->data_ptr_ = user_data_ptr;
            fd_to_socks_.emplace(new_ptr, SocketData{new_ptr, user_data_size, type, is_server});
            FEventAction action = is_server ? fws::FEVAC_READ : fws::FEVAC_WRITE;
            int add_ret = AddFEvent(fq_, fd, action, new_ptr);
            if FWS_UNLIKELY(add_ret < 0) {
                return {add_ret, new_sock_ptr};
            }
            return {0, new_sock_ptr};

        }





        // Should only be called when the socket is normal
        // DO NOT call this in on_close or on_error
        template<typename Socket>
        int DeleteSocket(Socket *sock_ptr, bool close_it) {
            return DeleteFd((void*)sock_ptr, close_it);
        }

        void StopRun() {
            stop_run_flag_ = true;
        }

        void Run() {
#ifdef FWS_ENABLE_FSTACK
            stop_run_flag_ = false;
            ff_run(OneStep, this);
#else
            stop_run_flag_ = false;
            clean_up_flag_ = false;
            while (!clean_up_flag_) {
                OneStep(this);
            }



#endif

        }

    protected:
        int DeleteFd(void *ptr, bool close_it) {
            auto find_it = fd_to_socks_.find(ptr);
            if (find_it != fd_to_socks_.end()) {
                auto &client_data = find_it->second;
//                auto &sock = client_data.sock;
                TCPSocket *sock_ptr = client_data.sock_ptr();
                if (close_it) {
                    if (sock_ptr->is_open()) {
                        sock_ptr->Close();
                    }
                }
                // Will deallocate the memory at the end of `OneStep`
                to_delete_socks_.push_back(std::move(client_data));
                fd_to_socks_.erase(find_it);
            }
            return 0;
        }

        template<class Socket, bool is_ws>
        std::tuple<int, Socket*> CopyCallbacksAndAddSocket(Socket &&new_sock, void *server_sock_ptr, size_t user_data_size) {
            auto& server_sock = *static_cast<Socket*>(server_sock_ptr);
            if constexpr (is_ws) {
                new_sock.SetOnNewConnection(server_sock.on_new_connection());
                new_sock.SetOnRead(server_sock.on_read());
                new_sock.SetOnWrite(server_sock.on_write());
                new_sock.SetOnClose(server_sock.on_close());
            }
            else {
                new_sock.SetOnReadable(server_sock.on_readable());
                new_sock.SetOnWritable(server_sock.on_writable());
                new_sock.SetOnClose(server_sock.on_close());
                new_sock.SetOnEof(server_sock.on_eof());
                new_sock.SetOnOpen(server_sock.on_open());
                new_sock.SetOnError(server_sock.on_error());
            }

            auto [add_ret, new_sock_ptr] = AddSocket<Socket>(std::forward<Socket>(new_sock), user_data_size, true);
            if FWS_UNLIKELY(add_ret < 0) {
                SetErrorFormatStr("Failed to add new socket %d when accepting, %s\n", new_sock.fd(), std::strerror(errno));
                return {add_ret, new_sock_ptr};
            }
            return {add_ret, new_sock_ptr};
        }

        int TryAcceptOneClient(void* sock_ptr, SocketType type, size_t user_data_size) {
            auto *tcp_sock_ptr = static_cast<TCPSocket*>(sock_ptr);
            auto new_opt_sock = tcp_sock_ptr->Accept(nullptr, nullptr);
            if (!new_opt_sock.has_value()) {
                if FWS_LIKELY(errno == EWOULDBLOCK) {
                    return 0;
                }
                else {
                    SetErrorFormatStr("Error in accept: %s\n", std::strerror(errno));
                    return -1;
                }
            }
            auto &new_sock = new_opt_sock.value();
            if constexpr (constants::ENABLE_NO_DELAY_BY_DEFAULT) {
                if FWS_UNLIKELY(new_sock.SetNoDelay() < 0) {
                    SetErrorFormatStr("Error in set no delay\n");
                    return -2;
                }
            }

            if constexpr (constants::ENABLE_BUSY_POLL_BY_DEFAULT) {
                if FWS_UNLIKELY(new_sock.SetBusyPoll(constants::BUSY_POLL_US_IF_ENABLED) < 0) {
                    SetErrorFormatStr("Error in set busy poll\n");
                    return -3;
                }
            }

            if constexpr (constants::ENABLE_NON_BLOCK_BY_DEFAULT) {
                if FWS_UNLIKELY(new_sock.SetNonBlock() < 0) {
                    SetErrorFormatStr("Error in set non block of new socket!\n");
                    return -4;
                }
            }
            new_sock.status_ = NORMAL_SOCKET_STATUS;
            new_sock.is_opened_ = true;
            int fd = new_sock.fd();
            int copy_callbacks_and_add_sock_ret = 0;
            void *new_sock_ptr = nullptr;
            if (is_tls_encrypted(type)) {
                // Move construct a TLSSocket from its base class TCPSocket
                /// Initialize the SSL part in below
                TLSSocket tls_sock{std::move(new_sock)};
                // TODO: Here we set hostname as nullptr. It should be find because
                // this is a new server socket. Only client socket sets sni now
                if FWS_UNLIKELY(tls_sock.InitSSLPart(true, nullptr) < 0) {
                    SetErrorFormatStr("Failed to init SSL part for new socket %d when accepting, %s\n", fd, GetErrorStrV());
                    return -5;
                }
                if (type == SOCKET_TYPE_TLS_WS) {
                    WSServerSocket<true> ws_sock{std::move(tls_sock)};
                    if FWS_UNLIKELY(ws_sock.InitWSPart() < 0) {
                        SetErrorFormatStr("Failed to init WS part for new socket %d when accepting, %s\n", fd, GetErrorStrV());
                        return -6;
                    }
                    std::tie(copy_callbacks_and_add_sock_ret, new_sock_ptr) = CopyCallbacksAndAddSocket<WSServerSocket<true>, true>(std::move(ws_sock), sock_ptr, user_data_size);
                }
                else {
                    std::tie(copy_callbacks_and_add_sock_ret, new_sock_ptr) = CopyCallbacksAndAddSocket<TLSSocket, false>(std::move(tls_sock), sock_ptr, user_data_size);
                }
            }
            else {
                if (type == SOCKET_TYPE_PLAIN_WS) {
                    WSServerSocket<false> ws_sock{std::move(new_sock)};
                    if FWS_UNLIKELY(ws_sock.InitWSPart() < 0) {
                        SetErrorFormatStr("Failed to init WS part for new socket %d when accepting, %s\n", fd, GetErrorStrV());
                        return -7;
                    }
                    std::tie(copy_callbacks_and_add_sock_ret, new_sock_ptr) = CopyCallbacksAndAddSocket<WSServerSocket<false>, true>(std::move(ws_sock), sock_ptr, user_data_size);
                }
                else {
                    std::tie(copy_callbacks_and_add_sock_ret, new_sock_ptr) = CopyCallbacksAndAddSocket<TCPSocket, false>(std::move(new_sock), sock_ptr, user_data_size);
                }
            }

            if FWS_UNLIKELY(copy_callbacks_and_add_sock_ret < 0) {
                return copy_callbacks_and_add_sock_ret;
            }

            // In theory, client_sock == new_sock, user_data is created in CopyCallbacksAndAddSocket
            auto find_it = fd_to_socks_.find(new_sock_ptr);
            auto &client_sock = *find_it->second.sock_ptr();
            client_sock.on_open_(client_sock, find_it->second.user_data_ptr());
            return fd;
        }

        // Assume the socket to release in loop->to_delete_socks_ is not empty
        static void ReclaimOneSocketFromLoop(FLoop *loop) {
            SocketData &to_delete = loop->to_delete_socks_.back();
            size_t data_size = to_delete.user_data_size;
            if (to_delete.type == SOCKET_TYPE_PLAIN_TCP) {
                TCPSocket *sock_ptr = to_delete.sock_ptr();
                TCPAllocTraits::destroy(loop->tcp_alloc_, sock_ptr);
                data_size += sizeof(TCPSocket);
            }
            else if (to_delete.type == SOCKET_TYPE_TLS_TCP){
//                    FWS_ASSERT(to_delete.type == SOCKET_TYPE_TLS_TCP);
                TLSSocket *sock_ptr = to_delete.tls_sock_ptr();
                TLSAllocTraits::destroy(loop->tls_alloc_, sock_ptr);
                data_size += sizeof(TLSSocket);
            }
            else if (to_delete.type == SOCKET_TYPE_PLAIN_WS) {
                if (to_delete.is_server) {
                    auto *sock_ptr = static_cast<WSServerSocket<false>*>(to_delete.data_ptr);
                    WSPlainServerAlloc alloc{};
                    WSPlainServerAllocTraits::destroy(alloc, sock_ptr);
                    data_size += sizeof(WSServerSocket<false>);
                }
                else {
                    auto *sock_ptr = static_cast<WSClientSocket<false>*>(to_delete.data_ptr);
                    WSPlainClientAlloc alloc{};
                    WSPlainClientAllocTraits::destroy(alloc, sock_ptr);
                    data_size += sizeof(WSClientSocket<false>);
                }

            }
            else {
                FWS_ASSERT(to_delete.type == SOCKET_TYPE_TLS_WS);
                if (to_delete.is_server) {
                    auto *sock_ptr = static_cast<WSServerSocket<true>*>(to_delete.data_ptr);
                    WSTLSServerAlloc alloc{};
                    WSTLSServerAllocTraits::destroy(alloc, sock_ptr);
                    data_size += sizeof(WSServerSocket<true>);
                }
                else {
                    auto *sock_ptr =  static_cast<WSClientSocket<true>*>(to_delete.data_ptr);
                    WSTLSClientAlloc alloc{};
                    WSTLSClientAllocTraits::destroy(alloc, sock_ptr);
                    data_size += sizeof(WSClientSocket<true>);
                }
            }


            loop->byte_alloc_.deallocate((char*)to_delete.data_ptr, data_size);
            loop->to_delete_socks_.pop_back();
        }

        static void PreExit(FLoop *loop) {
            while (!loop->fd_to_socks_.empty()) {
                auto first_it = loop->fd_to_socks_.begin();
                loop->DeleteFd(first_it->first, true);
            }
            while (!loop->to_delete_socks_.empty()) {
                ReclaimOneSocketFromLoop(loop);
            }
            loop->clean_up_flag_ = true;
        }

        static int OneStep(void *this_ptr) {
            auto *loop = (FLoop*)this_ptr;
            // May bring some overhead, consider to update it in a lower frequency
            if constexpr (constants::ENABLE_FLOOP_EVENT_TIME_UPDATE) {
                loop->last_event_time_ns_ = GetNowNsFromEpoch();
            }

            if FWS_UNLIKELY(loop->stop_run_flag_) {
                PreExit(loop);
                // clean_up_flag_ is set in PreExit, will stop the loop
                return 0;
            }
            int n_events = 0;

            if constexpr (constants::FEVENT_WAIT_RETURN_IMMEDIATELY) {
                timespec ts{0, 0};
                n_events = fws::FEventWait(loop->fq_, nullptr, 0, loop->wait_evs_.data(),
                                           MAX_MONITOR_EVENT_NUM, &ts);
            }
            else {
                n_events = fws::FEventWait(loop->fq_, nullptr, 0, loop->wait_evs_.data(),
                                           MAX_MONITOR_EVENT_NUM, nullptr);
            }
            if FWS_UNLIKELY(n_events < 0) {
                SetErrorFormatStr("Failed to wait for events, errno: %d\n%s",
                                  errno, std::strerror(errno));
                fprintf(stderr, "%s", GetErrorStrP());
                std::abort();
            }
            for (int k = 0; k < n_events; ++k) {
                auto &FWS_RESTRICT event = loop->wait_evs_[k];
//                int cur_fd = event.fd();
                void *sock_ptr = event.sock_ptr();
                if FWS_UNLIKELY(event.has_error()) {
                    int error = event.socket_err_code();
                    if (error == EINTR) {
                        SetErrorFormatStr("Epoll wait interrupted\n");
                    }
                    SetErrorFormatStr("event error, flags: %u, ptr: %p, %s\n",
                                      error, sock_ptr, std::strerror(error));
//                    SetErrorFormatStr("event error, flags: %u, fd: %d, %s\n",
//                                      error, cur_fd, std::strerror(error));
                    auto find_it = loop->fd_to_socks_.find(sock_ptr);
                    FWS_ASSERT(find_it != loop->fd_to_socks_.end());
                    auto& sock = *find_it->second.sock_ptr();
                    if (sock.status() & SEMI_SOCKET_STATUS) {
                        sock.on_error_(sock, error, GetErrorStrV(), find_it->second.user_data_ptr());
                    }
                    loop->DeleteFd(sock_ptr, true);
                }
                else {
                    if (event.is_writable()) {
                        auto find_it = loop->fd_to_socks_.find(sock_ptr);
                        if FWS_UNLIKELY(find_it == loop->fd_to_socks_.end()) {
//                            fprintf(stderr, "Cannot find socket for fd: %d in write event\n", cur_fd);
                            fprintf(stderr, "Cannot find socket for ptr: %p in write event\n", sock_ptr);
                            continue;
                        }
                        auto& sock = *find_it->second.sock_ptr();
                        void *user_data_ptr = find_it->second.user_data_ptr();
                        int cur_fd = sock.fd();
                        if FWS_UNLIKELY(sock.status() & SEMI_SOCKET_STATUS) {
                            FWS_ASSERT(!sock.is_open());
                            sock.is_opened_ = true;
                            sock.status_ = NORMAL_SOCKET_STATUS;
                            AddFEvent(loop->fq_, cur_fd, fws::FEVAC_READ, sock_ptr);
                            sock.on_open_(sock, user_data_ptr);
                        }
                        else {
                            sock.last_write_failed_ = false;
                            size_t writable_bytes = event.send_buf_size();
                            sock.on_writable_(sock, writable_bytes, user_data_ptr);
                            if (sock.last_write_failed_ == false || sock.status() & SHUTDOWN_SOCKET_STATUS) {
                                DeleteFEvent(loop->fq_, cur_fd, FEVAC_WRITE, sock_ptr);
                            }
                            if FWS_UNLIKELY(!sock.is_open()) {
                                loop->DeleteFd(sock_ptr, false);
                            }
                        }


                    } // if event.is_writable
                    else {
                        if (event.is_readable()) {
                            size_t max_readable_bytes = event.readable_size(); // not real
                            auto find_it = loop->fd_to_socks_.find(sock_ptr);
                            if FWS_UNLIKELY(find_it == loop->fd_to_socks_.end()) {
//                                fprintf(stderr, "Cannot find socket for fd: %d in read event, n_events: %d\n",
//                                        cur_fd, n_events);
                                fprintf(stderr, "Cannot find socket for ptr: %p in read event, n_events: %d\n",
                                        sock_ptr, n_events);
                                std::abort();
                            }
//                    auto& client_data = find_it->second;
                            auto &sock = *find_it->second.sock_ptr();
                            size_t user_data_size = find_it->second.user_data_size;
                            SocketType sock_type = find_it->second.type;
                            void *user_data_ptr = find_it->second.user_data_ptr();
                            if FWS_UNLIKELY(sock.status() & SEMI_SOCKET_STATUS) {
                                // Server keeps accept
                                while (true) {

                                    int new_client_fd = loop->TryAcceptOneClient(&sock, sock_type,
                                                                                 user_data_size);
                                    if (new_client_fd <= 0) {
                                        if FWS_UNLIKELY(new_client_fd < 0) {
                                            sock.on_error_(sock, errno, GetErrorStrV(),
                                                           user_data_ptr);
                                        }
                                        break;
                                    }
                                }
                            } else {
                                bool should_continue_read = true;
                                int sock_fd = sock.fd();
                                while (should_continue_read) {
                                    IOBuffer buf = sock.Read(max_readable_bytes,
                                                             constants::DEFAULT_READ_BUF_PRE_PADDING_SIZE);
                                    should_continue_read = false;
                                    ssize_t buf_size = buf.size;
                                    if (buf_size > 0) {

                                        sock.on_readable_(sock, std::move(buf), user_data_ptr);
                                        if (buf_size == (ssize_t) max_readable_bytes &&
                                            sock.is_open()) {
                                            should_continue_read = true;
                                        } else if FWS_UNLIKELY(!sock.is_open()) {
                                            loop->DeleteFd(sock_ptr, false);
                                        }

                                    } else if (buf_size == 0) {
                                        if (sock.status() & SHUTDOWN_SOCKET_STATUS) {
//                                    sock.on_close_(sock, client_data.ptr);
//                                        printf("DeleteFd %d in event.is_readable, buf.size == 0, already in SHUTDOWN\n", cur_fd);
                                            loop->DeleteFd(sock_ptr, true);

                                        } else {
                                            // read return 0, eof
                                            DeleteFEvent(loop->fq_, sock_fd, FEVAC_READ, sock_ptr);
                                            // user may call Close in on_eof_
                                            sock.on_eof_(sock, user_data_ptr);
//                                        printf("DeleteFd %d in event.is_readable, buf.size==0, not in SHUTDOWN\n", cur_fd);
                                            loop->DeleteFd(sock_ptr, false);
//                                    loop->DeleteTcpSocket(cur_fd, false);
                                        }
                                    } else {
                                        int err_code = errno;
                                        if (!(err_code == EAGAIN || err_code == EWOULDBLOCK)) {
                                            sock.on_error_(sock, err_code, std::strerror(err_code),
                                                           user_data_ptr);
//                                        printf("DeleteFd %d in event.is_readable, buf.size < 0\n", cur_fd);
                                            loop->DeleteFd(sock_ptr, true);
//                                    loop->DeleteTcpSocketFromIt(find_it, true);
                                        }
                                    }
                                }


                            }

                        }
                        // TODO: One thing is painful. In epoll, when there is an
                        // eof event, there will be no pollin or pollout event for
                        // that fd. However, it is not the case for kqueue. In kevent,
                        // a event can both be eof and readable/writable.
                        // If we handle eof first, we may not be able to do a clean
                        // close of the application protocol.
                        if FWS_UNLIKELY(event.is_eof()) {
                            auto find_it = loop->fd_to_socks_.find(sock_ptr);
                            if (find_it != loop->fd_to_socks_.end()) {
                                auto &sock = *find_it->second.sock_ptr();
                                if (sock.status() & SEMI_SOCKET_STATUS) {
                                    sock.on_error_(sock, ECONNRESET,
                                                   std::string_view("Eof for semi socket"),
                                                   find_it->second.user_data_ptr());
                                } else {
                                    if (!(sock.status() & SHUTDOWN_SOCKET_STATUS)) {
                                        sock.Shutdown(fws::TCPSocket::SHUT_WR_MODE);
                                    }
//                            sock.on_close_(sock, find_it->second.ptr);
                                }
//                        printf("DeleteFd %d in event.is_eof, n_events: %d\n", cur_fd, n_events);
                                loop->DeleteFd(sock_ptr, true);
//                        loop->DeleteTcpSocketFromIt(find_it, true);
                            }

                        }
                    } // else branch of if event.is_writable
                }


            } // for k
            while (!loop->to_delete_socks_.empty()) {
                ReclaimOneSocketFromLoop(loop);
            }
            loop->on_event_(*loop);
            return 0;

        } // OneStep FUnc

    }; // class FLoop

} // namespace fws