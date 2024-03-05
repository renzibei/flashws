#pragma once

#include "flashws/base/base_include.h"
#include <climits>
#include <utility>

#ifndef FWS_ENABLE_FSTACK

//#define FWS_EPOLL 1

#if defined(FWS_LINUX) && !defined(FWS_FORCE_NO_EPOLL)
#   define FWS_EPOLL
#   include <sys/epoll.h>
#   include <linux/sockios.h>
#else
#   define FWS_POLL
#   include <poll.h>
#endif

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "flashws/utils/flat_hash_map.h"

#endif

namespace fws {

    struct FQueue {
        int fd;
        FQueue() noexcept: fd(0) {}
        FQueue(int fd) noexcept: fd(fd) {}
        FQueue(const FQueue&) = delete;
        FQueue(FQueue &&o) noexcept: fd(std::exchange(o.fd, 0)) {}
        FQueue& operator=(FQueue&& o) noexcept {
            if (this != &o) {
                std::swap(this->fd, o.fd);
            }
            return *this;
        }
        FQueue& operator=(const FQueue&) = delete;

        ~FQueue();
    };

#ifdef FWS_ENABLE_FSTACK

    enum FEventFilter: int16_t {
        FEVFILT_READ = EVFILT_READ,
        FEVFILT_WRITE = EVFILT_WRITE,
        FEVFILT_AIO = EVFILT_AIO,
        FEVFILT_EMPTY = EVFILT_EMPTY,
    };

    enum FEventFlag: uint16_t {
        FEV_ADD = EV_ADD,
        FEV_DELETE = EV_DELETE,
        FEV_ENABLE = EV_ENABLE,
        FEV_DISABLE = EV_DISABLE,
        FEV_FORCEONESHOT = EV_FORCEONESHOT,
        FEV_ONESHOT = EV_ONESHOT,
        FEV_CLEAR = EV_CLEAR,
        FEV_RECEIPT = EV_RECEIPT,
        FEV_DISPATCH = EV_DISPATCH,
        FEV_SYSFLAGS = EV_SYSFLAGS,
        FEV_EOF = EV_EOF,
        FEV_ERROR = EV_ERROR,
    };

    inline FEventFlag operator| (FEventFlag a, FEventFlag b) {
        return static_cast<FEventFlag>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
    }

    enum FEventFFlag: uint32_t {
        FEFFLAG_NONE = 0,
        FNOTE_LOWAT = NOTE_LOWAT,
    };

    class FEvent : protected kevent {

    public:
        FEvent(uintptr_t fd, FEventFilter filter, FEventFlag flags,
               FEventFFlag fflags, intptr_t data, void* udata) noexcept {
            this->ident = fd;
            this->filter = filter;
            this->flags = flags;
            this->fflags = fflags;
            this->data = data;
            this->udata = udata;
            this->ext[0] = 0;
            this->ext[1] = 0;
            this->ext[2] = 0;
            this->ext[3] = 0;
        }
        FEvent() = default;

        [[nodiscard]] bool is_eof() const {
            return flags & FEV_EOF;
        }

        [[nodiscard]] int socket_err_code() const {

            return static_cast<int>(fflags);
        }

        [[nodiscard]] bool has_error() const {
            return flags & FEV_ERROR;
        }

        [[nodiscard]] int64_t error_code() const {
            return data;
        }

        [[nodiscard]] bool is_readable() const {
            return filter == FEVFILT_READ;
        }

        [[nodiscard]] bool is_writable() const {
            return filter == FEVFILT_WRITE;
        }

        [[nodiscard]] int64_t send_buf_size() const {
            return data;
        }

        [[nodiscard]] int64_t readable_size() const {
            // TODO: Investigate how to tune this.
//            return constants::MAX_READABLE_SIZE_ONE_TIME;
            return data;
        }

        [[nodiscard]] int64_t available_accept_size() const {
            return data;
        }

//        [[nodiscard]] int fd() const {
//            return static_cast<int>(ident);
//        }

        [[nodiscard]] void* sock_ptr() const {
            return udata;
        }

    };

    static_assert(sizeof(FEvent) == sizeof(kevent));

    enum FEventAction {
        FEVAC_READ = 0x1,
        FEVAC_WRITE = 0x2,
    };

    inline FEventAction operator| (FEventAction a, FEventAction b) {
        return static_cast<FEventAction>(static_cast<int>(a) | static_cast<int>(b));
    }

    int AddFEvent(FQueue &fq, int fd, FEventAction action, void *sock_ptr) {
        FEvent change_evs[2];
        int change_idx = 0;
        if (action & FEVAC_READ) {
            change_evs[change_idx++] = FEvent(fd, FEVFILT_READ, FEV_ADD,
                                              FEFFLAG_NONE, 0, sock_ptr);
        }
        if (action & FEVAC_WRITE) {
            change_evs[change_idx++] = FEvent(fd, FEVFILT_WRITE, FEV_ADD,
                                              FEFFLAG_NONE, 0, sock_ptr);
        }
        int ret = ff_kevent(fq.fd, (kevent*)change_evs, change_idx, nullptr, 0, nullptr);
        return ret;
    }

    int DeleteFEvent(FQueue &fq, int fd, FEventAction action, void *sock_ptr) {
        FEvent change_evs[2];
        int change_idx = 0;
        if (action & FEVAC_READ) {
            change_evs[change_idx++] = FEvent(fd, FEVFILT_READ, FEV_DELETE,
                                              FEFFLAG_NONE, 0, sock_ptr);
        }
        if (action & FEVAC_WRITE) {
            change_evs[change_idx++] = FEvent(fd, FEVFILT_WRITE, FEV_DELETE,
                                              FEFFLAG_NONE, 0, sock_ptr);
        }
        int ret = ff_kevent(fq.fd, (kevent*)change_evs, change_idx, nullptr, 0, nullptr);
        return ret;
    }
#else

#ifdef FWS_EPOLL

    enum FEventFilter: int16_t {
        FEVFILT_READ = EPOLLIN,
        FEVFILT_WRITE = EPOLLOUT,
//        FEVFILT_AIO = -3,
//        FEVFILT_EMPTY = -13,
    };

    enum FEventFlag: uint16_t {
        FEV_ADD = EPOLL_CTL_ADD,
        FEV_DELETE = EPOLL_CTL_DEL,
        // Some flags are disabled in linux
//        FEV_ENABLE = 0x0004,
//        FEV_DISABLE = 0x0008,
//        FEV_FORCEONESHOT = 0x0100,
//        FEV_ONESHOT = 0x0010,
//        FEV_CLEAR = 0x0020,
//        FEV_RECEIPT = 0x0040,
//        FEV_DISPATCH = 0x0080,
//        FEV_SYSFLAGS = 0xF000,
        FEV_EOF = 0x8000,
        FEV_ERROR = 0x4000,
    };
#else
    enum FEventFilter: int16_t {
        FEVFILT_READ = POLLIN,
        FEVFILT_WRITE = POLLOUT,
//        FEVFILT_AIO = -3,
//        FEVFILT_EMPTY = -13,
    };

    enum FEventFlag: uint16_t {
        FEV_ADD = 0x0001,
        FEV_DELETE = 0x0002,
        // Some flags are disabled in linux
        FEV_EOF = 0x8000,
        FEV_ERROR = 0x4000,
    };
#endif

    inline FEventFlag operator| (FEventFlag a, FEventFlag b) {
        return static_cast<FEventFlag>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
    }

    enum FEventFFlag: uint32_t {
        FEFFLAG_NONE = 0,
        FNOTE_LOWAT = 0x0001,
    };
#ifdef FWS_EPOLL
    class FEvent : protected epoll_event {
    public:
        FEvent() = default;

        FEvent(uint32_t events, void *sock_ptr) {
            this->events = events;
            this->data.ptr = sock_ptr;
        }

        [[nodiscard]] bool is_eof() const {
            return events & EPOLLHUP;
        }

        [[nodiscard]] int socket_err_code() const {
            int       error = 0;
            socklen_t errlen = sizeof(error);
            void *sock_ptr = data.ptr;
            // fd is the first member variable of socket
            int fd = *(int*)sock_ptr;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) == 0) {
                return error;
            }
            return errno;
        }

        [[nodiscard]] bool has_error() const {
            return events & EPOLLERR;
        }

        [[nodiscard]] int64_t error_code() const {
            return errno;
        }

        [[nodiscard]] bool is_readable() const {
            return events & EPOLLIN;
        }

        [[nodiscard]] bool is_writable() const {
            return events & EPOLLOUT;
        }

        [[nodiscard]] int64_t send_buf_size() const {
            return 1LL << 21;
        }

        [[nodiscard]] int64_t readable_size() const {
            return constants::MAX_READABLE_SIZE_ONE_TIME;
        }

        [[nodiscard]] int64_t available_accept_size() const {
            return 1;
        }

        [[nodiscard]] void* sock_ptr() const {
            return data.ptr;
        }

//        [[nodiscard]] int fd() const {
//            return data.fd;
//        }

    protected:
    };
#else
    class FEvent : protected pollfd {
    public:
        FEvent() = default;

//        FEvent(uint32_t events, void *sock_ptr) {
//            this->events = events;
//            this->data.ptr = sock_ptr;
//        }
        FEvent(uint32_t events, int fd, void *sock_ptr) {
            this->events = events;
            this->fd = fd;
            this->udata = sock_ptr;
        }

        [[nodiscard]] bool is_eof() const {
            return revents & POLLHUP;
        }

        [[nodiscard]] int socket_err_code() const {
            int       error = 0;
            socklen_t errlen = sizeof(error);
//            void *sock_ptr = data.ptr;
            // fd is the first member variable of socket
//            int fd = *(int*)sock_ptr;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) == 0) {
                return error;
            }
            return errno;
        }

        [[nodiscard]] bool has_error() const {
            return revents & POLLERR;
        }

        [[nodiscard]] int64_t error_code() const {
            return errno;
        }

        [[nodiscard]] bool is_readable() const {
            return revents & POLLIN;
        }

        [[nodiscard]] bool is_writable() const {
            return revents & POLLOUT;
        }

        [[nodiscard]] int64_t send_buf_size() const {
            return 1LL << 21;
        }

        [[nodiscard]] int64_t readable_size() const {
            return constants::MAX_READABLE_SIZE_ONE_TIME;
        }

        [[nodiscard]] int64_t available_accept_size() const {
            return 1;
        }

        [[nodiscard]] void* sock_ptr() const {
            return udata;
        }

        [[nodiscard]] int Fd() const {
            return this->fd;
        }

        void SetFd(int fd) {
            this->fd = fd;
        }

        void SetData(void* data) {
            this->udata = data;
        }

        void SetRevents(short revents) {
            this->revents = revents;
        }

    protected:
        void *udata = nullptr;

        friend int FEventWait(FQueue &fq, const FEvent* change_list,
                              int n_changes, FEvent* event_list, int n_events,
                              const timespec* timeout);
    };
#endif


#endif

    namespace detail {

#if !defined(FWS_ENABLE_FSTACK)
        struct FdInfo {
            int cur_evs = 0;
            void *user_data = nullptr;
        };
        using FdInfoMap = ska::flat_hash_map<int, FdInfo>;
        using QueueToFdInfoMap = ska::flat_hash_map<int, FdInfoMap>;
        inline thread_local QueueToFdInfoMap queue_to_fd_info_map;
#endif

    };//namespace detail

    FWS_ALWAYS_INLINE FQueue CreateFQueue(int size = 8) {
        (void)size;
#ifdef FWS_ENABLE_FSTACK
        int kq_fd = ff_kqueue();
        return FQueue{kq_fd};
#elif defined(FWS_EPOLL)
        int epoll_fd = epoll_create(size);
        return FQueue{epoll_fd};
#else
        int new_fq_fd = (int)detail::queue_to_fd_info_map.size() + 1;
        detail::queue_to_fd_info_map.emplace(new_fq_fd, detail::FdInfoMap{});
        return FQueue(new_fq_fd);
//        static_assert(false, "Un supoorted OS");
#endif
    }

    FQueue::~FQueue() {
        if (this->fd != 0) {
#ifdef FWS_ENABLE_FSTACK
            ff_close(this->fd);
#elif defined(FWS_EPOLL)
            close(fd);
#else
            detail::queue_to_fd_info_map.erase(fd);
#endif
            this->fd = 0;
        }
    };


#ifdef FWS_EPOLL
    enum FEventAction {
        FEVAC_READ = EPOLLIN,
        FEVAC_WRITE = EPOLLOUT,
    };

    inline FEventAction operator| (FEventAction a, FEventAction b) {
        return static_cast<FEventAction>(static_cast<int>(a) | static_cast<int>(b));
    }

    int AddFEvent(FQueue &fq, int fd, FEventAction action, void *sock_ptr) {
        auto &fd_info_map = detail::queue_to_fd_info_map[fq.fd];

        auto find_it = fd_info_map.find(fd);
        if (find_it == fd_info_map.end()) {
            auto [insert_it, ok] = fd_info_map.emplace(fd, detail::FdInfo{0});
            (void)ok;
            find_it = insert_it;
        }
        int cur_events = find_it->second.cur_evs;
        int target_events = cur_events | action;
        int op = 0;
        if (!cur_events & (bool)target_events) {
            op = EPOLL_CTL_ADD;
        }
        else if ((bool)cur_events & !target_events) {
            op = EPOLL_CTL_DEL;
        }
        else if (cur_events != target_events) {
            op = EPOLL_CTL_MOD;
        }
        // If need to modify events
        if FWS_LIKELY(op != 0) {
            FEvent change_ev(target_events, sock_ptr);
            int epoll_ctl_ret = epoll_ctl(fq.fd, op, fd, (epoll_event*)&change_ev);
            if FWS_UNLIKELY(epoll_ctl_ret < 0) {
                SetErrorFormatStr("epoll return %d, fq.fd: %d, fd: %d, %s",
                                  epoll_ctl_ret, fq.fd, fd, std::strerror(errno));
                return epoll_ctl_ret;
            }
            find_it->second.cur_evs = target_events;
            return epoll_ctl_ret;
        }
        return 0;

    }

    int DeleteFEvent(FQueue &fq, int fd, FEventAction action, void* sock_ptr) {
        auto &fd_info_map = detail::queue_to_fd_info_map[fq.fd];

        auto find_it = fd_info_map.find(fd);
        if FWS_LIKELY(find_it == fd_info_map.end()) {
            auto [insert_it, ok] = fd_info_map.emplace(fd, detail::FdInfo{0});
            (void)ok;
            find_it = insert_it;
        }
        int cur_events = find_it->second.cur_evs;
        int target_events = cur_events & ~action;
        int op = 0;
        if (!cur_events & (bool)target_events) {
            op = EPOLL_CTL_ADD;
        }
        else if ((bool)cur_events & !target_events) {
            op = EPOLL_CTL_DEL;
        }
        else if (cur_events != target_events) {
            op = EPOLL_CTL_MOD;
        }

        FEvent change_ev(target_events, sock_ptr);
        int epoll_ctl_ret = epoll_ctl(fq.fd, op, fd, (epoll_event*)&change_ev);
        if FWS_UNLIKELY(epoll_ctl_ret < 0) {
            SetErrorFormatStr("epoll return %d, %s",
                              epoll_ctl_ret, std::strerror(errno));
            return epoll_ctl_ret;
        }
        find_it->second.cur_evs = target_events;
        return epoll_ctl_ret;
    }
#elif defined(FWS_POLL)
    enum FEventAction {
        FEVAC_READ = POLLIN,
        FEVAC_WRITE = POLLOUT,
    };

    inline FEventAction operator| (FEventAction a, FEventAction b) {
        return static_cast<FEventAction>(static_cast<int>(a) | static_cast<int>(b));
    }

    int AddFEvent(FQueue &fq, int fd, FEventAction action, void *sock_ptr) {
        auto &fd_info_map = detail::queue_to_fd_info_map[fq.fd];

        auto find_it = fd_info_map.find(fd);
        if (find_it == fd_info_map.end()) {
            auto [insert_it, ok] = fd_info_map.emplace(fd, detail::FdInfo{0});
            (void)ok;
            find_it = insert_it;
        }
        int cur_events = find_it->second.cur_evs;
        int target_events = cur_events | action;
        find_it->second.cur_evs = target_events;
        find_it->second.user_data = sock_ptr;
        return 0;

    }

    int DeleteFEvent(FQueue &fq, int fd, FEventAction action, void* /*sock_ptr*/) {
        auto &fd_info_map = detail::queue_to_fd_info_map[fq.fd];

        auto find_it = fd_info_map.find(fd);
        if (find_it == fd_info_map.end()) {
            return 0;
        }
        int cur_events = find_it->second.cur_evs;
        int target_events = cur_events & ~action;
        find_it->second.cur_evs = target_events;
        if FWS_LIKELY(!target_events) {
            fd_info_map.erase(find_it);
        }

        return 0;
    }
#endif


    int FEventWait(FQueue &fq, const FEvent* change_list,
                         int n_changes, FEvent* event_list, int n_events,
                         const timespec* timeout) {

#ifdef FWS_ENABLE_FSTACK
        return ff_kevent(fq.fd, (const kevent*)change_list, n_changes, (kevent*)event_list, n_events,
                         timeout);
#elif defined(FWS_EPOLL)
        FWS_ASSERT(n_changes == 0);
        (void)(change_list);
        if (n_events > 0) {
            int timeout_ms = -1;
            if (timeout != nullptr) {
                int64_t temp_timeout_ms = timeout->tv_sec * (1000LL) + timeout->tv_nsec / (1000000LL);
                FWS_ASSERT(temp_timeout_ms <= INT_MAX);
                timeout_ms = int(temp_timeout_ms);
            }
            int ret = epoll_wait(fq.fd, (epoll_event*)event_list, n_events, timeout_ms);
            return ret;

        }
        return 0;
#else
        auto& FWS_RESTRICT fd_info_map = detail::queue_to_fd_info_map[fq.fd];
        FWS_ASSERT(n_changes == 0);
        (void)(change_list);
        if (n_events > 0) {
            size_t registered_fd_size = fd_info_map.size();
            size_t pollfd_bytes = registered_fd_size * sizeof(pollfd);
            IOBuffer events_buf = RequestBuf(pollfd_bytes);
            pollfd* pollfd_data = (pollfd*)(events_buf.data);
            int timeout_ms = -1;
            if (timeout != nullptr) {
                int64_t temp_timeout_ms = timeout->tv_sec * (1000LL) + timeout->tv_nsec / (1000000LL);
                FWS_ASSERT(temp_timeout_ms <= INT_MAX);
                timeout_ms = int(temp_timeout_ms);
            }
            size_t fd_cnt = 0;
            for (const auto&[fd, fd_info]: fd_info_map) {
                pollfd_data[fd_cnt] = pollfd{fd, (short)fd_info.cur_evs, 0};
                ++fd_cnt;
            }
            int poll_ret = poll(pollfd_data, registered_fd_size, timeout_ms);
            if FWS_UNLIKELY(poll_ret < 0) {
                SetErrorFormatStr("poll return %d, %s",
                                  poll_ret, std::strerror(errno));
                return poll_ret;
            }
            int should_stop_cnt = std::min(poll_ret, n_events);
            int handled_fds = 0;
            for (size_t i = 0; (i < registered_fd_size) & (handled_fds < should_stop_cnt); ++i) {
                auto &ep_event = pollfd_data[i];
                auto ep_flag = ep_event.revents;
                if (ep_flag == 0) {
                    continue;
                }
                auto &f_event = event_list[handled_fds++];
                f_event = FEvent{};
                int fd = ep_event.fd;
                // set fd, revents
                static_cast<pollfd&>(f_event) = ep_event;
                auto find_it = fd_info_map.find(fd);
                f_event.udata = find_it->second.user_data;


            }
            return poll_ret;
        }
        return 0;
#endif
    }

} // namespace fws