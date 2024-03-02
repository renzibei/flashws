#pragma once

#include "flashws/base/base_include.h"
#include "flashws/net/tcp_socket.h"
#include "flashws/net/fevent.h"
#include "flashws/net/w_socket.h"
#include "flashws/net/ws_server_socket.h"

namespace fws {


    class WsServer {

    public:

        WsServer(bool no_delay = false, int busy_poll_us = 0) noexcept:
                poll_us_(busy_poll_us), no_delay_(no_delay) {}

        template<class EventHandler>
        int HandleFEvent(FQueue& FWS_RESTRICT fq, const FEvent& FWS_RESTRICT event,
                         EventHandler& FWS_RESTRICT handler) {
            if FWS_UNLIKELY(event.has_error()) {
                SetErrorFormatStr("Error in event, flags: %u", event.socket_err_code());
                return -1;
            }
            else {



#ifdef FWS_ENABLE_FSTACK
                int available = event.available_accept_size();
#ifdef FWS_DEV_DEBUG
                fprintf(stderr, "ws server %d get %d sockets to accept\n",
                        tcp_socket_.fd(), available);
#endif
//                size_t need_fevent_size = sizeof(fws::FEvent) * available;
//                IOBuffer events_buf = RequestBuf(need_fevent_size);
//                FEvent* ev_start = (FEvent*)(events_buf.data);
//                size_t ev_cnt = 0;
#endif

                while(true) {
#ifdef FWS_ENABLE_FSTACK
                    if (available-- <= 0) {
                        break;
                    }
#endif
                    auto new_opt_sock = tcp_socket_.Accept(nullptr, nullptr);
                    if (!new_opt_sock.has_value()) {
                        if FWS_LIKELY(errno == EWOULDBLOCK) {
                            break;
                        }
                        SetErrorFormatStr("WS server failed to accept new socket");
                        return -2;
                    }
                    auto &new_tcp_sock = new_opt_sock.value();
                    int new_fd = new_tcp_sock.fd();
                    if FWS_UNLIKELY(new_tcp_sock.SetNonBlock() < 0) {
                        SetErrorFormatStr("Failed to set new socket non-blocking");
                        return -3;
                    }
                    if (no_delay_) {
                        if FWS_UNLIKELY(new_tcp_sock.SetNoDelay() < 0) {
                            SetErrorFormatStr("Failed to set new socket no delay");
                            return -4;
                        }
                    }
                    if (poll_us_ > 0) {
                        if FWS_UNLIKELY(new_tcp_sock.SetBusyPoll(poll_us_) < 0) {
                            return -7;
                        }
                    }
                    int add_read_ret = AddFEvent(fq, new_fd, FEVAC_READ);
                    if FWS_UNLIKELY(add_read_ret < 0) {
                        SetErrorFormatStr("Error in add read event for new socket");
                        return -5;
                    }
//#ifdef FWS_ENABLE_FSTACK
//                    ev_start[ev_cnt++] = FEvent(new_fd, FEVFILT_READ, FEV_ADD, FEFFLAG_NONE,
//                                      0, nullptr);
//#else
//                    FEvent read_event(new_fd, FEVFILT_READ, FEV_ADD, FEFFLAG_NONE,
//                                      0, nullptr);
//                    if FWS_UNLIKELY(fws::FEventWait(fq, &read_event, 1, nullptr, 0, nullptr) < 0) {
//                        return -5;
//                    }
//#endif
                    fws::WSServerSocket new_wsocket{};
                    new_wsocket.Init(new_tcp_sock);
                    handler.OnNewTcpConnection(new_wsocket);
                }
//#ifdef FWS_ENABLE_FSTACK
//                if FWS_UNLIKELY(fws::FEventWait(fq, ev_start, ev_cnt, nullptr, 0, nullptr) < 0) {
//                        return -6;
//                }
//#endif
            }
            return 0;
        }

        int StartListen(const char* host_ip_addr,
                                             uint16_t port, int backlog,
                     TCPSocket::BindMode bind_mode) {
            if FWS_UNLIKELY(tcp_socket_.Init() < 0) {
                return -1;
            }
            if FWS_UNLIKELY(tcp_socket_.SetNonBlock() < 0) {
                tcp_socket_.Close();
                return -2;
            }
            if FWS_UNLIKELY(tcp_socket_.Bind(host_ip_addr, port, bind_mode) < 0) {
                tcp_socket_.Close();
                return -3;
            }
            if FWS_UNLIKELY(tcp_socket_.Listen(backlog) < 0) {
                tcp_socket_.Close();
                return -4;
            }
            return 0;
        }

        TCPSocket& tcp_socket() {
            return tcp_socket_;
        }

    protected:
        TCPSocket tcp_socket_;
        int poll_us_;
        bool no_delay_;

    }; // class WsServer

} // namespace fws