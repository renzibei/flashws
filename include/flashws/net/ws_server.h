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
                         EventHandler& FWS_RESTRICT handler) FWS_FUNC_RESTRICT {
            if FWS_UNLIKELY(event.flags & fws::FEV_ERROR) {
                SetErrorFormatStr("Error in event, flags: %u", event.flags);
                return -1;
            }
            else {
                int available = static_cast<int>(event.data);

                do {
                    auto new_opt_sock = tcp_socket_.Accept(nullptr, nullptr);
                    if FWS_UNLIKELY(!new_opt_sock.has_value()) {
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
                    FEvent read_event(new_fd, FEVFILT_READ, FEV_ADD, FEFFLAG_NONE,
                                      0, nullptr);
                    if FWS_UNLIKELY(fws::FEventWait(fq, &read_event, 1, nullptr, 0, nullptr) < 0) {
                        return -5;
                    }
                    fws::WSServerSocket new_wsocket{};
                    new_wsocket.Init(new_tcp_sock);
                    handler.OnNewTcpConnection(new_wsocket);
                } while(--available);
            }
            return 0;
        }

        int StartListen(const char* host_ip_addr,
                                             uint16_t port, int backlog,
                     TcpSocket::BindMode bind_mode) {
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

        TcpSocket& tcp_socket() {
            return tcp_socket_;
        }

    protected:
        TcpSocket tcp_socket_;
        int poll_us_;
        bool no_delay_;

    }; // class WsServer

} // namespace fws