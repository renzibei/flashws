#pragma once
#include "flashws/net/w_socket.h"

namespace fws {

    class WSClientSocket: public WSocket<WSClientSocket, false> {
    protected:
        enum ClientStatus {
            CLOSE_STATUS = 0,
            WAIT_TCP_CONNECT = 1,
            WAIT_HTTP_REPLY = 2,
            OPEN_STATUS = 3,
        };

        friend class WSocket<WSClientSocket, false>;

    public:
        int Init(bool no_delay, int busy_poll_us = 0) {
            int tcp_init_ret = tcp_socket_.Init();
            client_status_ = CLOSE_STATUS;
            if FWS_UNLIKELY(tcp_init_ret < 0) {
                return tcp_init_ret;
            }
            int tcp_set_nb_ret = tcp_socket_.SetNonBlock();
            if FWS_UNLIKELY(tcp_set_nb_ret < 0) {
                return tcp_set_nb_ret;
            }
            if (no_delay) {
                int tcp_set_ret = tcp_socket_.SetNoDelay();
                if FWS_UNLIKELY(tcp_set_ret < 0) {
                    return tcp_set_ret;
                }
            }
            if (busy_poll_us > 0) {
                int busy_poll_ret = tcp_socket_.SetBusyPoll(busy_poll_us);
                if FWS_UNLIKELY(busy_poll_ret < 0) {
                    return busy_poll_ret;
                }
            }
            return 0;
        }

        int Close(WSStatusCose close_code, std::string_view reason) FWS_FUNC_RESTRICT {
            return CloseCon(close_code, reason);
        }

        template<class EventHandler>
        int HandleFEvent(const FEvent& FWS_RESTRICT event,
                         EventHandler& FWS_RESTRICT handler) FWS_FUNC_RESTRICT {
            uint32_t flags = event.flags;
            if FWS_UNLIKELY(client_status_ == CLOSE_STATUS) {
                SetErrorFormatStr("WS Client Socket is CLOSED, shouldn't be called");
                return -1;
            }
            if FWS_UNLIKELY(flags & FEV_ERROR) {
                return -2;
            }
            else if FWS_UNLIKELY(flags & FEV_EOF) {
                handler.OnCloseConnection(*this, fws::WS_ABNORMAL_CLOSE, {});
                Close(fws::WS_ABNORMAL_CLOSE, {});
                return 0;
            }
            else if (event.filter == FEVFILT_READ) {
                size_t available_size = size_t(event.data);
                auto recv_buf = tcp_socket_.Read(available_size, constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                if FWS_UNLIKELY(recv_buf.data == nullptr) {
                    SetErrorFormatStr("Error when reading in RECVING_REQ\n");
                    return -3;
                }
                if FWS_LIKELY(client_status_ == OPEN_STATUS) {
                    int handle_read_ret = OnRecvData(handler, recv_buf);
                    return handle_read_ret;
                }
                else if (client_status_ == WAIT_HTTP_REPLY) {
                    return HandleHandshakeReply(recv_buf, handler);
                }
                else if (client_status_ == WAIT_TCP_CONNECT) {
                    // Will be connected in writable event
                    return 0;
                }
                else {
                    SetErrorFormatStr("Shouldn't be in this status in read event, status: %d",
                                      client_status_);
                    return -4;
                }
            }
            else if (event.filter == FEVFILT_WRITE) {
                size_t available_size = size_t(event.data);
                if FWS_LIKELY(client_status_ == OPEN_STATUS) {
                    if FWS_UNLIKELY(need_send_control_msg_) {
                        ssize_t handle_control_msg_ret = HandleUnsentControlMsgOnWritable(available_size);
                        if FWS_UNLIKELY(handle_control_msg_ret < 0) {
                            return handle_control_msg_ret;
                        }
                        available_size -= handle_control_msg_ret;
                    }
                    available_size = std::min(available_size, constants::MAX_WRITABLE_SIZE_ONE_TIME);
                    int write_ret = handler.OnWritable(*this, available_size);
                    return write_ret;
                }
                else if (client_status_ == WAIT_TCP_CONNECT) {
                    return SendHandshakeRequest(handler);
                }
                else {
                    SetErrorFormatStr("Shouldn't be in this status in write event, status: %d\n",
                                      client_status_);
                    return -5;
                }
            }
            return 0;
        }

        // User can use fws::GetTxWSFrameHdrSize to calculate the size of frame
        // header. Only when the sum of hdr size and payload size is no less than
        // writable_size, will we make this frame the last frame of a msg.
        FWS_ALWAYS_INLINE ssize_t WriteFrame(IOBuffer& io_buf, size_t writable_size,
                                             WSTxFrameType frame_type,
                                             bool last_frame_if_possible) {
            return SendFrame(io_buf, writable_size, frame_type, last_frame_if_possible);
        }

        int Connect(const char* server_ip, uint16_t host_port,
                    std::string_view request_uri, std::string_view request_host,
                    std::string_view request_origin = {},
                    std::string_view sub_protocols = {},
                    std::string_view extensions = {}) {
            int tcp_con_ret = tcp_socket_.Connect(server_ip, host_port);
            if FWS_UNLIKELY((tcp_con_ret < 0) & (errno != EINPROGRESS)) {
                SetErrorFormatStr("Failed to connect %s:%u in tcp, %s",
                                  server_ip, host_port, std::strerror(errno));
                return tcp_con_ret;
            }

            int make_request_text = MakeHttpRequestText(request_uri,
                        request_host, request_origin, sub_protocols, extensions);
            if FWS_UNLIKELY(make_request_text < 0) {
                return make_request_text;
            }
            client_status_ = WAIT_TCP_CONNECT;
            return 0;
        }

    protected:
        ClientStatus client_status_ = CLOSE_STATUS;

        char expect_reply_sha1[20];

        int CloseClean() {
            client_status_ = CLOSE_STATUS;
            return 0;
        }

        void FillRandom16Bytes(uint8_t buf[16]) {
            auto [v0, v1] = SemiSecureRand128();
            memcpy(buf, &v0, 8);
            memcpy(buf + 8, &v1, 8);
        }

        static bool HasRecvWholeHttpReply(const uint8_t* src, size_t size) {
            if FWS_UNLIKELY(size < 4) {
                return false;
            }
            if FWS_LIKELY(memcmp(src + size - 4, "\r\n\r\n", 4) == 0) {
                return true;
            }
            return false;
        }

        FWS_ALWAYS_INLINE int MakeHttpRequestText(std::string_view request_uri, std::string_view request_host,
                                                  std::string_view request_origin = {},
                                                  std::string_view sub_protocols = {},
                                                  std::string_view extensions = {}) {
            size_t estimated_request_len = 204U + request_uri.size()
                                           + request_host.size() + request_origin.size()
                                           + sub_protocols.size() + extensions.size();
            if (estimated_request_len > constants::MAX_HANDSHAKE_REQUEST_LENGTH) {
                SetErrorFormatStr("Websocket request length should be no longer"
                                  "than constants::MAX_HANDSHAKE_REQUEST_LENGTH"
                                  "%zu, but estimated length is %zu",
                                  constants::MAX_HANDSHAKE_REQUEST_LENGTH, estimated_request_len);
                return -1;
            }
            constexpr size_t BUF_LEN = constants::MAX_HANDSHAKE_REQUEST_LENGTH;
            buf_ = RequestBuf(BUF_LEN);
            uint8_t* FWS_RESTRICT data = (uint8_t*)(buf_.data + buf_.start_pos);
            uint8_t* FWS_RESTRICT const data_start = data;
            constexpr char SP = ' ';
            constexpr char CRLF[2] = {'\r', '\n'};
            memcpy(data, "GET ", 4);
            data += 4;
            memcpy(data, request_uri.data(), request_uri.size());
            data += request_uri.size();
            *data++ = SP;
            static constexpr char HTTP_VERSION_STR[] = "HTTP/1.1\r\n";
            static_assert(sizeof(HTTP_VERSION_STR) == 11);
            constexpr size_t HTTP_VERSION_STR_LEN  = sizeof(HTTP_VERSION_STR) - 1U;
            memcpy(data, HTTP_VERSION_STR, HTTP_VERSION_STR_LEN);
            data += HTTP_VERSION_STR_LEN;
            static constexpr char HOST_STR[] = "Host: ";
            memcpy(data, HOST_STR, sizeof(HOST_STR) - 1U);
            data += sizeof(HOST_STR) - 1U;
            memcpy(data, request_host.data(), request_host.size());
            data += request_host.size();
            static constexpr char UPGRADE_TYPE_STR[] = "\r\nUpgrade: websocket\r\n";
            memcpy(data, UPGRADE_TYPE_STR, sizeof(UPGRADE_TYPE_STR) - 1U);
            data += sizeof(UPGRADE_TYPE_STR) - 1U;
            static constexpr char CONNECTION_STR[] = "Connection: Upgrade\r\n";
            memcpy(data, CONNECTION_STR, sizeof(CONNECTION_STR) - 1U);
            data += sizeof(CONNECTION_STR) - 1U;
            uint8_t random_16bytes[16];
            FillRandom16Bytes(random_16bytes);
            constexpr size_t SEC_KEY_LEN = GetBase64EncodeLength(sizeof(random_16bytes));
            uint8_t sec_key_buf[SEC_KEY_LEN];
            Base64Encode(random_16bytes, sizeof(random_16bytes), sec_key_buf);
            // Calculate the sha1 of sec key in resp from server, not base64 yet
            Sha1SecKey((const char*)sec_key_buf, expect_reply_sha1);
            static constexpr char SEC_KEY_STR[] = "Sec-WebSocket-Key: ";
            memcpy(data, SEC_KEY_STR, sizeof(SEC_KEY_STR) - 1U);
            data += sizeof(SEC_KEY_STR) - 1U;
            memcpy(data, sec_key_buf, SEC_KEY_LEN - 1U);
            data += SEC_KEY_LEN - 1U;
            static constexpr char SEC_WS_VERSION_STR[] = "\r\nSec-WebSocket-Version: 13\r\n";
            memcpy(data, SEC_WS_VERSION_STR, sizeof(SEC_WS_VERSION_STR) - 1U);
            data += sizeof(SEC_WS_VERSION_STR) - 1U;
            if (!request_origin.empty()) {
                static constexpr char ORIGIN_STR[] = "Origin: ";
                memcpy(data, ORIGIN_STR, sizeof(ORIGIN_STR) - 1U);
                data += sizeof (ORIGIN_STR) - 1U;
                memcpy(data, request_origin.data(), request_origin.size());
                data += request_origin.size();
                memcpy(data, CRLF, 2);
                data += 2;
            }
            if (!sub_protocols.empty()) {
                static constexpr char SUB_PROTOCOL_STR[] = "Sec-WebSocket-Protocol:";
                memcpy(data, SUB_PROTOCOL_STR, sizeof(SUB_PROTOCOL_STR) - 1U);
                data += sizeof(SUB_PROTOCOL_STR) - 1U;
                memcpy(data, sub_protocols.data(), sub_protocols.size());
                data += sub_protocols.size();
                memcpy(data, CRLF, 2);
                data += 2;
            }
            if (!extensions.empty()) {
                static constexpr char EXTENSION_STR[] = "Sec-WebSocket-Extensions:";
                memcpy(data, EXTENSION_STR, sizeof(EXTENSION_STR) - 1U);
                data += sizeof(EXTENSION_STR) - 1U;
                memcpy(data, extensions.data(), extensions.size());
                data += extensions.size();
                memcpy(data, CRLF, 2);
                data += 2;
            }
            memcpy(data, CRLF, 2);
            data += 2;
            size_t request_len = data - data_start;
            FWS_ASSERT(request_len < BUF_LEN);
            buf_.size = request_len;
            return 0;
        }

        template<class EventHandler>
        int HandleHandshakeReply(IOBuffer& FWS_RESTRICT io_buf,
                                 EventHandler& FWS_RESTRICT handler) FWS_FUNC_RESTRICT {
            if FWS_LIKELY(buf_.data == nullptr) {
                if FWS_LIKELY(HasRecvWholeHttpReply(io_buf.data + io_buf.start_pos, io_buf.size)) {
                    return ParseReply(io_buf, handler);
                }
                else {
                    buf_ = RequestBuf(constants::MAX_HANDSHAKE_RESP_LENGTH);
                }
            }


            size_t remain_cap = buf_.capacity - (buf_.start_pos + buf_.size);
            if FWS_UNLIKELY(remain_cap < io_buf.size) {
                SetErrorFormatStr("Handshake reply too long, larger than"
                                  "size %zu, abort the connection",
                                  buf_.capacity);
                return -1;
            }
            memcpy(buf_.data + buf_.start_pos + buf_.size,
                   io_buf.data + io_buf.start_pos, io_buf.size);
            buf_.size += io_buf.size;
//            ReclaimBuf(io_buf);
            if (HasRecvWholeHttpReply(buf_.data + buf_.start_pos, buf_.size)) {
                int parse_ret = ParseReply(buf_, handler);
                buf_.size = 0U;
                return parse_ret;
            }
            return 0;
        }

        template<class EventHandler>
        int ParseReply(IOBuffer &io_buf, EventHandler& handler) {

            char* FWS_RESTRICT data = (char*)io_buf.data + io_buf.start_pos;
            char* FWS_RESTRICT const data_end = (char* const)(io_buf.data
                    + io_buf.start_pos + io_buf.size);
            char *FWS_RESTRICT data_start = data;
            bool http_status_ok = false, upgrade_ok = false, connection_ok = false;
            bool accept_ok = false;
            std::string_view sub_protocols{}, ws_extensions{};
            constexpr char SP = ' ', TAB = '\t';
            while (true) {
                char* lf = (char*)memchr(data, '\n', data_end - data);
                if FWS_UNLIKELY((!lf) || (*(lf - 1LL) != '\r')) {
                    break;
                }
                --lf;
                if (!http_status_ok) {
                    static constexpr char VALID_STATUS_LINE[] = "HTTP/1.1 101";
                    if FWS_UNLIKELY(lf < data + sizeof(VALID_STATUS_LINE) - 1U
                            || memcmp(data, "HTTP/1.1 101", sizeof(VALID_STATUS_LINE) - 1U)) {
                        break;
                    }
                    http_status_ok = true;
                }
                else {
                    const char* FWS_RESTRICT field_end = lf - 1LL;
                    while ((*field_end == SP) | (*field_end == TAB)) {
                        --field_end;
                    }
                    ++field_end;
                    if FWS_UNLIKELY(field_end == data) {
                        if (!upgrade_ok | !connection_ok | !accept_ok) {
                            break;
                        }
                        client_status_ = OPEN_STATUS;
                        int on_con_ret = handler.OnConnected(*this, sub_protocols, ws_extensions);
//                        ReclaimBuf(io_buf);
                        return on_con_ret;
                    }
                    char* const FWS_RESTRICT colon_ptr = (char*)memchr(data, ':', field_end - data);
                    if FWS_UNLIKELY(!colon_ptr) {
                        break;
                    }
                    char* FWS_RESTRICT field_val = colon_ptr + 1LL;
                    while ((*field_val == SP) | (*field_val == TAB))
                        ++field_val;
                    uint32_t name_len = colon_ptr - data;
                    size_t val_len = field_end - field_val;
                    // case insensitive
                    for (uint32_t i = 0; i < name_len; ++i) {
                        data[i] = ToLowerCase(data[i]);
                    }
                    if (name_len == 7 && memcmp(data, "upgrade", 7) == 0) {
                        if FWS_UNLIKELY(val_len != 9) {
                            break;
                        }
                        for (size_t i = 0; i < val_len; ++i) {
                            field_val[i] = ToLowerCase(field_val[i]);
                        }
                        if (memcmp(field_val, "websocket", 9) != 0) break;
                        upgrade_ok = true;
                    }
                    else if (name_len == 10U && !(memcmp(data, "connection", 10))) {
                        if FWS_UNLIKELY(val_len != 7) {
                            break;
                        }
                        for (size_t i = 0; i < val_len; ++i) {
                            field_val[i] = ToLowerCase(field_val[i]);
                        }
                        if (memcmp(field_val, "upgrade", 7) != 0)
                            break;
                        connection_ok = true;
                    }
                    else if (name_len == 20 && !(memcmp(data, "sec-websocket-accept", 20))) {
                        if FWS_UNLIKELY(val_len != 28) {
                            break;
                        }
                        char base64_buf[GetBase64EncodeLength(20)];
                        Base64Encode(expect_reply_sha1, 20, base64_buf);
                        if (memcmp(field_val, base64_buf, 28) != 0) break;
                        accept_ok = true;
                    }
                    else if (name_len == 22 && !memcmp(data, "sec-webSocket-protocol", 22)) {
                        sub_protocols = std::string_view(field_val, val_len);
                    }
                    else if (name_len == 24 && !memcmp(data, "sec-websocket-extensions", 24)) {
                        ws_extensions = std::string_view(field_val, val_len);
                    }
                }
                data = lf + 2;
            }
            client_status_ = CLOSE_STATUS;
            tcp_socket_.Close();
            handler.OnFailToConnect(*this, std::string_view(data_start, data_end - data_start));
            SetErrorFormatStr("The http response from server is not accepted");
//            ReclaimBuf(io_buf);
            return 1;
        }

        template<class EventHandler>
        int SendHandshakeRequest(EventHandler& FWS_RESTRICT handler) FWS_FUNC_RESTRICT {
            // TODO: Assume that one request can be fully written in one write
#ifdef FWS_DEV_DEBUG
            fprintf(stderr, "Prepare to send handshake request\n%s\n", (const char*)buf_.data);
#endif
            size_t remain_req_size = buf_.size;
            ssize_t write_ret = tcp_socket_.Write(buf_, buf_.size);
            if FWS_UNLIKELY(write_ret < 0) {
                SetErrorFormatStr("Failed to send request via socket, write return %d",
                                  write_ret);
                return -1;
            }
            if (remain_req_size == size_t(write_ret)) {
                int stop_write_ret = handler.OnNeedStopWriteRequest(*this);
                if (stop_write_ret < 0) {
                    client_status_ = CLOSE_STATUS;
                    tcp_socket_.Close();
                    return -1;
                }
                client_status_ = WAIT_HTTP_REPLY;
                buf_.size = 0;
                buf_.data = nullptr;

            }
#ifdef FWS_DEV_DEBUG
            fprintf(stderr, "write return: %zd, request size: %zu\n",
                    write_ret, remain_req_size);
#endif

            return 0;
        }

    }; // class WSClientSocket

} // namespace fws_client_socket