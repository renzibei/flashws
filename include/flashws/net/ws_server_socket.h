#pragma once

#include "flashws/net/w_socket.h"

namespace fws {

    class WSServerSocket: public WSocket<WSServerSocket, true> {
    protected:
        enum ServerStatus: uint8_t {
            RECVING_REQ = 0,
            SENDING_REPLY = 1,
            SENDING_ERROR = 2,
            OPEN_STATUS = 3,

            NOT_RECV_NOT_SENT_CLOSE = 4,  // 00100
            NOT_RECV_HAS_SENT_CLOSE = 12, // 01100
            HAS_RECV_NOT_SENT_CLOSE = 20, // 10100
            CLOSED_STATUS = 28,           // 11100

        };
        friend class WSocket<WSServerSocket, true>;
    public:

        int Init(TcpSocket &new_tcp_socket) {
            status_ = RECVING_REQ;
            int ret_code = this->InitBase(new_tcp_socket);
            return ret_code;
        }


        template<class EventHandler>
        int Close(EventHandler &handler, WSStatusCose close_code, std::string_view reason) {
            if (IsWaitForClose()) {
                return 1;
            }
//            FWS_ASSERT(!IsWaitForClose());
            status_ = NOT_RECV_NOT_SENT_CLOSE;
            int handle_ret = PrepareSendClose(handler, close_code, reason);
            return handle_ret;
        }

        template<class EventHandler>
        int HandleFEvent(const FEvent& FWS_RESTRICT event,
                         EventHandler& FWS_RESTRICT handler) {
            int ret = 0;
//            uint32_t flags = event.flags;
            if FWS_UNLIKELY(status_ == CLOSED_STATUS) {
                SetErrorFormatStr("WS Socket status is CLOSED");
                return -6;
            }
            if FWS_UNLIKELY(event.has_error()) {
                int error_code = event.socket_err_code();
                SetErrorFormatStr("FEV_ERROR in event flags: %d, %s", error_code, std::strerror(error_code));
                status_ = CLOSED_STATUS;
                handler.OnCloseConnection(*this, fws::WS_ABNORMAL_CLOSE, GetErrorStrV());
                ret = -1;
            }
            else if FWS_UNLIKELY(event.is_eof()) {
                SetErrorFormatStr("fd %d eof, old status: %d", status_);
                status_ = CLOSED_STATUS;

                // TODO: handle close
                handler.OnCloseConnection(*this, fws::WS_ABNORMAL_CLOSE, GetErrorStrV());
//                Close(fws::WS_ABNORMAL_CLOSE, {});
            }
            else if (event.is_readable()){
                size_t available_size = event.readable_size();
                auto recv_buf = tcp_socket_.Read(available_size, constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                if FWS_UNLIKELY(recv_buf.data == nullptr) {
                    if (recv_buf.size < 0) {
                        // shouldn't be EAGAIN when readable
                        SetErrorFormatStr("Error when reading in ws server read, ava size: %zu, %s\n",
                                          available_size, std::strerror(errno));
                        ret = -2;
                    }
                    status_ = CLOSED_STATUS;
                    handler.OnCloseConnection(*this, fws::WS_ABNORMAL_CLOSE, GetErrorStrV());

                }
                else if FWS_LIKELY(status_ == OPEN_STATUS) {
                    ret = OnRecvData(handler, recv_buf);
                    if FWS_UNLIKELY(ret < 0) {
                        Close(handler, fws::WS_ABNORMAL_CLOSE, GetStringViewSlice(GetErrorStrV(),
                             constants::WS_MAX_CONTROL_FRAME_SIZE - tx_control_frame_hdr_size() - 2U));
                    }
//                    return handle_read_ret;
                }
                else if (status_ == RECVING_REQ){

                    ret = HandleHandshakeRequest(recv_buf, handler);
//                    return handle_request_ret;
                }
                else {
                    SetErrorFormatStr("Shouldn't be in this status, status: %d\n", status_);
                    ret = -3;
                }
            }
#ifdef FWS_ENABLE_FSTACK
            else
#endif
            if (event.is_writable()) {
//                size_t available_size = event.send_buf_size();
                if FWS_LIKELY(status_ == OPEN_STATUS) {
                    TrySendBufferedFrames(handler);
//                    if FWS_UNLIKELY(need_send_control_msg_) {
//                        ssize_t handle_control_msg_ret = HandleUnsentControlMsgOnWritable(handler, available_size);
//                        if FWS_UNLIKELY(handle_control_msg_ret < 0) {
//                            return handle_control_msg_ret;
//                        }
//                        available_size -= handle_control_msg_ret;
//                    }
                    ret = 0;
//                    available_size = std::min(available_size, constants::MAX_WRITABLE_SIZE_ONE_TIME);
//                    ret = handler.OnWritable(*this, available_size);
//                    return write_ret;
                }
                else {
                    SetErrorFormatStr("Shouldn't be in this status\n");
                    ret = -4;
                }
            }
            // If we finish the close handshake
            if FWS_UNLIKELY(status_ == CLOSED_STATUS) {
                int fd = tcp_socket_.fd();
                tcp_socket_.Close();
                ret = handler.OnCleanSocket(fd);
            }
            return ret;
        }

        // User can use fws::GetTxWSFrameHdrSize to calculate the size of frame
        // header. However, when there is unsent control frame, need to take
        // the size of control frame into account. Only when the sum of hdr
        // size and payload size is no less than
        // writable_size, will we make this frame the last frame of a msg.
        template<class EventHandler>
        FWS_ALWAYS_INLINE ssize_t WriteFrame(EventHandler &handler, IOBuffer& io_buf,
                                             WSTxFrameType frame_type, bool last_frame_if_possible) {
//            if FWS_UNLIKELY(need_send_control_msg_) {
//                ssize_t handle_control_msg_ret = HandleUnsentControlMsgOnWritable(handler, writable_size);
//                if FWS_UNLIKELY(handle_control_msg_ret < 0) {
//                    return handle_control_msg_ret;
//                }
//                writable_size -= handle_control_msg_ret;
//            }
            return SendFrame(handler, io_buf, frame_type, last_frame_if_possible);
        }

    protected:
        ServerStatus status_;
//        IOBuffer req_buf_;

//        friend class WSocket<WSServerSocket>;

        constexpr bool IsServer() {
            return true;
        }

        static std::string_view GetStringViewSlice(std::string_view s, size_t max_len) {
            return {s.data(), std::min(s.size(), max_len)};
        }

//        int CloseClean() {
//            status_ = CLOSED_STATUS;
//            return 0;
//        }

        bool IsWaitForClose() const {
            return status_ & 4U;
        }

        bool HasRecvClose() const {
            return status_ & 16U;
        }

        bool HasSentClose() const {
            return status_ & 8U;
        }

        int OnRecvCloseFrame() {
            // TODO: finish
            if (!IsWaitForClose()) {
                status_ = HAS_RECV_NOT_SENT_CLOSE;
            }
            else {
                if (status_ == NOT_RECV_NOT_SENT_CLOSE) {
                    status_ = HAS_RECV_NOT_SENT_CLOSE;
                }
                else if (status_ == NOT_RECV_HAS_SENT_CLOSE) {
                    status_ = CLOSED_STATUS;
                }
                else {
                    FWS_ASSERT_M(false, "Shouldn't in this status when recv close!");
                }
            }
            return 0;
        }

        int OnSentCloseFrame() {
            FWS_ASSERT(IsWaitForClose());
            if (status_ == NOT_RECV_NOT_SENT_CLOSE) {
                status_ = NOT_RECV_HAS_SENT_CLOSE;
            }
            else if (status_ == HAS_RECV_NOT_SENT_CLOSE) {
                status_ = CLOSED_STATUS;
            }
            else {
                FWS_ASSERT_M(false, "Shouldn't in this status when send close!");
            }
            return 0;
        }

        static bool HasRecvWholeHttpRequest(const uint8_t* FWS_RESTRICT src, size_t size) {
            if FWS_UNLIKELY(size < 4) {
                return false;
            }
            if FWS_LIKELY(memcmp(src + size - 4, "\r\n\r\n", 4) == 0) {
                return true;
            }
            return false;
        }

        template<class EventHandler>
        int HandleHandshakeRequest(IOBuffer& FWS_RESTRICT io_buf,
                                     EventHandler& FWS_RESTRICT handler) {
            if FWS_LIKELY(buf_.data == 0) {
                if FWS_LIKELY(HasRecvWholeHttpRequest(io_buf.data + io_buf.start_pos, io_buf.size)) {
                    return ParseRequest(io_buf, handler);
                }
                else {
                    buf_ = RequestBuf(constants::MAX_HANDSHAKE_REQUEST_LENGTH);
                }
            }
            size_t remain_cap = buf_.capacity - (buf_.start_pos + buf_.size);
            if FWS_UNLIKELY(remain_cap < size_t(io_buf.size)) {
                SetErrorFormatStr("Handshake http request too long, larger than"
                                  "size %zu, abort the connection",
                                  buf_.capacity);
                return -1;
            }
            memcpy(buf_.data + buf_.start_pos + buf_.size,
                   io_buf.data + io_buf.start_pos, io_buf.size);
            buf_.size += io_buf.size;
//            ReclaimBuf(io_buf);
            if (HasRecvWholeHttpRequest(buf_.data + buf_.start_pos, buf_.size)) {
                int parse_ret = ParseRequest(buf_, handler);
                buf_.size = 0U;
                return parse_ret;
            }
            return 0;
        }

        template<class EventHandler>
        int ParseRequest(IOBuffer &buf,
                         EventHandler& handler) {
            char* FWS_RESTRICT data = (char* FWS_RESTRICT)buf.data + buf.start_pos;
            char* const FWS_RESTRICT data_end = (char* const)(buf.data + buf.start_pos + buf.size);
//            char req_uri[constants::MAX_REQ_URI_LENGTH] = {0};
            // TODO: reclaim buf
            std::string_view req_uri{}, host{}, sec_key{}, sub_protocols{};
            std::string_view ws_extensions{}, origin{};
            bool upgrade_valid = false;
            bool connection_valid = false;
            bool ws_version_valid = false;
            constexpr char SP = ' ';
            constexpr char TAB = '\t';
            while (true) {
                char* lf = (char*) memchr(data, '\n', data_end - data);
                // if no LF or not CRLF then break
                if FWS_UNLIKELY((!lf) || (*(lf - 1LL) != '\r')) {
                    break;
                }
                --lf;
                if FWS_UNLIKELY(req_uri.empty()) {
                    if FWS_UNLIKELY(memcmp(data, "GET ", 4) != 0) {
                        break;
                    }
                    data += 4;
                    char* const uri_end = (char*)memchr(data, SP, lf - data);
                    uint64_t uri_len = uint64_t(uri_end) - uint64_t(data);
                    if FWS_UNLIKELY((!uri_end)) {
                        break;
                    }
                    req_uri = std::string_view(data, uri_len);
                    // TODO: handle HTTP version
                }
                else {
                    const char* FWS_RESTRICT field_end = lf - 1LL;
                    while ((*field_end == SP) | (*field_end == TAB)) {
                        --field_end;
                    }
                    ++field_end;
                    // two CRLF means end
                    if FWS_UNLIKELY(field_end == data) {
                        if (host.empty() || sec_key.empty() ||
                            (!upgrade_valid | !connection_valid | !ws_version_valid)) {
                            break;
                        }
                        auto resp_buf = RequestBuf(constants::MAX_HANDSHAKE_RESP_LENGTH);
                        size_t resp_buf_len = 0;
                        std::string_view resp_sub_protocol{}, resp_extensions{};
                        int acc_code = handler.OnNewWsConnection(*this,
                                                                 req_uri, host, origin, sub_protocols,
                                                                 ws_extensions, resp_sub_protocol,
                                                                 resp_extensions);
//                        ReclaimBuf(buf);
                        if (acc_code == 0) {
                            status_ = SENDING_REPLY;
//                            char src_key_buf[24 + 36];
//                            memcpy(src_key_buf, sec_key.data(), 24);
//                            memcpy(src_key_buf + 24, constants::GLOBAL_WS_UUID, 36);
//                            char sha1_buf[20];

                            constexpr size_t BASE64_BUF_LEN = (20 + 2) / 3 * 4 + 1;
                            char base64_buf[BASE64_BUF_LEN] = {0};
//                            fws::Sha1(src_key_buf, 24 + 36, sha1_buf);
//                            fws::Base64Encode(sha1_buf, 20, base64_buf);
                            Sha1AndBase64Key(sec_key.data(), base64_buf);
                            static constexpr char resp_header[] =
                                    "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Accept: ";
                            constexpr size_t resp_header_size = sizeof(resp_header) - 1U;
                            memcpy(resp_buf.data, resp_header, resp_header_size);
                            memcpy(resp_buf.data + resp_header_size, base64_buf, BASE64_BUF_LEN - 1U);
                            memcpy(resp_buf.data + resp_header_size + BASE64_BUF_LEN - 1U, "\r\n", 2);
                            constexpr size_t least_resp_buf_len = resp_header_size + BASE64_BUF_LEN - 1U + 2U;
                            static_assert(least_resp_buf_len + 2U < constants::MAX_HANDSHAKE_RESP_LENGTH);
                            resp_buf_len = least_resp_buf_len;
                            size_t expect_resp_len = resp_buf_len + resp_sub_protocol.size() + resp_extensions.size()
                                                     + 6UL;
                            if (expect_resp_len >= constants::MAX_HANDSHAKE_RESP_LENGTH) {
                                SetErrorFormatStr("resp_length %zu larger than "
                                                  "constants::MAX_HANDSHAKE_RESP_LENGTH: %zu\n",
                                                  expect_resp_len, constants::MAX_HANDSHAKE_RESP_LENGTH);
                                return -1;
                            }
                            if (!resp_sub_protocol.empty()) {
                                memcpy(resp_buf.data + resp_buf_len, resp_sub_protocol.data(),
                                       resp_sub_protocol.size());
                                resp_buf_len += resp_sub_protocol.size();
                                memcpy(resp_buf.data + resp_buf_len, "\r\n", 2);
                                resp_buf_len += 2;
                            }
                            if (!resp_extensions.empty()) {
                                memcpy(resp_buf.data + resp_buf_len, resp_extensions.data(),
                                       resp_extensions.size());
                                resp_buf_len += resp_extensions.size();
                                memcpy(resp_buf.data + resp_buf_len, "\r\n", 2);
                                resp_buf_len += 2;
                            }
                            memcpy(resp_buf.data + resp_buf_len, "\r\n", 2);
                            resp_buf_len += 2;

                        }
                        else {
                            status_ = SENDING_ERROR;
                            int printf_len = snprintf((char*)resp_buf.data, resp_buf.capacity,
                                                      "HTTP/1.1 403 Forbidden\r\n"
                                                      "Sec-WebSocket-Version: %s\r\n",
                                                      constants::SEC_WS_VERSION);
                            resp_buf_len = printf_len;
                            if FWS_UNLIKELY(printf_len < 0) {
                                SetErrorFormatStr("Snprintf 403 http reply error");
                                return -1;
                            }
                        }
                        resp_buf.size = resp_buf_len;
                        // TODO: need underlying tcp socket support small write even
                        // in nonblocking mode
                        ssize_t send_ret = tcp_socket_.Write(resp_buf, resp_buf_len);
                        if FWS_UNLIKELY(size_t(send_ret) != resp_buf_len) {
                            SetErrorFormatStr("tcp socket write return %zd,"
                                              "target resp length: %zu\n",
                                              send_ret, resp_buf_len);
                            status_ = CLOSED_STATUS;
                            return -1;
                        }
                        if (status_ == SENDING_REPLY) {
                            status_ = OPEN_STATUS;
                        }
                        else /* status == SENDING_ERROR */{
                            status_ = CLOSED_STATUS;
                        }

                        return 0;
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
                    if (name_len == 4U && memcmp(data, "host", 4) == 0) {
                        host = std::string_view{field_val, val_len};
                    }
                    else if (name_len == 6U && !memcmp(data, "origin", 6)) {
                        origin = {field_val, val_len};
                    }
                    else if (name_len == 7U && !memcmp(data, "upgrade", 7)) {
                        if FWS_UNLIKELY(val_len != 9) {
                            break;
                        }
                        for (size_t i = 0; i < val_len; ++i) {
                            field_val[i] = ToLowerCase(field_val[i]);
                        }
                        if (memcmp(field_val, "websocket", 9) != 0) break;
                        upgrade_valid = true;
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
                        connection_valid = true;
                    }
                    else if (name_len == 17U && !memcmp(data, "sec-websocket-key", 17)) {
                        if (val_len != 24)
                            break;
                        sec_key = {field_val, val_len};
                    }
                    else if (name_len == 21U &&
                             !memcmp(data, "sec-websocket-version", 21)) {
                        static_assert(sizeof(constants::SEC_WS_VERSION) == 3);
                        if (val_len != 2 ||
                            memcmp(field_val, constants::SEC_WS_VERSION, 2) != 0) {
                            break;
                        }
                        ws_version_valid = true;
                    }
                    else if (name_len == 22U && !memcmp(data, "sec-websocket-protocol", 22)) {
                        sub_protocols = {field_val, val_len};
                    }
                    else if (name_len == 24U && !memcmp(data, "sec-websocket-extensions", 24)) {
                        ws_extensions = {field_val, val_len};
                    }
                }
                data = lf + 2LL;
                // TODO: Currently we ignore other optional fields
            }
//            ReclaimBuf(buf);
            status_ = SENDING_ERROR;
            static constexpr char HTTP_400_RESP[] = "HTTP/1.1 400 Bad Request\r\n"
                                                    "Sec-WebSocket-Version: 13\r\n\r\n";
            constexpr size_t RESP_400_LEN = sizeof(HTTP_400_RESP) - 1U;
            IOBuffer temp_buf = RequestBuf(RESP_400_LEN);
            memcpy(temp_buf.data, HTTP_400_RESP, RESP_400_LEN);
            temp_buf.size = RESP_400_LEN;
            ssize_t write_ret = tcp_socket_.Write(temp_buf, RESP_400_LEN);
            status_ = CLOSED_STATUS;
            if FWS_UNLIKELY(write_ret != RESP_400_LEN) {
                SetErrorFormatStr("tcp socket write return %zd,"
                                  "target resp length: %zu\n",
                                  write_ret, RESP_400_LEN);
                return -1;
            }

            return 0;
        }
    }; // class WSServerSocket

//    static_assert(sizeof(WSServerSocket) == 80);

} // namespace fws