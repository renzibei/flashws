#pragma once
#include "flashws/net/w_socket.h"

namespace fws {


    template<bool enable_tls=false>
    class WSClientSocket: public WSocket<WSClientSocket<enable_tls>, false, enable_tls> {
    protected:
        using Base = WSocket<WSClientSocket<enable_tls>, false, enable_tls>;
        friend Base;


        enum ClientStatus {
//            CLOSE_STATUS = 0,
            WAIT_TCP_CONNECT = 1,
            WAIT_HTTP_REPLY = 2,
            OPEN_STATUS = 3,

            NOT_RECV_NOT_SENT_CLOSE = 4,  // 00100
            NOT_RECV_HAS_SENT_CLOSE = 12, // 01100
            HAS_RECV_NOT_SENT_CLOSE = 20, // 10100
            CLOSED_STATUS = 28,           // 11100
        };

        using Base::buf_;
        using Base::Sha1SecKey;
        using Base::ToLowerCase;
        using Base::OnRecvData;
        using Base::TrySendBufferedFrames;
        using Base::PrepareSendClose;
        using Base::SendFrame;
        using Base::InitWSPart;
        using Base::on_open;
        using Base::in_shutting_down_;
        using UnderSocket = typename Base::UnderSocket;


    public:
        using Base::under_socket;
        using WSOnOpen = stdext::inplace_function<void(WSClientSocket& /*w_socket*/,
                                                       std::string_view /*resp_sub_protocol*/, std::string_view /*resp*/, void* /*user_data*/)>;
        using WSOnConnectErrorFunc = stdext::inplace_function<void(WSClientSocket&,
                                                       std::string_view /*http_resp*/, void* /*user_data*/)>;

        WSClientSocket(): Base(),
            client_status_(CLOSED_STATUS),
            expect_reply_sha1{},
            ws_on_open_{},
            ws_on_connect_error_{} {}

        WSClientSocket(WSClientSocket&& o) noexcept:
            Base(std::move(o)),
            client_status_(std::exchange(o.client_status_, CLOSED_STATUS)),
            expect_reply_sha1(std::move(o.expect_reply_sha1)),
            ws_on_open_{std::move(o.ws_on_open_)},
            ws_on_connect_error_(std::move(o.ws_on_connect_error_))
            {}

        WSClientSocket& operator=(WSClientSocket&& o) noexcept {
            std::swap(static_cast<Base&>(*this), static_cast<Base&>(o));
            std::swap(client_status_, o.client_status_);
            std::swap(expect_reply_sha1, o.expect_reply_sha1);
            std::swap(ws_on_open_, o.ws_on_open_);
            std::swap(ws_on_connect_error_, o.ws_on_connect_error_);
            return *this;
        }

        WSClientSocket(const WSClientSocket&) = delete;
        WSClientSocket& operator=(const WSClientSocket&) = delete;

        int SetOnOpen(WSOnOpen&& on_open) {
            ws_on_open_ = std::move(on_open);
            return 0;
        }

        void SetOnConnectionError(WSOnConnectErrorFunc&& on_connect_error) {
            ws_on_connect_error_ = std::move(on_connect_error);
        }

        int Init(const char* host_name = nullptr, bool no_delay = constants::ENABLE_NO_DELAY_BY_DEFAULT,
                 bool busy_poll = constants::ENABLE_BUSY_POLL_BY_DEFAULT,
                 int busy_poll_us = constants::BUSY_POLL_US_IF_ENABLED) {
            // TODO: under_socket() should be initialized when adding to the floop
            // because the address of it is before the WS object
            int tcp_init_ret = 0;
            if constexpr (enable_tls) {
                tcp_init_ret = under_socket().template Init<false>(host_name,
                              constants::ENABLE_NON_BLOCK_BY_DEFAULT, no_delay,
                              busy_poll, busy_poll_us);
            }
            else {
                tcp_init_ret = under_socket().Init(constants::ENABLE_NON_BLOCK_BY_DEFAULT, no_delay,
                                                   busy_poll, busy_poll_us);
            }
            if FWS_UNLIKELY(tcp_init_ret < 0) {
                SetErrorFormatStr("Failed to create tcp socket, %s", std::strerror(errno));
                return tcp_init_ret;
            }
            int ret = InitWSPart();
            return ret;
        }



        bool IsClosed() const {
            return client_status_ == CLOSED_STATUS;
        }

        int Close(WSStatusCode close_code, std::string_view reason) {
//            FWS_ASSERT(!IsWaitForClose());
            if (IsWaitForClose()) {
                // TODO: Why use 1 instead of -1? Maybe it is not an error?
                return 1;
            }
            client_status_ = NOT_RECV_NOT_SENT_CLOSE;
            int handle_ret = PrepareSendClose(close_code, reason);
            return handle_ret;
        }


        // User can use fws::GetTxWSFrameHdrSize to calculate the size of frame
        // header. However, when there is unsent control frame, need to take
        // the size of control frame into account.
        FWS_ALWAYS_INLINE ssize_t WriteFrame(IOBuffer&& io_buf,
                                             WSTxFrameType frame_type,
                                             bool last_frame_if_possible) {
            return SendFrame(std::move(io_buf), frame_type, last_frame_if_possible);
        }

        int Connect(const char* server_ip, uint16_t host_port,
                    std::string_view request_uri, std::string_view request_host,
                    std::string_view request_origin = {},
                    std::string_view sub_protocols = {},
                    std::string_view extensions = {}) {
            int tcp_con_ret = under_socket().Connect(server_ip, host_port);
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
        ClientStatus client_status_ = CLOSED_STATUS;

        std::array<char, 20> expect_reply_sha1;

        WSOnOpen ws_on_open_;
        WSOnConnectErrorFunc ws_on_connect_error_;

        void CleanDataDerived() {
            std::destroy_at(&ws_on_open_);
            std::destroy_at(&ws_on_connect_error_);
        }

        int InitWSPartImp() {
            int ret = Base::InitBase();
            client_status_ = CLOSED_STATUS;
            SetOnOpen([](WSClientSocket& /*w_socket*/, std::string_view /*resp_sub_protocol*/,
                             std::string_view /*resp*/, void* /*user_data*/){});
            SetOnConnectionError([](WSClientSocket& /*sock*/, std::string_view /*http_resp*/, void* /*user_data*/) {
            });
            return ret;
        }

        WSOnConnectErrorFunc& on_connect_error() {
            return ws_on_connect_error_;
        }

        WSOnOpen& on_open() {
            return ws_on_open_;
        }


        void InitUnderOnReadImp() {
            Base::under_socket().SetOnReadable([](UnderSocket& under_s, IOBuffer&& recv_buf, void* /*user_data*/) {
//                auto recv_buf = under_socket().Read(available_size, constants::SUGGEST_RESERVE_WS_HDR_SIZE);
                int ret = 0;
                auto &sock = static_cast<WSClientSocket&>(under_s);
                // Should not be any case that recv_buf.size < 0
                // Will not reach here
                FWS_ASSERT(recv_buf.size >= 0);
//                }
                if FWS_LIKELY((sock.client_status_ == OPEN_STATUS) | (sock.client_status_ == NOT_RECV_HAS_SENT_CLOSE)) {
                    ret = sock.OnRecvData(recv_buf);

                }
                else if (sock.client_status_ == WAIT_HTTP_REPLY) {
                    ret = sock.HandleHandshakeReply(recv_buf);
                }
                else if (sock.client_status_ == WAIT_TCP_CONNECT) {
                    // Will be connected in writable event
//                    return 0;
                }
                else {
                    SetErrorFormatStr("Shouldn't be in this status in read event, status: %d",
                                      sock.client_status_);
                    ret = -4;
                }
                if (ret < 0 || (sock.client_status_ == CLOSED_STATUS && !sock.in_shutting_down_)) {
                    // TODO: Currently, we try to call on_close() when the client_status_
                    // switches to CLOSED_STATUS, but we should also Close the underlying
                    // socket when we set the close status. What's more, not all the failing
                    // case do we set client_status_ to CLOSED_STATUS
                    sock.under_socket().Close();
                }
//                return ret;
            });
        }

        void InitUnderOnWriteImp() {
            Base::under_socket().SetOnWritable([](UnderSocket& under_s, size_t /*writable_size*/, void* user_data) {
                int ret = 0;
                auto &sock = static_cast<WSClientSocket&>(under_s);
                if FWS_LIKELY(sock.client_status_ == OPEN_STATUS ||
                        sock.client_status_ == NOT_RECV_NOT_SENT_CLOSE || sock.client_status_ == HAS_RECV_NOT_SENT_CLOSE) {
                    ret = sock.TrySendBufferedFrames();
                    if (ret == 0 && sock.unsent_buf_ring_.empty() &&
                        sock.client_status_ == OPEN_STATUS) {
                        sock.on_write()(sock, user_data);
                    }
                }
                else if (sock.client_status_ == WAIT_TCP_CONNECT) {
                    ret = sock.SendHandshakeRequest();
                }
                else {
                    SetErrorFormatStr("Shouldn't be in this status in write event, status: %d\n",
                                      sock.client_status_);
                    ret = -5;
                }
                if FWS_UNLIKELY(ret < 0 || (sock.client_status_ == CLOSED_STATUS && !sock.in_shutting_down_)) {
                    // TODO: Currently, we try to call on_close() when the client_status_
                    // switches to CLOSED_STATUS, but we should also Close the underlying
                    // socket when we set the close status. What's more, not all the failing
                    // case do we set client_status_ to CLOSED_STATUS
                    sock.under_socket().Close();
                }
            });
        }

        bool IsWaitForClose() const {
            return client_status_ & 4U;
        }

        bool HasRecvClose() const {
            return client_status_ & 16U;
        }

        bool HasSentClose() const {
            return client_status_ & 8U;
        }



        int OnRecvCloseFrame() {
            // TODO: finish
            in_shutting_down_ = true;
            if (!IsWaitForClose()) {
                client_status_ = HAS_RECV_NOT_SENT_CLOSE;
            }
            else {
                if (client_status_ == NOT_RECV_NOT_SENT_CLOSE) {
                    client_status_ = HAS_RECV_NOT_SENT_CLOSE;
                }
                else if (client_status_ == NOT_RECV_HAS_SENT_CLOSE) {
                    client_status_ = CLOSED_STATUS;
                }
                else {
                    FWS_ASSERT_M(false, "Shouldn't in this status when recv close!");
                }
            }
            return 0;
        }

        int OnSentCloseFrame() {
            FWS_ASSERT(IsWaitForClose());
            if (client_status_ == NOT_RECV_NOT_SENT_CLOSE) {
                client_status_ = NOT_RECV_HAS_SENT_CLOSE;
            }
            else if (client_status_ == HAS_RECV_NOT_SENT_CLOSE) {
                client_status_ = CLOSED_STATUS;
            }
            else {
                FWS_ASSERT_M(false, "Shouldn't in this status when send close!");
            }
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
            FixBase64Encode<sizeof(random_16bytes)>(random_16bytes, sec_key_buf);
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

        int HandleHandshakeReply(IOBuffer& FWS_RESTRICT io_buf) {
            if FWS_LIKELY(buf_.data == nullptr) {
                if FWS_LIKELY(HasRecvWholeHttpReply(io_buf.data + io_buf.start_pos, io_buf.size)) {
                    return ParseReply(io_buf);
                }
                else {
                    buf_ = RequestBuf(constants::MAX_HANDSHAKE_RESP_LENGTH);
                }
            }


            size_t remain_cap = buf_.capacity - (buf_.start_pos + buf_.size);
            if FWS_UNLIKELY(remain_cap < size_t(io_buf.size)) {
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
                int parse_ret = ParseReply(buf_);
                buf_.size = 0U;
                return parse_ret;
            }
            return 0;
        }

        int ParseReply(IOBuffer &io_buf) {

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
                        on_open()(*this, sub_protocols, ws_extensions, this + 1);
//                        int on_con_ret = handler.OnConnected(*this, sub_protocols, ws_extensions);
//                        ReclaimBuf(io_buf);
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
                        Fix20Base64Encode<20>(expect_reply_sha1.data(), base64_buf);
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
            client_status_ = CLOSED_STATUS;
//            under_socket().Close();
            SetErrorFormatStr("The http response from server is not accepted");
            on_connect_error()(*this, std::string_view(data_start, data_end - data_start),
                    this + 1);
//            handler.OnFailToConnect(*this, std::string_view(data_start, data_end - data_start));
//            ReclaimBuf(io_buf);
            // TODO: Why we set it 1 instead of -1?
            return 1;
        }

        int SendHandshakeRequest() {
            // TODO: will continue to try to send requests if not fully sent
#ifdef FWS_DEV_DEBUG
            fprintf(stderr, "Prepare to send handshake request\n%s\n", (const char*)buf_.data);
#endif
//            TrySendBufferedFrames(handler);
            size_t remain_req_size = buf_.size;
            ssize_t write_ret = under_socket().Write(buf_, buf_.size);
            if FWS_UNLIKELY(write_ret < 0) {
                if (errno != EAGAIN) {
                    client_status_ = CLOSED_STATUS;
                    SetErrorFormatStr("Failed to send request via socket, write return %d",
                                      write_ret);
                    return -1;
                }
            }
            if (remain_req_size == size_t(write_ret)) {
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