#pragma once

#include "flashws/net/tls_socket.h"
//#include "flashws/utils/ring_buffer.h"

namespace fws {

    struct HTTPUnspecified{};

    enum HTTPOpType : int32_t {
        HTTP_GET_OP  = 1,
        HTTP_POST_OP = 2,
        HTTP_PUT_OP  = 3,
        HTTP_DELETE_OP = 4,
    };

    template<bool enable_tls, typename UserData=HTTPUnspecified>
    class HTTPClient {
    protected:
        using UnderSocket = std::conditional_t<enable_tls, TLSSocket, TCPSocket>;


    public:

        struct Header {
            std::string_view key;
            std::string_view value;
        };

        HTTPClient(HTTPClient &&other) noexcept:
                sock_ptr_(std::exchange(other.sock_ptr_, nullptr)),
                host_len_(std::exchange(other.host_len_, 0)),
                ip_len_(std::exchange(other.ip_len_, 0)),
                stage_(std::exchange(other.stage_, STAGE_CLOSE)),
                on_recv_part_(std::move(other.on_recv_part_)),
                on_recv_msg_(std::move(other.on_recv_msg_)),
                on_open_(std::move(other.on_open_)),
                on_close_(std::move(other.on_close_)),
                on_error_(std::move(other.on_error_)),
                send_buf_(std::move(other.send_buf_)),
                recv_buf_(std::move(other.recv_buf_)),
                next_recv_size_(std::exchange(other.next_recv_size_, 0)),
                last_resp_status_code_(std::exchange(other.last_resp_status_code_, 0)),
                wait_tail_size_for_chunked_(std::exchange(other.wait_tail_size_for_chunked_, 0)),
                chunked_size_buf_len_(std::exchange(other.chunked_size_buf_len_, 0)),
                recv_msg_registered_(std::exchange(other.recv_msg_registered_, false)),
                is_chunked_(std::exchange(other.is_chunked_, false)),
                chunked_size_buf_(std::move(other.chunked_size_buf_)),
                host_buf_(std::move(other.host_buf_)),
                ip_buf_(std::move(other.ip_buf_)),
                user_data_(std::move(other.user_data_)),
                header_num_(std::exchange(other.header_num_, 0)),
                headers_(std::move(other.headers_))
        {}

        std::tuple<const Header*, size_t> headers() const {
            return {headers_.data(), header_num_};
        }

        HTTPClient() = delete;

        using HTTPOnRecvPartFunc = stdext::inplace_function<void(HTTPClient&,
                int /*status_code*/, bool /*is_msg_end*/, IOBuffer&&, UserData&)>;
        using HTTPOnRecvMsgFunc = stdext::inplace_function<void(HTTPClient&,
                int /*status_code*/, IOBuffer&&, UserData&)>;
        using HTTPOnCloseFunc = stdext::inplace_function<void(HTTPClient&, UserData&)>;
        using HTTPOnErrorFunc = stdext::inplace_function<void(HTTPClient&, std::string_view, UserData&)>;
        using HTTPOnOpenFunc = stdext::inplace_function<void(HTTPClient&, UserData&)>;

        HTTPClient(const HTTPClient&) = delete;
        HTTPClient &operator=(const HTTPClient&) = delete;

        int Close() {
            if (sock_ptr_ != nullptr) {
                if (sock_ptr_->is_open()) {
                    sock_ptr_->Close();
                }
                sock_ptr_ = nullptr;
            }
            stage_ = STAGE_CLOSE;
            return 0;
        }

        bool is_connected() const {
            return stage_ >= STAGE_IDLE;
        }

        bool ready_to_send() const {
            return stage_ == STAGE_IDLE;
        }

        bool is_idle() const {
            return stage_ == STAGE_IDLE;
        }

        bool wait_for_resp() const {
            return (stage_ == STAGE_WAIT_RESP_BODY) | (stage_ == STAGE_WAIT_RESP_HDR);
        }

        int last_status_code() const {
            return last_resp_status_code_;
        }



        template<typename CharAlloc = fws::FlashAllocator<char>>
        static std::tuple<int, HTTPClient*> Create(FLoop<CharAlloc> &loop, std::string_view host,
                                           std::string_view ip, int port, UserData &&user_data) {
            HTTPClient http_client{std::move(user_data)};
            UnderSocket under_sock{};
            constexpr size_t max_host_len = http_client.host_buf_.size() - 1U;
            constexpr size_t max_ip_len = http_client.ip_buf_.size() - 1U;
            if FWS_UNLIKELY(host.size() > max_host_len) {
                SetErrorFormatStr("Host too long, %zu, max_len: %zu\n", host.size(), max_host_len);
                return {-1, nullptr};
            }
            if FWS_UNLIKELY(ip.size() > max_ip_len) {
                SetErrorFormatStr("IP too long, %zu, max_len: %zu\n", ip.size(), max_ip_len);
                return {-1, nullptr};
            }
            http_client.send_buf_ = RequestBuf(constants::MAX_READABLE_SIZE_ONE_TIME, 0);
            http_client.recv_buf_ = RequestBuf(constants::MAX_READABLE_SIZE_ONE_TIME, 0);
            memcpy(http_client.host_buf_.data(), host.data(), host.size());
            http_client.host_len_ = host.size();
            http_client.host_buf_[host.size()] = '\0';
            memcpy(http_client.ip_buf_.data(), ip.data(), ip.size());
            http_client.ip_len_ = ip.size();
            http_client.ip_buf_[ip.size()] = '\0';
            if constexpr (enable_tls) {
                if (under_sock.template Init<false>(http_client.host_buf_.data()) < 0) {
                    return {-1, nullptr};
                }
            } else {
                if (under_sock.Init() < 0) {
                    return {-1, nullptr};
                }
            }
            if FWS_UNLIKELY(under_sock.Connect(http_client.ip_buf_.data(), port) < 0 && errno != EINPROGRESS) {
                return {-1, nullptr};
            }
            auto [add_ret, sock_ptr] = loop.AddSocket(std::move(under_sock), sizeof(HTTPClient), false, std::move(http_client));
            if FWS_UNLIKELY(add_ret < 0) {
                return {-1, nullptr};
            }
            HTTPClient *http_part_ptr = reinterpret_cast<HTTPClient*>(sock_ptr + 1);
            http_part_ptr->sock_ptr_ = sock_ptr;
            http_part_ptr->InitUnderCallbacks();
            http_part_ptr->stage_ = STAGE_WAIT_FOR_OPEN;
            http_part_ptr->on_open_ = [](HTTPClient &, UserData &) {};
            http_part_ptr->on_recv_part_ = [](HTTPClient &, int, bool, IOBuffer&&, UserData &) {};
            http_part_ptr->on_close_ = [](HTTPClient &, UserData &) {};
            http_part_ptr->on_error_ = [](HTTPClient &, std::string_view, UserData &) {};
            return {0, http_part_ptr};
        }

//        template<typename ParamForwardIt>
        template<HTTPOpType op_type>
        int SendRequest(std::string_view path, std::string_view query_params={},
                        const char* body=nullptr, size_t body_size=0, std::string_view headers={}) {
            FWS_ASSERT(sock_ptr_ != nullptr);
            if FWS_UNLIKELY(stage_ != STAGE_IDLE) {
                SetErrorFormatStr("HTTPClient not in idle stage, current stage: %d\n", stage_);
                Close();
                return -1;
            }
            if FWS_UNLIKELY(sock_ptr_->is_open() == false) {
                SetErrorFormatStr("Socket is not opened\n");
                Close();
                return -1;
            }
            CleanBeforeSend();
            stage_ = STAGE_REQ_SENDING;
            last_resp_status_code_ = 0;
            FWS_ASSERT(send_buf_.data != nullptr);
            FWS_ASSERT(send_buf_.size == 0 && send_buf_.start_pos == 0);
            size_t estimated_size = path.size() + query_params.size() + headers.size() + body_size + constants::HTTP_REQUEST_RESERVE_HDR_SIZE;
            if (estimated_size > send_buf_.capacity - send_buf_.start_pos) {
                send_buf_ = RequestBuf(estimated_size, 0);
            }
            uint8_t* FWS_RESTRICT data = send_buf_.data + send_buf_.start_pos;
            uint8_t* FWS_RESTRICT const data_start = data;
//            constexpr char SP = ' ';
            constexpr char CRLF[2] = {'\r', '\n'};
            static_assert(op_type == HTTP_GET_OP || op_type == HTTP_POST_OP || op_type == HTTP_PUT_OP || op_type == HTTP_DELETE_OP, "Invalid op_type");
            if constexpr (op_type == HTTP_GET_OP) {
                memcpy(data, "GET ", 4);
                data += 4;
            }
            else if constexpr (op_type == HTTP_POST_OP) {
                memcpy(data, "POST ", 5);
                data += 5;
            }
            else if constexpr (op_type == HTTP_PUT_OP) {
                memcpy(data, "PUT ", 4);
                data += 4;
            }
            else if constexpr (op_type == HTTP_DELETE_OP) {
                memcpy(data, "DELETE ", 7);
                data += 7;
            }
            memcpy(data, path.data(), path.size());
            data += path.size();
            if (!query_params.empty()) {
                *data++ = '?';
                memcpy(data, query_params.data(), query_params.size());
                data += query_params.size();
            }
            static constexpr char HTTP_VER[] = " HTTP/1.1\r\n";
            memcpy(data, HTTP_VER, sizeof(HTTP_VER) - 1);
            data += sizeof(HTTP_VER) - 1;
            memcpy(data, "Host: ", 6);
            data += 6;
            memcpy(data, host_buf_.data(), host_len_);
            data += host_len_;
            memcpy(data, CRLF, 2);
            data += 2;
            if (!headers.empty()) {
                memcpy(data, headers.data(), headers.size());
                data += headers.size();
                memcpy(data, CRLF, 2);
                data += 2;
            }
            static constexpr char ACCEPT_ENCODING[] = "Accept-Encoding: \r\n";
            memcpy(data, ACCEPT_ENCODING, sizeof(ACCEPT_ENCODING) - 1);
            data += sizeof(ACCEPT_ENCODING) - 1;
            if constexpr (op_type == HTTP_GET_OP) {
                if (body != nullptr && body_size > 0) {
                    Close();
                    SetErrorFormatStr("GET request should not have body\n");
                    return -1;
                }
            }
            else {
                if (body != nullptr && body_size > 0) {
                    static constexpr char CONTENT_LENGTH[] = "Content-Length: ";
                    memcpy(data, CONTENT_LENGTH, sizeof(CONTENT_LENGTH) - 1);
                    data += sizeof(CONTENT_LENGTH) - 1;
                    int body_size_len = snprintf((char*)data, 10, "%zu", body_size);
                    data += body_size_len;
                    memcpy(data, CRLF, 2);
                    data += 2;
                    memcpy(data, CRLF, 2);
                    data += 2;
                    memcpy(data, body, body_size);
                    data += body_size;
                }
            }
            memcpy(data, CRLF, 2);
            data += 2;
            send_buf_.size = data - data_start;
            // TODO: delete debug info
#ifdef FWS_DEV_DEBUG
            printf("Request size: %zu\n", send_buf_.size);
            fwrite(send_buf_.data + send_buf_.start_pos, 1, send_buf_.size, stderr);
            printf("\n");
#endif
            FWS_ASSERT(sock_ptr_->is_open());
            SendBufferedReq();

            return 0;
        }


        // This will be called when there is new data received, whether the msg
        // is complete can be determined in the function parameter is_msg_end.
        void SetOnRecvPart(HTTPOnRecvPartFunc&& on_read) {
            on_recv_part_ = std::move(on_read);
        }

        // If this is set, there will be a recv buffer for this http client.
        // The callback will only be called when the whole message is received.
        void SetOnRecvMsg(HTTPOnRecvMsgFunc&& on_recv) {
            on_recv_msg_ = std::move(on_recv);
            recv_msg_registered_ = true;
        }

        void SetOnOpen(HTTPOnOpenFunc&& on_open) {
            on_open_ = std::move(on_open);
        }

        void SetOnClose(HTTPOnCloseFunc&& on_close) {
            on_close_ = std::move(on_close);
        }

        void SetOnError(HTTPOnErrorFunc&& on_error) {
            on_error_ = std::move(on_error);
        }

    protected:
        UnderSocket *sock_ptr_ = nullptr; // do not have ownership
        static constexpr size_t MAX_HOST_BUF_LEN = 128;
        static constexpr size_t MAX_IP_BUF_LEN = 16;
        static constexpr size_t MAX_HEADER_NUM = 48;
        static constexpr size_t MAX_CHUNKED_SIZE_BUF_LEN = 10;
        size_t host_len_, ip_len_;

        enum HTTPStage: int32_t {
            STAGE_CLOSE = 0,
            STAGE_WAIT_FOR_OPEN = 1,
            STAGE_IDLE = 2,
            STAGE_REQ_SENDING = 4,
            STAGE_WAIT_RESP_HDR = 8,
            STAGE_WAIT_RESP_BODY = 16,
        };

        HTTPStage stage_;
        HTTPOnRecvPartFunc on_recv_part_;
        HTTPOnRecvMsgFunc on_recv_msg_;
        HTTPOnOpenFunc on_open_;
        HTTPOnCloseFunc on_close_;
        HTTPOnErrorFunc on_error_;
        IOBuffer send_buf_;
        IOBuffer recv_buf_;
        size_t next_recv_size_;
        int last_resp_status_code_;
        int wait_tail_size_for_chunked_;
        int chunked_size_buf_len_;
        bool recv_msg_registered_;
        bool is_chunked_;

        std::array<char, MAX_CHUNKED_SIZE_BUF_LEN> chunked_size_buf_;
        std::array<char, MAX_HOST_BUF_LEN> host_buf_;
        std::array<char, MAX_IP_BUF_LEN> ip_buf_;
        UserData user_data_;
        size_t header_num_;
        std::array<Header, MAX_HEADER_NUM> headers_;

        void CleanWhenMsgEnd() {
            stage_ = STAGE_IDLE;

//            on_recv_part_ = [](HTTPClient &, int, bool, IOBuffer&&, UserData &) {};
//            on_error_ = [](HTTPClient &, std::string_view, UserData &) {};
        }

        void CleanBeforeSend() {
            if (recv_msg_registered_) {
                recv_buf_ = RequestBuf(constants::HTTP_MAX_RECV_BUF_SIZE, 0);
            }
            send_buf_.start_pos = 0;
            send_buf_.size = 0;
            recv_buf_.start_pos = 0;
            recv_buf_.size = 0;
            next_recv_size_ = 0;
            last_resp_status_code_ = 0;
            wait_tail_size_for_chunked_ = 0;
            chunked_size_buf_len_ = 0;
//            recv_msg_registered_ = false;
            is_chunked_ = false;
            header_num_ = 0;
            // callbacks should be set by users or the connection pool
        }

        int SendBufferedReq() {
            if (send_buf_.size == 0) {
                return 0;
            }
            ssize_t write_ret = sock_ptr_->Write((const char*)send_buf_.data + send_buf_.start_pos, send_buf_.size);
            if FWS_UNLIKELY(write_ret < 0) {
                Close();
                return -1;
            }
            if (write_ret == send_buf_.size) {
                stage_ = STAGE_WAIT_RESP_HDR;
                send_buf_.start_pos = 0;
                send_buf_.size = 0;
            }
            else {
                send_buf_.start_pos += write_ret;
                send_buf_.size -= write_ret;
            }
            return 0;
        }

//        struct ReqData {
//            HTTPOpType type;
//            IOBuffer req_buf;
//            IOBuffer resp_buf;
//        };

//        frb::RingBuffer<ReqData> req_ring_buf_;

        [[nodiscard]] std::string_view host_sv() const {
            return {host_buf_.data(), host_len_};
        }

        [[nodiscard]] std::string_view ip_sv() const {
            return {ip_buf_.data(), ip_len_};
        }

        explicit HTTPClient(UserData &&u_data) noexcept:
            sock_ptr_(nullptr),
            host_len_(0),
            ip_len_(0),
            stage_(STAGE_CLOSE),
            on_recv_part_{},
            on_recv_msg_{},
            on_open_{},
            on_close_{},
            on_error_{},
            send_buf_{},
            recv_buf_{},
            next_recv_size_{0},
            last_resp_status_code_{0},
            wait_tail_size_for_chunked_{0},
            chunked_size_buf_len_{0},
            recv_msg_registered_{false},
            is_chunked_{false},
            chunked_size_buf_{},
            host_buf_{},
            ip_buf_{},
            user_data_(std::move(u_data)),
            header_num_(0),
            headers_{}
            {}


        void InitUnderCallbacks() {
            InitUnderOnRead();
            InitUnderOnWrite();
            InitUnderOnOpen();
            InitUnderOnClose();
            InitUnderOnError();
        }

        void InitUnderOnError() {
            sock_ptr_->SetOnError([](UnderSocket &, int /**/, std::string_view reason, void *user_data){
                auto *http_client = reinterpret_cast<HTTPClient*>(user_data);
                http_client->on_error_(*http_client, reason, http_client->user_data_);
            });
        }


        void InitUnderOnOpen() {
            sock_ptr_->SetOnOpen([](UnderSocket &, void *user_data){
                auto *http_client = reinterpret_cast<HTTPClient*>(user_data);
                http_client->stage_ = STAGE_IDLE;
                http_client->on_open_(*http_client, http_client->user_data_);
//                http_client->SendBufferedReq();
//                http_client->OnOpen(sock);
            });
        }

        //src needs to be at least 3 bytes
        FWS_ALWAYS_INLINE constexpr static int ReadStatusCode(const char* FWS_RESTRICT src) {
            int code = int(src[0]) * 100 + int(src[1]) * 10 + int(src[2]) - int('0') * 111;
            return code;
        }

        static_assert(ReadStatusCode("213") == 213);

        FWS_ALWAYS_INLINE constexpr static char ToLowerCase(char c) {
            c += (uint32_t(c - 'A') < 26U) << 5;
            return c;
        }

        static_assert(ToLowerCase('A') == 'a');
        static_assert(ToLowerCase('a') == 'a');
        static_assert(ToLowerCase('-') == '-');

        // Is wait to recv a hex formatted chunk size
        [[nodiscard]] int is_wait_chunk_size() const {
            if (next_recv_size_ == 0 && wait_tail_size_for_chunked_ == 0) {
                return 1;
            }
            return 0;
        }

        // src is a hex format string, convert into int
        FWS_ALWAYS_INLINE constexpr static ssize_t ParseChunkedSize(const char* FWS_RESTRICT src, size_t len) {
            ssize_t ret = 0;
            for (size_t i = 0; i < len; ++i) {
                char c = src[i];
                if (c >= '0' && c <= '9') {
                    ret = ret * 16 + (c - '0');
                }
                else if (c >= 'a' && c <= 'f') {
                    ret = ret * 16 + (c - 'a' + 10);
                }
                else if (c >= 'A' && c <= 'F') {
                    ret = ret * 16 + (c - 'A' + 10);
                }
                else {
                    return -1;
                }
            }
            return ret;
        }

        static_assert(ParseChunkedSize("ae86", 4) == 44678);

        int HandleTrunkTailSize(IOBuffer &buf) {
            if FWS_UNLIKELY(buf.size > wait_tail_size_for_chunked_) {
                on_error_(*this, "Extra data after chunk size", user_data_);
                return -1;
            }
            wait_tail_size_for_chunked_ -= buf.size;
            buf.start_pos += buf.size;
            buf.size = 0;
            if (wait_tail_size_for_chunked_ == 0) {
                // Notify the msg is end
//                IOBuffer temp_buf = recv_msg_registered_ ?
//                        IOBuffer(recv_buf_.data, recv_buf_.size, recv_buf_.start_pos, recv_buf_.size) : IOBuffer{};
                int status_code = last_resp_status_code_;
                // set stage to idle in case the user send msg in the following callbacks
                CleanWhenMsgEnd();
                on_recv_part_(*this, status_code, true, IOBuffer{},  user_data_);
                if (recv_msg_registered_) {
                    on_recv_msg_(*this, status_code, std::move(recv_buf_), user_data_);
                }

            }
            return 0;
        }

        int ConsumeChunk(IOBuffer &buf) {
            if (is_wait_chunk_size()) {
//                const char* FWS_RESTRICT src = (const char*)buf.data + buf.start_pos;
                char *lf = (char*)memchr(buf.data + buf.start_pos, '\n', buf.size);
                if FWS_UNLIKELY(lf == nullptr) {
                    size_t remain_size_in_chunk_size_buf = MAX_CHUNKED_SIZE_BUF_LEN - chunked_size_buf_len_;
                    if FWS_UNLIKELY((size_t)buf.size >= remain_size_in_chunk_size_buf) {
                        on_error_(*this, "Failed to find the end of the chunk size", user_data_);
                        return -1;
                    }
                    memcpy(chunked_size_buf_.data() + chunked_size_buf_len_, buf.data + buf.start_pos, buf.size);
                    chunked_size_buf_len_ += buf.size;
                    buf.start_pos += buf.size;
                    buf.size = 0;
                    return 0;
                }
                size_t to_start_dis = lf - (char*)buf.data - buf.start_pos;
                // Maybe CR have been read in last part. We only care about digits
                if (to_start_dis > 1) {
                    memcpy(chunked_size_buf_.data() + chunked_size_buf_len_,
                           buf.data + buf.start_pos, to_start_dis - 1);
                    chunked_size_buf_len_ += to_start_dis - 1;
                }
                buf.start_pos += to_start_dis + 1;
                buf.size -= to_start_dis + 1;
                ssize_t chunk_size = ParseChunkedSize(chunked_size_buf_.data(), chunked_size_buf_len_);
                if FWS_UNLIKELY(chunk_size < 0) {
                    on_error_(*this, "Failed to parse chunk size", user_data_);
                    return -1;
                }
                if (recv_msg_registered_) {
                    ssize_t remain_cap_in_recv_buf = recv_buf_.capacity - recv_buf_.start_pos - recv_buf_.size;
                    if FWS_UNLIKELY(chunk_size > remain_cap_in_recv_buf) {
                        on_error_(*this, "Chunk size larger than remain cap of recv_buf", user_data_);
                        return -1;
                    }
                }
                chunked_size_buf_len_ = 0;
                // Include the CRLF
                next_recv_size_ = chunk_size + 2;
                if (chunk_size == 0) {
                    wait_tail_size_for_chunked_ = 2;
                }
            }
            if (wait_tail_size_for_chunked_ > 0) {
                return HandleTrunkTailSize(buf);
            }
            else {
                IOBuffer temp_buf{};
                if (buf.size > (ssize_t)next_recv_size_) {
                    size_t temp_buf_size = next_recv_size_ - 2;
                    temp_buf = IOBuffer{buf.data, ssize_t(temp_buf_size), buf.start_pos, temp_buf_size + buf.start_pos};
                    buf.start_pos += next_recv_size_;
                    buf.size -= next_recv_size_;
                    next_recv_size_ = 0;
                }
                else {
                    temp_buf = IOBuffer{buf.data, buf.size, buf.start_pos, (size_t)buf.size + buf.start_pos};
                    buf.start_pos += buf.size;
                    buf.size = 0;
                    next_recv_size_ -= temp_buf.size;
                }
                if (recv_msg_registered_) {
                    memcpy(recv_buf_.data + recv_buf_.start_pos + recv_buf_.size, temp_buf.data + temp_buf.start_pos, temp_buf.size);
                    recv_buf_.size += temp_buf.size;
                }
                on_recv_part_(*this, last_resp_status_code_, false, std::move(temp_buf), user_data_);
            }
            return 0;
        }

        int OnRecvBodyPart(IOBuffer &&buf) {
            if (is_chunked_) {
                while (buf.size > 0) {
                    if FWS_UNLIKELY(ConsumeChunk(buf) < 0) {
                        return -1;
                    }
                }
            }
            else {
                if FWS_UNLIKELY(buf.size > (ssize_t)next_recv_size_) {
                    on_error_(*this, "Extra data after content length", user_data_);
                    return -1;
                }
                next_recv_size_ -= buf.size;
                memcpy(recv_buf_.data + recv_buf_.start_pos + recv_buf_.size, buf.data + buf.start_pos, buf.size);
                recv_buf_.size += buf.size;
                on_recv_part_(*this, last_resp_status_code_, next_recv_size_ == 0, std::move(buf), user_data_);
                if (next_recv_size_ == 0) {
                    CleanWhenMsgEnd();
                    if (recv_msg_registered_) {
                        on_recv_msg_(*this, last_resp_status_code_, std::move(recv_buf_), user_data_);
                    }
                }
            }

            return 0;
        }

        int ParseHttpHeader(size_t header_size, size_t header_size_in_part, IOBuffer &&part_buf) {
//            constexpr char CRLF[2] = {'\r', '\n'};
            constexpr char SP = ' ';
            constexpr char TAB = '\t';
            char* FWS_RESTRICT data = (char*)recv_buf_.data + recv_buf_.start_pos;
            const char* FWS_RESTRICT data_end = data + header_size;
            FWS_ASSERT((ssize_t)header_size_in_part <= part_buf.size);
            constexpr size_t LEAST_HEADER_SIZE = 19;
            if FWS_UNLIKELY(header_size < LEAST_HEADER_SIZE) {
                on_error_(*this, "Header too short", user_data_);
                return -1;
            }
            if FWS_UNLIKELY(memcmp(data, "HTTP/1.1 ", 9) != 0) {
                on_error_(*this, "Invalid http version", user_data_);
                return -2;
            }
            data += 9;
            if FWS_UNLIKELY(!std::isdigit(data[0]) || !std::isdigit(data[1]) || !std::isdigit(data[2])) {
                on_error_(*this, "Invalid status code", user_data_);
                return -3;
            }
            int status_code = ReadStatusCode(data);
            last_resp_status_code_ = status_code;
            char* FWS_RESTRICT status_str_start = data;
            data += 4;
            char* lf = (char*)memchr(data, '\n', data_end - data);
            if FWS_UNLIKELY((lf == nullptr) | (*(lf - 1LL) != '\r')) {
                on_error_(*this, "Failed to find the end of the status line", user_data_);
                return -4;
            }
            --lf;
            if FWS_UNLIKELY(!(status_code >= 200 && status_code <= 206)) {
//                on_error_(*this, std::string_view(status_str_start, lf - status_str_start), user_data_);
                std::string part_body = std::string(data_end, (char*)recv_buf_.data + recv_buf_.start_pos + recv_buf_.size - data_end);
                on_error_(*this, std::string_view(std::string(status_str_start, lf - status_str_start) + "\n" + part_body), user_data_);
                return -5;
            }
            data = lf + 2;
            int header_count = 0;
            int content_len = -1;

            while (true) {
                lf = (char*)memchr(data, '\n', data_end - data);
                if FWS_UNLIKELY((lf == nullptr) || (*(lf - 1LL) != '\r')) {
                    break;
                }
                --lf;
                const char* FWS_RESTRICT field_end = lf - 1;
                while ((*field_end == SP) | (*field_end == TAB)) {
                    --field_end;
                }
                ++field_end;
                if FWS_UNLIKELY(field_end == data) {
                    header_num_ = header_count;
                    part_buf.start_pos += header_size_in_part;
                    part_buf.size -= header_size_in_part;
                    stage_ = STAGE_WAIT_RESP_BODY;
                    recv_buf_.start_pos += header_size;
                    recv_buf_.size = 0;
                    if (part_buf.size > 0) {
                        return OnRecvBodyPart(std::move(part_buf));
                    }
                    //TODO:
                    return 0;
                }
                char* const FWS_RESTRICT colon_ptr = (char*)memchr(data, ':', field_end - data);
                if FWS_UNLIKELY(!colon_ptr) {
                    break;
                }

                char* FWS_RESTRICT field_val = colon_ptr + 1LL;
                while ((*field_val == SP) | (*field_val == TAB))
                    ++field_val;
                uint32_t key_len = colon_ptr - data;
                size_t val_len = field_end - field_val;
                // case insensitive
                for (uint32_t i = 0; i < key_len; ++i) {
                    data[i] = ToLowerCase(data[i]);
                }
                Header &cur_header = headers_[header_count++];
                cur_header.key = {data, key_len};
                cur_header.value = {field_val, val_len};
                if (cur_header.key == "content-length") {
                    content_len = 0;
                    for (size_t i = 0; i < val_len; ++i) {
                        if FWS_UNLIKELY(!std::isdigit(field_val[i])) {
                            break;
                        }
                        content_len = content_len * 10 + (field_val[i] - '0');
                    }
                    // This shouldn't happen for correctly formatted http response
                    if FWS_LIKELY(!is_chunked_) {
                        next_recv_size_ = content_len;
                    }
                    ssize_t body_size_in_part = (ssize_t)part_buf.size - header_size_in_part;
                    ssize_t remain_body_size = content_len - body_size_in_part;
                    ssize_t recv_buf_remain_cap = recv_buf_.capacity - recv_buf_.size - recv_buf_.start_pos;
                    if FWS_UNLIKELY(remain_body_size > recv_buf_remain_cap) {
                        on_error_(*this, "Content length too long for the recv buf", user_data_);
                        return -1;
                    }

                }
                else if (cur_header.key == "transfer-encoding") {
                    if (cur_header.value == "chunked") {
                        is_chunked_ = true;
                        next_recv_size_ = 0;
                        // If next_recv_size_ == 0 and wait_tail_size_for_chunked_ != 0,
                        // we should read the tail of the chunked data.
                        // If next_recv_size_ == 0 and wait_tail_size_for_chunked_ == 0,
                        // this is the start of the chunked data.
                        wait_tail_size_for_chunked_ = 0;
                        // if content_len is also set, we should ignore it
                    }
                    else {
                        break;
                    }
                }
                data = lf + 2;
            }
            on_error_(*this, "Failed to parse the response header", user_data_);


            return -1;
        }

        void InitUnderOnRead() {
            sock_ptr_->SetOnReadable([](UnderSocket &, IOBuffer&& buf, void *user_data){
                auto *http_client = reinterpret_cast<HTTPClient*>(user_data);
                auto &u_data = http_client->user_data_;
                if FWS_UNLIKELY(!http_client->wait_for_resp()) {
                    http_client->on_error_(*http_client, "Recv data when not waiting for resp",
                                           u_data);
                    http_client->Close();
                    return;
                }

                // TODO: Handle requests, parse it and determine length
                if (http_client->stage_ == STAGE_WAIT_RESP_HDR) {

                    auto &recv_buf = http_client->recv_buf_;
                    if FWS_UNLIKELY(buf.size > (ssize_t)recv_buf.capacity - recv_buf.size - (ssize_t)recv_buf.start_pos) {
                        http_client->on_error_(*http_client, "Resp too long for the recv buf", u_data);
                        http_client->Close();
                        return;
                    }
                    // In old recv_buf, header is not complete
                    size_t header_size_in_old_recv_buf = recv_buf.size;
                    memcpy(recv_buf.data + recv_buf.start_pos + recv_buf.size, buf.data + buf.start_pos, buf.size);
                    recv_buf.size += buf.size;
                    auto [contain_header_end, header_size] = ContainHttpHeaderEnd((const char*)recv_buf.data + recv_buf.start_pos, recv_buf.size);
                    if (contain_header_end) {
                        size_t header_size_in_new_buf = header_size - header_size_in_old_recv_buf;
//                        ssize_t recv_buf_remain_size = recv_buf.capacity - recv_buf.size - recv_buf.start_pos;
                        int parse_ret = http_client->ParseHttpHeader(header_size, header_size_in_new_buf, std::move(buf));
                        if FWS_UNLIKELY(parse_ret < 0) {
                            http_client->Close();
                        }
                    }
                }
                else if(http_client->stage_ == STAGE_WAIT_RESP_BODY) {
                    int consume_ret = http_client->OnRecvBodyPart(std::move(buf));
                    if FWS_UNLIKELY(consume_ret < 0) {
                        http_client->Close();
                    }
                }
                else {
                    http_client->on_error_(*http_client, "Invalid stage when recv data", u_data);
                    http_client->Close();
                }

//                bool is_msg_end = false;
//                http_client->on_recv_part_(*http_client, std::move(buf), is_msg_end, http_client->user_data_);
            });
        }

        void InitUnderOnClose() {
            sock_ptr_->SetOnClose([](UnderSocket &, void *user_data){
                auto *http_client = reinterpret_cast<HTTPClient*>(user_data);
                http_client->on_close_(*http_client, http_client->user_data_);
                http_client->stage_ = STAGE_CLOSE;
                std::destroy_at(http_client);
            });
        }

        void InitUnderOnWrite() {
            sock_ptr_->SetOnWritable([](UnderSocket &/**/, size_t /**/, void *user_data){
                auto *http_client = reinterpret_cast<HTTPClient*>(user_data);
                http_client->SendBufferedReq();
            });
        }

        // If the header end is found, return true and the pointer of the header end (after the last LF)
        static inline std::tuple<bool, ssize_t> ContainHttpHeaderEnd(const char* FWS_RESTRICT src,
                                                                     size_t size) {
            constexpr char CRLFCRLF[4] = {'\r', '\n', '\r', '\n'};
            const char* search_ptr = std::search(src, src + size, CRLFCRLF, CRLFCRLF + 4);
            if FWS_UNLIKELY(search_ptr == src + size) {
                return {false, 0};
            }
            return {true, search_ptr + 4 - src};
        }

    };
} // namespace fws