#pragma once

#include "flashws/net/http_client.h"
#include "flashws/utils/ring_buffer.h"

namespace fws {

    template<bool enable_tls, typename CharAlloc=FlashAllocator<char>>
    class HTTPClientPool {
    protected:
        using String = std::basic_string<char, std::char_traits<char>, CharAlloc>;
    public:

        using ClientType = HTTPClient<enable_tls, HTTPClientPool*>;
        using HTTPOnRecvMsgFunc = std::function<void(ClientType&, int, IOBuffer&&)>;
        using HTTPOnErrorFunc = std::function<void(ClientType&, std::string_view)>;

        HTTPClientPool():
            keep_conn_cnt_(0), max_conn_cnt_(0), conn_pre_open_cnt_(0), cur_retry_cnt_(0), max_retry_cnt_(0),
            loop_ptr_(nullptr), idle_client_pool_{} , request_to_add_{}, port_(0), host_(), ip_(),
            busy_client_map_{} {}

        HTTPClientPool(const HTTPClientPool&) = delete;
        HTTPClientPool& operator=(const HTTPClientPool&) = delete;

        HTTPClientPool(HTTPClientPool&& o) noexcept:
            keep_conn_cnt_(std::exchange(o.keep_conn_cnt_, 0)),
            max_conn_cnt_(std::exchange(o.max_conn_cnt_, 0)),
            conn_pre_open_cnt_(std::exchange(o.conn_pre_open_cnt_, 0)),
            cur_retry_cnt_(std::exchange(o.cur_retry_cnt_, 0)),
            max_retry_cnt_(std::exchange(o.max_retry_cnt_, 0)),
            loop_ptr_(std::exchange(o.loop_ptr_, nullptr)),
            idle_client_pool_(std::move(o.idle_client_pool_)),
            request_to_add_(std::move(o.request_to_add_)),
            port_(std::exchange(o.port_, 0)),
            host_(std::move(o.host_)),
            ip_(std::move(o.ip_)),
            busy_client_map_(std::move(o.busy_client_map_))
        {}

        /**
         *
         * @param loop
         * @param host
         * @param ip
         * @param port
         * @param keep_conn_cnt Default connection count, if the connection
         * count is less than this value, new connections will be added
         * @param max_conn_cnt Max possible connection count, if more requests are
         * added, they will be blocked until a connection is available
         * @param max_retry_cnt Max total retry count, if the retry count exceed
         * this value, the loop will be stopped
         * @return
         */
        int Init(FLoop<CharAlloc> &loop, std::string_view host,
                 std::string_view ip, int port,
                 size_t keep_conn_cnt, size_t max_conn_cnt, size_t max_retry_cnt = 1000'000) {
            FWS_ASSERT(keep_conn_cnt <= max_conn_cnt);
            idle_client_pool_.reserve(max_conn_cnt);
            busy_client_map_.reserve(max_conn_cnt);
            keep_conn_cnt_ = keep_conn_cnt;
            max_conn_cnt_ = max_conn_cnt;
            conn_pre_open_cnt_ = 0;
            cur_retry_cnt_ = 0;
            max_retry_cnt_ = max_retry_cnt;
            loop_ptr_ = &loop;
            port_ = port;
            host_ = host;
            ip_ = ip;
            for (size_t i = 0; i < keep_conn_cnt; ++i) {
                int add_ret = AddNewHttpClient(loop, host, ip, port);
                if FWS_UNLIKELY(add_ret < 0) {
                    SetErrorFormatStr("HTTPClientPool Init AddNewHttpClient failed");
                    return -1;
                }
            }
            return 0;
        }

        template<HTTPOpType op_type>
        int SendRequest(std::string_view path,
                        HTTPOnRecvMsgFunc on_recv_msg,
                        HTTPOnErrorFunc on_error,
                        std::string_view query_params={},
                        const char* body=nullptr, size_t body_size=0, std::string_view headers={}) {
            if (idle_client_pool_.empty()) {
                size_t total_possible_conn = busy_client_map_.size() + idle_client_pool_.size() + conn_pre_open_cnt_;
                if FWS_UNLIKELY(total_possible_conn >= max_conn_cnt_) {
                    // Requests will be added to the queue and postponed until a connection is available
#ifdef FWS_DEBUG
                    fprintf(stderr, "HTTPClientPool cur connection size reach max_conn_cnt %zu\n",
                                      max_conn_cnt_);
#endif
                }
//                FWS_ASSERT(conn_pre_open_cnt_ >= request_to_add_.size());
                if (conn_pre_open_cnt_ <= request_to_add_.size() && total_possible_conn < max_conn_cnt_) {
                    int add_ret = AddNewHttpClient(*loop_ptr_, host_, ip_, port_);
                    if FWS_UNLIKELY(add_ret < 0) {
                        SetErrorFormatStr("HTTPClientPool AddNewHttpClient failed");
                        return -1;
                    }
                }

                IOBuffer body_buf{};
                if (body != nullptr) {
                    body_buf = RequestBuf(body_size);
                    memcpy(body_buf.data + body_buf.start_pos, body, body_size);
                    body_buf.size = body_size;
                }
                request_to_add_.emplace_back(RequestInfo{op_type, String(path), String(query_params),
                                std::move(body_buf),
                                String(headers),
                                ClientInfo{std::move(on_recv_msg), std::move(on_error)}
                });
                return 0;
            }
            auto *client = *idle_client_pool_.begin();
            idle_client_pool_.erase(client);
            busy_client_map_.emplace(client, ClientInfo{std::move(on_recv_msg), std::move(on_error)});
            int send_ret = client->template SendRequest<op_type>(path, query_params, body, body_size, headers);
            if FWS_UNLIKELY(send_ret < 0) {
                SetErrorFormatStr("HTTPClientPool SendRequest failed, %s", GetErrorString().c_str());
                return -1;
            }
            return 0;
        }

    protected:

        struct ClientInfo {
            HTTPOnRecvMsgFunc on_recv_msg;
            HTTPOnErrorFunc on_error;
            ClientInfo() = default;
            ClientInfo(HTTPOnRecvMsgFunc&& on_recv_msg, HTTPOnErrorFunc&& on_error) noexcept:
                on_recv_msg(std::move(on_recv_msg)), on_error(std::move(on_error)) {}
            ClientInfo(ClientInfo &&o) noexcept:
                on_recv_msg(std::move(o.on_recv_msg)),
                on_error(std::move(o.on_error)) {}
            ClientInfo& operator=(ClientInfo &&o) noexcept {
                std::swap(on_recv_msg, o.on_recv_msg);
                std::swap(on_error, o.on_error);
                return *this;
            }
            ClientInfo(const ClientInfo&) = delete;
            ClientInfo& operator=(const ClientInfo&) = delete;
        };
        using PtrAlloc = typename std::allocator_traits<CharAlloc>::template rebind_alloc<ClientType*>;
        size_t keep_conn_cnt_;
        size_t max_conn_cnt_;
        size_t conn_pre_open_cnt_;
        size_t cur_retry_cnt_;
        size_t max_retry_cnt_;
        FLoop<CharAlloc> *loop_ptr_;
        ska::flat_hash_set<ClientType*, std::hash<ClientType*>, std::equal_to<ClientType*>, PtrAlloc> idle_client_pool_;
        struct RequestInfo {
            RequestInfo() = default;
            RequestInfo(RequestInfo &&o) noexcept:
                op_type(o.op_type),
                path(std::move(o.path)), query_params(std::move(o.query_params)),
                body(std::move(o.body)), headers(std::move(o.headers)),
                client_info(std::move(o.client_info)) {}

            RequestInfo(HTTPOpType op_type, String&& path, String&& query_params, IOBuffer&& body, String&& headers, ClientInfo&& client_info) noexcept:
                op_type(op_type),
                path(std::move(path)), query_params(std::move(query_params)),
                body(std::move(body)), headers(std::move(headers)),
                client_info(std::move(client_info)) {}

            RequestInfo(const RequestInfo&) = delete;
            RequestInfo& operator=(const RequestInfo&) = delete;

            HTTPOpType op_type;
            String path;
            String query_params;
            IOBuffer body;
            String headers;
            ClientInfo client_info;
        };
        using RequestInfoAlloc = typename std::allocator_traits<CharAlloc>::template rebind_alloc<RequestInfo>;
        frb::RingBuffer<RequestInfo, RequestInfoAlloc> request_to_add_;
        int port_;
        String host_;
        String ip_;


        using KVPairAlloc = typename std::allocator_traits<CharAlloc>::template rebind_alloc<std::pair<const ClientType*, ClientInfo>>;
        using MapType = ska::flat_hash_map<ClientType*, ClientInfo, std::hash<ClientType*>, std::equal_to<ClientType*>, KVPairAlloc>;
        MapType busy_client_map_;

        int PatchRequestToClient(ClientType &http) {
            auto *this_ptr = this;
            auto &req_info = this_ptr->request_to_add_.front();
            int send_ret = 0;
            if (req_info.op_type == HTTP_GET_OP) {
                send_ret = http.template SendRequest<HTTP_GET_OP>(std::string_view(req_info.path),
                                                                  std::string_view(req_info.query_params),
                                                                  nullptr,
                                                                  0,
                                                                  std::string_view(req_info.headers));
            }
            else if (req_info.op_type == HTTP_POST_OP) {
                send_ret = http.template SendRequest<HTTP_POST_OP>(std::string_view(req_info.path),
                                                                   std::string_view(req_info.query_params),
                                                                   (const char*)req_info.body.data + req_info.body.start_pos,
                                                                   req_info.body.size,
                                                                   std::string_view(req_info.headers));
            }
            else if (req_info.op_type == HTTP_PUT_OP) {
                send_ret = http.template SendRequest<HTTP_PUT_OP>(std::string_view(req_info.path),
                                                                  std::string_view(req_info.query_params),
                                                                  (const char*)req_info.body.data + req_info.body.start_pos,
                                                                  req_info.body.size,
                                                                  std::string_view(req_info.headers));
            }
            else if (req_info.op_type == HTTP_DELETE_OP) {
                send_ret = http.template SendRequest<HTTP_DELETE_OP>(std::string_view(req_info.path),
                                                                     std::string_view(req_info.query_params),
                                                                     (const char*)req_info.body.data + req_info.body.start_pos,
                                                                     req_info.body.size,
                                                                     std::string_view(req_info.headers));
            }
            else {
                FWS_ASSERT(false);
            }

            if FWS_UNLIKELY(send_ret < 0) {
                fprintf(stderr, "HTTPClientPool AddNewHttpClient SendRequest failed\n");
                this_ptr->loop_ptr_->StopRun();
            }
            this_ptr->busy_client_map_.emplace(&http, std::move(req_info.client_info));
            this_ptr->request_to_add_.pop_front();
            return 0;
        }


        int AddNewHttpClient(FLoop<CharAlloc> &loop, std::string_view host,
                             std::string_view ip, int port) {
            auto [create_ret, client] = ClientType::Create(loop, host, ip, port, this);
            if (create_ret < 0) {
                return -1;
            }
            ++conn_pre_open_cnt_;
            client->SetOnOpen([](ClientType &http, void *user_data) {
                auto *this_ptr = static_cast<HTTPClientPool*>(user_data);
                --this_ptr->conn_pre_open_cnt_;
                if (this_ptr->request_to_add_.empty()) {
                    this_ptr->idle_client_pool_.emplace(&http);
                    return;
                }
                this_ptr->PatchRequestToClient(http);

            });
            client->SetOnError([](ClientType &http, std::string_view reason, void *user_data) {
                auto *this_ptr = static_cast<HTTPClientPool*>(user_data);
                auto find_it = this_ptr->busy_client_map_.find(&http);
                FWS_ASSERT(find_it != this_ptr->busy_client_map_.end());

                find_it->second.on_error(http, reason);
//                this_ptr->busy_client_map_.erase(find_it);
            });
            client->SetOnClose([](ClientType &http, void *user_data) {
                auto *this_ptr = static_cast<HTTPClientPool*>(user_data);
                auto find_it = this_ptr->busy_client_map_.find(&http);
                if (find_it != this_ptr->busy_client_map_.end()) {
                    this_ptr->busy_client_map_.erase(find_it);
                }
                else {
                    auto pool_it = this_ptr->idle_client_pool_.find(&http);
                    if (pool_it != this_ptr->idle_client_pool_.end()) {
                        this_ptr->idle_client_pool_.erase(pool_it);
                    }
                    else {
                        // otherwise, the client may be closed before it is opened.
                        // For example, when we StopRun the loop
                        FWS_ASSERT(this_ptr->conn_pre_open_cnt_ > 0);
                        --this_ptr->conn_pre_open_cnt_;
                        FWS_ASSERT(!this_ptr->loop_ptr_->is_running());
                        return;
                    }

                }
                if FWS_UNLIKELY(!this_ptr->loop_ptr_->is_running()) {
                    return;
                }

                if FWS_UNLIKELY(this_ptr->cur_retry_cnt_ > this_ptr->max_retry_cnt_) {
                    fprintf(stderr, "HTTPClientPool AddNewHttpClient retry cnt exceed max_retry_cnt\n");
                    this_ptr->loop_ptr_->StopRun();
                }
                if (this_ptr->idle_client_pool_.size() < this_ptr->keep_conn_cnt_) {
                    ++this_ptr->cur_retry_cnt_;
                    // TODO: Delete debug print
//                    printf("HTTPClientPool AddNewHttpClient retry cnt %zu\n", this_ptr->cur_retry_cnt_);
                    int add_ret = this_ptr->AddNewHttpClient(*this_ptr->loop_ptr_,
                                         std::string_view(this_ptr->host_),
                                         std::string_view(this_ptr->ip_), this_ptr->port_);
                    if FWS_UNLIKELY(add_ret < 0) {
                        fprintf(stderr, "HTTPClientPool AddNewHttpClient failed\n");
                        this_ptr->loop_ptr_->StopRun();
                    }
                }
            });
            client->SetOnRecvMsg([](ClientType &http, int status_code, IOBuffer &&buf, void *user_data) {
                auto *this_ptr = static_cast<HTTPClientPool*>(user_data);
                auto find_it = this_ptr->busy_client_map_.find(&http);
                FWS_ASSERT(find_it != this_ptr->busy_client_map_.end());
                find_it->second.on_recv_msg(http, status_code, std::move(buf));
                // TODO: This may cause a performance issue, if the user sends
                // requests through the pool in the on_recv_msg callback, it will be patched to
                // a "cold" client, instead of the current hot client.
                // If we want to fix this, we need to first take the ownership
                // of the on_recv_msg in the `find_it`, and then erase the `find_it`
                // from the `busy_client_map_` and add http to the `idle_client_pool_`.
                // The user may send the requests directly using the http client
                // we passed in the on_recv_msg callback.

                // If the user sends the requests using the http client we
                // passed in the on_recv_msg callback, we need to check if
                // the http client is idle.
                if (http.is_idle()) {
                    if (!this_ptr->request_to_add_.empty()) {
                        this_ptr->PatchRequestToClient(http);
                    }
                    else {
                        this_ptr->idle_client_pool_.emplace(&http);
                        this_ptr->busy_client_map_.erase(find_it);
                    }
                }




            });


            return 0;
        }

    };

} // namespace fws