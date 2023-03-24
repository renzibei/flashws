#pragma once

#include "flashws/net/tcp_socket.h"
#include "flashws/net/fevent.h"
#include "flashws/crypto/base64.h"
#include "flashws/crypto/sha.h"
#include "flashws/crypto/ws_mask.h"
#include "flashws/crypto/rng.h"
#include "flashws/base/hw_endian.h"
#include "flashws/utils/ring_buffer.h"


namespace fws {

    enum WSOpCode: uint32_t {
        WS_OPCODE_CONTI = 0x0U,
        WS_OPCODE_TEXT = 0x1U,
        WS_OPCODE_BIN = 0x2U,
        WS_OPCODE_CLOSE = 0x8U,
        WS_OPCODE_PING = 0x9U,
        WS_OPCODE_PONG = 0xAU,
    };

    enum WSTxFrameType: uint32_t {
        WS_TEXT_FRAME = WS_OPCODE_TEXT,
        WS_BIN_FRAME = WS_OPCODE_BIN,
        WS_CLOSE_FRAME = WS_OPCODE_CLOSE,
        WS_PING_FRAME = WS_OPCODE_PING,
        WS_PONG_FRAME = WS_OPCODE_PONG,
    };


    enum WSStatusCose: uint32_t {
        WS_NORMAL_CLOSE = 1000,
        WS_GOING_AWAY_CLOSE = 1001,
        WS_PROTOCOL_ERR_CLOSE = 1002,
        WS_TYPE_MISMATCH_CLOSE = 1003,
        WS_NO_STATUS_CLOSE = 1005,
        WS_ABNORMAL_CLOSE = 1006,
        WS_NON_CONSISTENT_CLOSE = 1007,
        WS_VIOLATE_POLICY_CLOSE = 1008,
        WS_MSG_TOO_LARGE_CLOSE = 1009,
        WS_EXTENSIONS_MISSING_CLOSE = 1010,
        WS_SERVER_UNEXPECTED_CLOSE = 1011,
        WS_FAIL_TLS_CLOSE = 1015,
    };

    template<bool is_server>
    FWS_ALWAYS_INLINE constexpr size_t GetTxWSFrameHdrSize(size_t payload_size) {
        size_t mask_len = 0;
        size_t additional_pl_len_field_size = 0;
        if constexpr (!is_server) {
            mask_len = 4;
        }
        if (payload_size >= 126) {
            if FWS_LIKELY(payload_size <= UINT16_MAX) {
                additional_pl_len_field_size = 2;
            }
            else {
                additional_pl_len_field_size = 8;
            }
        }
        return 2U + mask_len + additional_pl_len_field_size;
    }


    template<class Derived, bool is_server>
    class WSocket {
    public:



        FWS_ALWAYS_INLINE TcpSocket& tcp_socket() {
            return tcp_socket_;
        }

        template<class EventHandler>
        int PrepareSendClose(EventHandler& handler, uint16_t status_code, std::string_view reason) {
            if FWS_UNLIKELY(sizeof(status_code) + reason.size() > constants::WS_MAX_CONTROL_FRAME_SIZE) {
                SetErrorFormatStr("Control size must be smaller than %zu",
                                  constants::WS_MAX_CONTROL_FRAME_SIZE);
                return -1;
            }
            size_t buf_cap = sizeof(status_code) + reason.size() + constants::MAX_WS_FRAME_HEADER_SIZE;
            buf_ = RequestBuf(buf_cap);
            buf_.start_pos = constants::MAX_WS_FRAME_HEADER_SIZE;
            status_code = Host2Net16(status_code);
            uint8_t *data = buf_.data + buf_.start_pos;
            memcpy(data, &status_code, sizeof(status_code));
            data += sizeof(status_code);
            memcpy(data, reason.data(), reason.size());
            buf_.size = sizeof(status_code) + reason.size();
            SendControlMsg(handler, buf_, WS_CLOSE_FRAME);
//            need_send_control_msg_ = true;
//            unsent_control_msg_opcode_ = WS_OPCODE_CLOSE;
            return 0;
        }

//        int CloseCon(uint16_t status_code, std::string_view reason) FWS_FUNC_RESTRICT {
//            // TODO: handle the situation when close frame cannot be sent at once
//            size_t buf_cap = sizeof(status_code) + reason.size() + constants::MAX_WS_FRAME_HEADER_SIZE;
//            IOBuffer io_buf = RequestBuf(buf_cap);
//            io_buf.start_pos = constants::MAX_WS_FRAME_HEADER_SIZE;
//            status_code = Host2Net16(status_code);
//            uint8_t *data = io_buf.data + io_buf.start_pos;
//            memcpy(data, &status_code, sizeof(status_code));
//            data += sizeof(status_code);
//            memcpy(data, reason.data(), reason.size());
//            io_buf.size = sizeof(status_code) + reason.size();
//            SendFrame(io_buf, buf_cap, WS_CLOSE_FRAME, true);
//            int clean_ret = static_cast<Derived*>(this)->CloseClean();
//
//            tcp_socket_.Shutdown(TcpSocket::SHUT_RDWR_MODE);
//            int close_ret = tcp_socket_.Close();
////#ifdef FWS_DEV_DEBUG
////            fprintf(stderr, "tcp socket closed in CloseCon, clean_ret: %d, close_ret %d\n",
////                clean_ret, close_ret);
////#endif
//            return clean_ret | close_ret;
//        }

        // return negative value if failed
        int RequestWriteEvent(FQueue &fq) {
            return AddFEvent(fq, tcp_socket_.fd(), FEVAC_WRITE);
//            FEvent write_ev(tcp_socket_.fd(), fws::FEVFILT_WRITE, fws::FEV_ADD,
//                            fws::FEFFLAG_NONE, 0, nullptr);
//            return FEventWait(fq, &write_ev, 1, nullptr, 0, nullptr);
        }

        int StopWriteRequest(FQueue &fq) {
            return DeleteFEvent(fq, tcp_socket_.fd(), FEVAC_WRITE);
//            FEvent delete_ev(tcp_socket_.fd(), fws::FEVFILT_WRITE, fws::FEV_DELETE,
//                            fws::FEFFLAG_NONE, 0, nullptr);
//            return FEventWait(fq, &delete_ev, 1, nullptr, 0, nullptr);
        }

        int RequestReadEvent(FQueue &fq) {
            return AddFEvent(fq, tcp_socket_.fd(), FEVAC_READ);
//            FEvent read_ev(tcp_socket_.fd(), fws::FEVFILT_READ, fws::FEV_ADD,
//                            fws::FEFFLAG_NONE, 0, nullptr);
//            return FEventWait(fq, &read_ev, 1, nullptr, 0, nullptr);
        }

        int StopReadRequest(FQueue &fq) {
            return DeleteFEvent(fq, tcp_socket_.fd(), FEVAC_READ);
//            FEvent delete_ev(tcp_socket_.fd(), fws::FEVFILT_READ, fws::FEV_DELETE,
//                             fws::FEFFLAG_NONE, 0, nullptr);
//            return FEventWait(fq, &delete_ev, 1, nullptr, 0, nullptr);
        }

        static constexpr size_t max_rx_frame_hdr_size() {
            if constexpr(is_server) {
                return constants::MAX_WS_SERVER_RX_FRAME_HEADER_SIZE;
            }
            else {
                return constants::MAX_WS_CLIENT_RX_FRAME_HEADER_SIZE;
            }
        }

        static constexpr size_t tx_control_frame_hdr_size() {
            if constexpr(is_server) {
                return constants::WS_SERVER_TX_CONTROL_HDR_SIZE;
            }
            else {
                return constants::WS_CLIENT_TX_CONTROL_HDR_SIZE;
            }
        }

    protected:
        TcpSocket tcp_socket_;

        enum RecvStatus {
            WAIT_FRAME_HEAD = 0,
            WAIT_FRAME_PAYLOAD = 1,
        };

        RecvStatus recv_status_;
        uint64_t unread_pl_len_;
        uint32_t last_rx_mask_key_;
        uint8_t last_rx_opcode_;
        uint8_t last_rx_control_opcode_;
        uint8_t last_rx_fin_flag_;
        bool is_rx_control_frame_;
        bool last_msg_not_fin_;
//        bool need_send_control_msg_;
//        uint8_t unsent_control_msg_opcode_;
        uint32_t last_rx_hdr_part_len_;
        IOBuffer buf_;

        uint8_t rx_ws_hdr_buf_[max_rx_frame_hdr_size()];
        // buffer for http request, reply, and control frame

        struct WaitForSentFrame{
            IOBuffer buf;
            WSTxFrameType frame_type;

            WaitForSentFrame(IOBuffer &&o_buf, WSTxFrameType type): buf(std::move(o_buf)), frame_type(type) {}
        };

        frb::RingBuffer<WaitForSentFrame, FlashAllocator<WaitForSentFrame>> unsent_buf_ring_;




        int InitBase(TcpSocket &new_tcp_socket) {
            tcp_socket_ = std::move(new_tcp_socket);
            recv_status_ = WAIT_FRAME_HEAD;
            is_rx_control_frame_ = false;
            last_msg_not_fin_ = false;
            last_rx_hdr_part_len_ = 0;
//            need_send_control_msg_ = false;
            buf_ = {nullptr, size_t(0U), 0U, 0U};
//            open_ = 0;
            return 0;
        }

        FWS_ALWAYS_INLINE static bool IsControlFrame(uint32_t opcode) {
            return opcode >> 3;
        }


        // return 0 if not a complete hdr
        int ParseFrameHdr(uint8_t* FWS_RESTRICT data,
                                            uint8_t* FWS_RESTRICT const data_end,
                                            uint32_t& opcode,
                                            uint32_t& fin,
                                            bool &is_control,
                                            bool &is_masked,
                                            uint32_t &mask_key,
                                            uint64_t &payload_len) {
            if FWS_UNLIKELY(data_end - data < 2) {
                return 0;
            }
            uint8_t* FWS_RESTRICT const data_start = data;
            uint32_t first_8_bit = data[0];
            opcode = first_8_bit & 15U;
            is_control = opcode >> 3;
            // TODO: Check whether opcode is valid in context
            if FWS_UNLIKELY(!IsValidOpcode(opcode)) {
                SetErrorFormatStr("Opcode %u is not valid", opcode);
                return -9;
            }
            if FWS_UNLIKELY(is_control) {
                is_rx_control_frame_ = true;
                last_rx_control_opcode_ = opcode;
            }
            else {
                bool is_first_part = (opcode != WS_OPCODE_CONTI);
                if (is_first_part) {
                    last_rx_opcode_ = opcode;
                }
            }
            fin = first_8_bit >> 7;
            uint32_t rev_1_to_3 = first_8_bit & 112U;
            if FWS_UNLIKELY(rev_1_to_3) {
                SetErrorFormatStr("rev bits are not zero");
                return -1;
            }
            uint32_t second_8_bit = data[1];
            is_masked = second_8_bit >> 7;
            payload_len = second_8_bit & 127U;
            data += 2;
            // unaligned load should work fine on x86 and arm after ARMv7
            if (payload_len == 126U) {
                if FWS_UNLIKELY(data_end - data < 2) {
                    return 0;
                }
                payload_len = Net2Host16(*(uint16_t*)(data));
                data += 2;
            }
            else if (payload_len == 127U) {
                if FWS_UNLIKELY(data_end - data < 8) {
                    return 0;
                }
                payload_len = Net2Host64(*(uint64_t*)(data));
                data += 8;
            }
            if FWS_UNLIKELY(payload_len > constants::MAX_WS_FRAME_SIZE) {
                SetErrorFormatStr("payload length %zu larger than"
                                  "constants::MAX_WS_FRAME_SIZE %zu",
                                  payload_len, constants::MAX_WS_FRAME_SIZE);
                return -2;
            }


            // Only frames sent from client to server should be masked
            if constexpr(is_server) {
                if FWS_LIKELY(is_masked) {
                    mask_key = *(uint32_t*)(data);
                    if FWS_UNLIKELY(data_end - data < 4) {
                        return 0;
                    }
                    data += 4;
                    last_rx_mask_key_ = mask_key;
                    // TODO: extensions support

                }
                else {
                    return -3;
                }
            }
            else {
                if FWS_UNLIKELY(is_masked) {
                    SetErrorFormatStr("Msg from server to client shouldn't be masked!");
                    return -4;
                }
            }
            return data - data_start;
        }

        static FWS_ALWAYS_INLINE bool IsValidOpcode(uint32_t opcode) {
            return (opcode <= 2U) | ((opcode >= 8U) & (opcode <= 10U));
        }

        template<class EventHandler>
        int SendControlMsg(EventHandler &handler, IOBuffer &io_buf, WSTxFrameType frame_type) {
            if (unsent_buf_ring_.empty()) {
                int send_ret = SendFrame(handler, io_buf, frame_type, true);
                return send_ret;
            }
            else {
                unsent_buf_ring_.emplace_back(std::move(io_buf), frame_type);
            }
            return 0;
        }

        template<class EventHandler>
        int OnRecvData(EventHandler& handler, IOBuffer &io_buf) {
            uint8_t * FWS_RESTRICT data = io_buf.data + io_buf.start_pos;

            uint8_t* const FWS_RESTRICT data_end = io_buf.data +
                    io_buf.start_pos + io_buf.size;
            while (data < data_end) {
                size_t remain_size = 0;
                // size of available payload in this rx packet
                size_t pl_size_available = 0;
                if (recv_status_ == WAIT_FRAME_HEAD) {
                    // Assume that we can at least recv the frame head in one rx
#ifdef FWS_DEV_DEBUG
                    if FWS_UNLIKELY(data_end - data < 2) {
                        fprintf(stderr, "remain size for frame: %zd, io_buf size: %zu\n",
                                data_end - data, io_buf.size);
                    }
#endif
                    uint32_t opcode;
                    uint32_t fin;
                    bool is_control;
                    bool is_masked;
                    uint32_t mask_key;
                    uint64_t payload_len;
                    FWS_ASSERT(last_rx_hdr_part_len_ < max_rx_frame_hdr_size());
                    size_t max_possible_remain_hdr_size = max_rx_frame_hdr_size() - last_rx_hdr_part_len_;
                    size_t cp_size = std::min(max_possible_remain_hdr_size, size_t(data_end - data));
                    memcpy(rx_ws_hdr_buf_ + last_rx_hdr_part_len_, data, cp_size);

//                    last_rx_hdr_part_len_ += cp_size;
                    int parse_hdr_ret = ParseFrameHdr(rx_ws_hdr_buf_,
                                                      rx_ws_hdr_buf_ + last_rx_hdr_part_len_ + cp_size,
                                                      opcode,
                                                      fin, is_control, is_masked, mask_key,
                                                      payload_len);
                    if FWS_LIKELY(parse_hdr_ret > 0) {
                        uint32_t new_add_hdr_size = parse_hdr_ret - last_rx_hdr_part_len_;
                        last_rx_hdr_part_len_ = 0;
                        data += new_add_hdr_size;
                        unread_pl_len_ = payload_len;
                        last_rx_fin_flag_ = fin;
                        remain_size = data_end - data;
                        pl_size_available = std::min(remain_size, payload_len);
                        if constexpr(is_server) {
                            WSMaskBytesFast(data, pl_size_available, mask_key);
                        }
                    }
                    else if (parse_hdr_ret == 0) {
                        FWS_ASSERT(data_end < data + max_rx_frame_hdr_size());
                        data = data_end;
                        last_rx_hdr_part_len_ += cp_size;
                        break;
                    }
                    else {
#ifdef FWS_DEV_DEBUG
                        fprintf(stderr, "fd %d Failed to parse frame hdr, %s\n",
                                tcp_socket_.fd(), std::string(GetErrorStrV()).c_str());
                        (void)(0);

#endif
                        return parse_hdr_ret;
                    }


                }
                else if (recv_status_ == WAIT_FRAME_PAYLOAD) {

                    remain_size = data_end - data;
                    pl_size_available = std::min(remain_size,
                                                        (size_t)unread_pl_len_);
                    if constexpr(is_server) {
                        uint32_t mask_key = last_rx_mask_key_;
                        WSMaskBytesFast(data, pl_size_available, mask_key);
                    }

                }
                else {
                    FWS_ASSERT_M(false, "Shouldn't run into this branch");
                }


                bool is_frame_end = unread_pl_len_ <= remain_size;
                bool is_msg_end = last_rx_fin_flag_ & is_frame_end;

                uint32_t opcode = is_rx_control_frame_ ? last_rx_control_opcode_
                                        : last_rx_opcode_;

                if FWS_UNLIKELY(is_rx_control_frame_ && (pl_size_available > 0U)) {
                    // we have received frame head in this step of loop
//#ifdef FWS_DEV_DEBUG
//                    fprintf(stderr, "It's rx control , fd %d, opcode %u, and pl size available: %zu,"
//                            "current recv_status_: %d, before buf_.size: %zu, ",
//                            tcp_socket_.fd(), opcode,
//                            pl_size_available, recv_status_, buf_.size);
//#endif
                    if (recv_status_ == WAIT_FRAME_HEAD) {
                        if (buf_.data == nullptr) {
                            buf_ = RequestBuf(constants::WS_MAX_CONTROL_FRAME_SIZE);
                        }
                        else {
                            // overwrite the previous unhandled control data (which
                            // happens in ping flood)
                            // TODO: make sure we don't have unsent close frame
                            buf_.size = 0U;
                            FWS_ASSERT(buf_.capacity == constants::WS_MAX_CONTROL_FRAME_SIZE);
                        }
                        buf_.start_pos = tx_control_frame_hdr_size();
                    }


                    uint8_t * FWS_RESTRICT buf_start = buf_.data + buf_.start_pos + buf_.size;

                    FWS_ASSERT(pl_size_available + buf_.start_pos + buf_.size <= constants::WS_MAX_CONTROL_FRAME_SIZE);
                    memcpy(buf_start, data, pl_size_available);
                    // data is added by pl_size_available below for all frames, so doesn't need to change here
//                    data += pl_size_available;
                    buf_.size += pl_size_available;
                }

                if FWS_UNLIKELY(is_frame_end & is_rx_control_frame_) {
                    if FWS_UNLIKELY(opcode == WS_OPCODE_PING) {
//                        SendFrame(handler, buf_, WS_OPCODE_PONG, true);
                        // ping frame should already be copied to control buf
//                        int req_write_ret = handler.OnNeedRequestWrite(*static_cast<Derived*>(this));
//                        if FWS_UNLIKELY(req_write_ret < 0) {
//                            return req_write_ret;
//                        }
                        SendControlMsg(handler, buf_, WS_PONG_FRAME);
//                        need_send_control_msg_ = true;
//                        unsent_control_msg_opcode_ = WS_OPCODE_PONG;

                    }
                    else if FWS_UNLIKELY(opcode == WS_OPCODE_CLOSE) {
                        uint32_t status_code = WS_NO_STATUS_CLOSE;
                        std::string_view reason{};

                        if (buf_.size >= 2) {
                            uint8_t * FWS_RESTRICT buf_start = buf_.data + buf_.start_pos;
                            status_code = Net2Host16(*(uint16_t*)buf_start);
//                            data += 2;
                            buf_start += 2;
                            size_t reason_len = buf_.size - 2U;
//                            size_t reason_len = pl_size_available -= 2U;
                            reason = std::string_view{(char*)buf_start, reason_len};
                        }
//                        bool is_wait_close = static_cast<Derived*>(this)->IsWaitForClose();
                        bool has_recv_close = static_cast<Derived*>(this)->HasRecvClose();
                        bool has_sent_close = static_cast<Derived*>(this)->HasSentClose();

                        if FWS_LIKELY(!has_recv_close) {
                            int handle_ret = static_cast<Derived*>(this)->OnRecvCloseFrame();
                            if FWS_UNLIKELY(handle_ret < 0) {
                                return handle_ret;
                            }
                        }
                        if (!has_sent_close) {

//                            int req_write_ret = handler.OnNeedRequestWrite(*static_cast<Derived*>(this));
//                            if FWS_UNLIKELY(req_write_ret < 0) {
//                                return req_write_ret;
//                            }
                            SendControlMsg(handler, buf_, WS_CLOSE_FRAME);
//                            need_send_control_msg_ = true;
//                            unsent_control_msg_opcode_ = WS_OPCODE_CLOSE;
                        }
                        handler.OnCloseConnection(*static_cast<Derived*>(this), status_code, reason);
                        // TODO: call on Close when the close handshake is over
//                        CloseCon(status_code, reason);

//                        ReclaimBuf(buf_);
//                        buf_.size = 0;
//                        break;
                    }
                }

                // Only non-control msg or pong msg is given to user
                if FWS_LIKELY(!is_rx_control_frame_ | (opcode == WS_OPCODE_PONG)) {
                    IOBuffer temp_io_buf{};
                    if FWS_LIKELY(!is_rx_control_frame_) {
                        temp_io_buf = IOBuffer(io_buf.data, pl_size_available, (data - io_buf.data),
                                                io_buf.capacity);
//                        AddBufRefCount(io_buf.data);
                    }
                    else {
                        temp_io_buf = std::move(buf_);
                    }
                    int on_rx_ws_part_ret = handler.OnRecvWsPart(
                            *static_cast<Derived*>(this),opcode,
                            std::move(temp_io_buf), is_frame_end, is_msg_end,
                            is_rx_control_frame_);
                    if FWS_UNLIKELY(on_rx_ws_part_ret < 0) {
                        return -5;
                    }
                    // when opcode is pong
                    if FWS_UNLIKELY(is_rx_control_frame_) {
                        buf_.size = 0;
                    }

                }


                data += pl_size_available;
                unread_pl_len_ -= pl_size_available;

                if FWS_UNLIKELY((unread_pl_len_ == 0U) & (is_rx_control_frame_)) {
                    is_rx_control_frame_ = false;
                }
                if FWS_UNLIKELY(!is_frame_end) {
                    if constexpr (is_server) {
                        last_rx_mask_key_ = RotateR(last_rx_mask_key_, (pl_size_available & 3U) * 8U);
                    }
                    recv_status_ = WAIT_FRAME_PAYLOAD;
                }
                else {
                    recv_status_ = WAIT_FRAME_HEAD;
                }

            } // while(data < data_end)
//            ReclaimBuf(io_buf);
            return 0;
        }

        template<class EventHandler>
        int TrySendBufferedFrames(EventHandler &handler) {
            while(!unsent_buf_ring_.empty()) {
                auto &cur_frame = unsent_buf_ring_.front();
                auto frame_type = cur_frame.frame_type;
                auto &cur_buf = cur_frame.buf;
                size_t buf_size = cur_buf.size;
                size_t this_time_send_size = std::min(buf_size, constants::MAX_WRITABLE_SIZE_ONE_TIME);
                ssize_t send_ret = tcp_socket_.Write(cur_buf, this_time_send_size);
                if FWS_UNLIKELY(send_ret < 0) {
                    if FWS_LIKELY(errno == EAGAIN) {
                        break;
                    }
                    return send_ret;
                }
                size_t send_size = send_ret;

                if (send_size == buf_size) {
                    if (frame_type == WS_CLOSE_FRAME) {
                        static_cast<Derived*>(this)->OnSentCloseFrame();
                    }
                    // send finish
                    unsent_buf_ring_.pop_front();
                    if (unsent_buf_ring_.empty()) {
                        handler.OnNeedStopWriteRequest(*static_cast<Derived*>(this));
                    }
                }
//                else if (send_size < this_time_send_size) {
                else {
                    // send buffer of OS is full now
                    break;
                }
                // else send_size == constants::MAX_WRITABLE_SIZE_ONE_TIME
            }
            return 0;
        }


        FWS_ALWAYS_INLINE static char ToLowerCase(char c) {
            c += (uint32_t(c - 'A') < 26U) << 5;
            return c;
        }


        FWS_ALWAYS_INLINE static void Sha1SecKey(const char* FWS_RESTRICT in_sec_key, char out_sha1[20]) {
            char src_key_buf[24 + 36];
            memcpy(src_key_buf, in_sec_key, 24);
            memcpy(src_key_buf + 24, constants::GLOBAL_WS_UUID, 36);
            fws::Sha1(src_key_buf, 24 + 36, out_sha1);
        }

        FWS_ALWAYS_INLINE static void Sha1AndBase64Key(const char* FWS_RESTRICT in_sec_key,
                                                       char out_sec_key[29]) {
            char sha1_buf[20];
            Sha1SecKey(in_sec_key, sha1_buf);
            assert(GetBase64EncodeLength(20) == 29);

            fws::Base64Encode(sha1_buf, 20, out_sec_key);
        }

//        template<class EventHandler>
//        ssize_t HandleUnsentControlMsgOnWritable(EventHandler &handler, size_t writable_size)  {
//            FWS_ASSERT(need_send_control_msg_);
//            FWS_ASSERT(buf_.size > 0);
//            size_t estimate_hdr_size = GetTxWSFrameHdrSize<is_server>(buf_.size);
//            size_t frame_size = estimate_hdr_size + buf_.size;
//            if FWS_UNLIKELY(frame_size > writable_size) {
//                return 0;
//            }
//            size_t payload_size = buf_.size;
//            ssize_t send_ret = SendFrame(handler, buf_,
//                         static_cast<fws::WSTxFrameType>(unsent_control_msg_opcode_), true);
//            if FWS_UNLIKELY(size_t(send_ret) < payload_size) {
//                SetErrorFormatStr("Failed to send control msg as a frame, send ret: %zd,"
//                                  "payload size: %zu, opcode: %u",
//                                  send_ret, payload_size, unsent_control_msg_opcode_);
//                return -11;
//            }
//            buf_.size = 0;
//            buf_.data = nullptr;
//            need_send_control_msg_ = false;
//            if (unsent_control_msg_opcode_ == WS_OPCODE_CLOSE) {
//                static_cast<Derived*>(this)->OnSentCloseFrame();
//            }
//            return frame_size;
//        }

        template<class EventHandler>
        ssize_t SendFrame(EventHandler &handler, IOBuffer& FWS_RESTRICT io_buf,
                          WSTxFrameType frame_type,
                          bool last_frame_if_possible) {
//            size_t first_estimate_hdr_size = GetTxWSFrameHdrSize<is_server>(io_buf.size);
//            if FWS_UNLIKELY(writable_size < first_estimate_hdr_size) {
//                return 0;
//            }
//            size_t send_payload_size = std::min((size_t)io_buf.size, writable_size - first_estimate_hdr_size);
            TrySendBufferedFrames(handler);
            size_t send_payload_size = io_buf.size;
            size_t expect_ws_hdr_size = GetTxWSFrameHdrSize<is_server>(send_payload_size);
            FWS_ASSERT_M(io_buf.start_pos >= expect_ws_hdr_size,
                         "IOBuffer start_pos should be larger enough to hold the ws frame header!");

//            FWS_ASSERT_M(io_buf.start_pos >= constants::MAX_WS_FRAME_HEADER_SIZE,
//                         "IOBuffer in send should be at least MAX_WS_FRAME_HEADER_SIZE");

            // Only when we can send this frame fully, we call it last frame
            bool is_last_frame = false;
            if (last_frame_if_possible & (size_t(io_buf.size) == send_payload_size)) {
                is_last_frame = true;
            }

            uint8_t* FWS_RESTRICT data = io_buf.data + io_buf.start_pos;
            uint8_t* data_end = data + send_payload_size;
            uint32_t mask_flags = 0;
            if constexpr (!is_server) {
                // TODO: Maybe want to use a more efficient rng
                uint32_t mask = SemiSecureRand32();
                WSMaskBytesFast(data, send_payload_size, mask);
                data -= 4;
                *(uint32_t*)data = mask;
                mask_flags = 128U;
            }
            uint32_t pl_flags = send_payload_size;
            if (send_payload_size >= 126) {
                if FWS_LIKELY(send_payload_size <= UINT16_MAX) {
                    data -= 2;
                    *(uint16_t*)data = Host2Net16(uint16_t(send_payload_size));
                    pl_flags = 126U;
                }
                else {
                    pl_flags = 127U;
                    data -= 8;
                    *(uint64_t*)data = Host2Net64(send_payload_size);
                }
            }

            *(--data) = mask_flags | pl_flags;

            uint32_t fin = is_last_frame;
            uint32_t opcode = WS_OPCODE_CONTI;
            bool is_control = IsControlFrame(frame_type);
            // If last msg has set the fin to 1, i.e. last msg has been sent
            if (!last_msg_not_fin_ | is_control) {
                opcode = static_cast<WSOpCode>(uint32_t(frame_type));
            }
            if (!is_control) {
                last_msg_not_fin_ = !is_last_frame;
            }

            *(--data) = (fin << 7) | opcode;
            size_t frame_size = data_end - data;
            size_t frame_hdr_size = expect_ws_hdr_size;
            FWS_ASSERT(frame_size == frame_hdr_size + send_payload_size);
            io_buf.start_pos -= frame_hdr_size;
//            size_t old_buf_size = io_buf.size;
            io_buf.size = frame_size;
            size_t this_time_write_size = std::min(frame_size, constants::MAX_WRITABLE_SIZE_ONE_TIME);
            ssize_t send_ret = 0;
            if (unsent_buf_ring_.empty()) {
                send_ret = tcp_socket_.Write(io_buf, this_time_write_size);
            }
//#ifdef FWS_DEV_DEBUG
//            if FWS_UNLIKELY(is_control || size_t(send_ret) != frame_size) {
//                fprintf(stderr, "fd %d Send frame opcode: %u, fin: %u, write ret: %zd,"
//                                "frame size: %zu, writable size %zu\n",
//                        tcp_socket_.fd(), opcode, fin, send_ret, frame_size, writable_size);
//            }
//
//#endif
            bool would_block = send_ret < 0 && errno == EAGAIN;
            if FWS_LIKELY(send_ret >= 0 || would_block) {
                size_t sent_size = send_ret;
                if ((send_ret >= 0 && sent_size < frame_size) || would_block) {
                    unsent_buf_ring_.emplace_back(std::move(io_buf), frame_type);
                    int req_write_ret = handler.OnNeedRequestWrite(*static_cast<Derived*>(this));
                    if FWS_UNLIKELY(req_write_ret < 0) {
                        return req_write_ret;
                    }
                }
                if (send_ret == ssize_t(frame_size)) {
                    if FWS_UNLIKELY(frame_type == WS_CLOSE_FRAME) {
                        static_cast<Derived*>(this)->OnSentCloseFrame();
                    }
                }
                return send_payload_size;
                // TODO: Use a ring buffer of IOBuffer to buffer the unsent io_buffer
//                FWS_ASSERT_M(size_t(send_ret) == frame_size, "send size should always equal"
//                                                             "to frame size");

//                ssize_t sent_pl_size =  send_ret - frame_hdr_size;
//                io_buf.size = old_buf_size - sent_pl_size;
                // exclude ws frame hdr size
//                return sent_pl_size;
//                return send_ret;
            }
            else {
                SetErrorFormatStr("Failed to write, %s", std::strerror(errno));
//                FWS_ASSERT(send_ret >= 0);
                return send_ret;
            }

        }



    }; // class WSocket



} // namespace fws