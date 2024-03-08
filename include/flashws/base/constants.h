#pragma once
#include <cstdint>
#include <cstddef>



namespace fws {

    namespace constants {

        constexpr inline bool ENABLE_BUSY_POLL_BY_DEFAULT = true;
        constexpr inline int BUSY_POLL_US_IF_ENABLED = 800;

        constexpr inline bool ENABLE_NO_DELAY_BY_DEFAULT = true;
        constexpr inline bool ENABLE_NON_BLOCK_BY_DEFAULT = true;

        // If this is enabled, the FLoop will update the time every time there
        // is an event. Users can access the time by calling last_event_time_ns()
        constexpr inline bool ENABLE_FLOOP_EVENT_TIME_UPDATE = false;

        // If this is enabled, even when there is no active event, the FEventWait
        // will return immediately. This is useful for some cases like manually
        // busy polling and check for events like timeout. However, for epoll,
        // this may harm the latency compared to the linux system-level busy_poll.
        // F-stack will return immediately regardless of this setting.
        // When using POSIX poll, for maximum performance, system level busy_poll should
        // be used with this.
#ifdef FWS_FORCE_TIMEOUT_ZERO
        constexpr inline bool FEVENT_WAIT_RETURN_IMMEDIATELY = true;
#else
        constexpr inline bool FEVENT_WAIT_RETURN_IMMEDIATELY = false;
#endif

        // This takes the stack space
        constexpr inline size_t MAX_REQ_URI_LENGTH = 512;

        constexpr inline size_t MAX_HANDSHAKE_RESP_LENGTH = 512;
        constexpr inline size_t MAX_HANDSHAKE_REQUEST_LENGTH = 4096;

//        constexpr inline size_t MAX_WRITABLE_SIZE_ONE_TIME = 16384;
        // TODO: dynamic change this
#ifdef FWS_ENABLE_FSTACK
        constexpr inline size_t MAX_WRITABLE_SIZE_ONE_TIME = 65536;
#else
        constexpr inline size_t MAX_WRITABLE_SIZE_ONE_TIME = 16384;
#endif

        // Used in the buffer of TLS and TCP read one time.
#ifdef FWS_ENABLE_FSTACK
        constexpr inline size_t MAX_READABLE_SIZE_ONE_TIME = 1 << 21;
#else
        constexpr inline size_t MAX_READABLE_SIZE_ONE_TIME = 1 << 21;
#endif
        // Padding before the buffer if using TCP/TLS read. WS may need this.
        constexpr inline size_t DEFAULT_READ_BUF_PRE_PADDING_SIZE = 32;

//        constexpr inline size_t MAX_WRITABLE_SIZE_ONE_TIME = 1UL << 21;

        // The actual maximum size of frame size is 4 GB for both recv and send
        constexpr inline size_t MAX_WS_FRAME_SIZE = (1ULL << 32);

        constexpr inline size_t MAX_WS_FRAME_HEADER_SIZE = 14;
        constexpr inline size_t MAX_WS_SERVER_RX_FRAME_HEADER_SIZE = 14;
        constexpr inline size_t MAX_WS_CLIENT_RX_FRAME_HEADER_SIZE = 10;
        // The typical frame hdr size for frame in [126, 65536] is 8 bytes
        // For alignment consideration, use 24 bytes ahead
        constexpr inline size_t SUGGEST_RESERVE_WS_HDR_SIZE = 24;
        constexpr inline size_t WS_SERVER_TX_CONTROL_HDR_SIZE = 2;
        constexpr inline size_t WS_CLIENT_TX_CONTROL_HDR_SIZE = 6;
        constexpr inline size_t WS_MAX_CONTROL_FRAME_SIZE = 125;

        static_assert(SUGGEST_RESERVE_WS_HDR_SIZE <= DEFAULT_READ_BUF_PRE_PADDING_SIZE);

        constexpr inline size_t HTTP_REQUEST_RESERVE_HDR_SIZE = 512;
        static_assert(HTTP_REQUEST_RESERVE_HDR_SIZE < MAX_READABLE_SIZE_ONE_TIME);

        constexpr inline size_t HTTP_MAX_RECV_BUF_SIZE = 1UL << 23;

        // Defined in RFC doc
        constexpr inline const char SEC_WS_VERSION[] = "13";

        constexpr inline const char GLOBAL_WS_UUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        // uuid str length is 36
        static_assert(sizeof(GLOBAL_WS_UUID) == 37);
    } // namespace constants

} // namespace fws