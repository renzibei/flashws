#include "flashws/flashws.h"
#include "flashws/net/floop.h"
#include "flashws/net/http_client.h"
#include "flashws/net/http_client_pool.h"
namespace test {





    struct Context {
        size_t send_cnt = 0;
        size_t conn_cnt = 0;
        fws::FLoop<> *loop_ptr = nullptr;
        fws::HTTPClientPool<true> *http_pool_ptr = nullptr;
        int64_t start_ns = 0;
        int64_t end_ns = 0;
        fws::HTTPClientPool<true>::HTTPOnRecvMsgFunc on_recv_msg;
        fws::HTTPClientPool<true>::HTTPOnErrorFunc on_error;

    };

    int TestHTTPClient() {
        fws::FLoop loop{};

        if (loop.Init<true>() < 0) {
            printf("Failed to init floop, %s\n", fws::GetErrorStrP());
            return -1;
        }

        int ssl_manager_init_ret = fws::SSLManager::instance().Init(true, nullptr, nullptr, nullptr);
        if (ssl_manager_init_ret < 0) {
            printf("Error in ssl manager init, return %d, %s\n",
                   ssl_manager_init_ret, fws::GetErrorStrP());
            std::abort();
        }

        constexpr static std::string_view HOST = "www.google.com";
//        constexpr static std::string_view HOST = "www.baidu.com";
//        constexpr static std::string_view HOST = "www.cloudflare.com";
        constexpr static std::string_view PATH = "/";
        constexpr static std::string_view IP_STR = "74.125.138.99"; // google
//        constexpr static std::string_view IP_STR = "103.235.47.103"; // baidu
//        constexpr static std::string_view IP_STR = "104.16.124.96"; // cloudflare
        constexpr static int PORT = 443;
//        fws::HTTPClient<true, Context> *http_client_ptr = nullptr;
        constexpr size_t REQUEST_COUNT = 9;
        constexpr size_t KEEP_CONN_CNT = 10;
        constexpr size_t MAX_CONN_CNT = 10;

        constexpr size_t TEST_TARGET_CONN_CNT_SAME_TIME = 3;
        constexpr int64_t NS_PER_SEC = 1'000'000'000LL;

        constexpr int64_t WAIT_TO_SEND_NS = 1LL * NS_PER_SEC;
        constexpr int64_t PRE_EXIT_WAIT_NS = 0LL * NS_PER_SEC;
//        size_t cur_request_count = 0;
        fws::HTTPClientPool<true> http_pool{};
        if (http_pool.Init(loop, HOST, IP_STR, PORT, KEEP_CONN_CNT, MAX_CONN_CNT) < 0) {
            printf("Error in init http pool, %s\n", fws::GetErrorStrP());
            return -1;
        }
        Context ctx{0, 0, &loop, &http_pool, 0, 0};
        ctx.start_ns = fws::GetNowNsFromEpoch();
        {

            auto on_recv_msg = [&ctx](fws::HTTPClientPool<true>::ClientType &http, int status_code,
                    fws::IOBuffer &&buf){
                printf("HTTP OnRecvMsg, status: %d, msg size %ld\n", status_code, buf.size);
                fwrite(buf.data + buf.start_pos, 1, buf.size, stdout);
                constexpr char ENDLINE = '\n';
                fwrite(&ENDLINE, 1, 1, stdout);

                auto [hdr_arr, hdr_cnt] = http.headers();
                for (size_t i = 0; i < hdr_cnt; ++i) {
                    printf("%s: %s\n", std::string(hdr_arr[i].key).c_str(),
                           std::string(hdr_arr[i].value).c_str());
                }
                if (ctx.send_cnt >= REQUEST_COUNT) {
                    if (ctx.end_ns == 0) {
                        ctx.end_ns = fws::GetNowNsFromEpoch();
//                    http.Close();
//                    ctx.loop_ptr->StopRun();

                    }
                    return;
                }
                ++ctx.send_cnt;
                if (ctx.http_pool_ptr->template SendRequest<fws::HTTP_GET_OP>(PATH, ctx.on_recv_msg, ctx.on_error) < 0) {
                    printf("Error in send request, %s\n", fws::GetErrorStrP());
                    ctx.loop_ptr->StopRun();
                }

//                if (http.SendRequest<fws::HTTP_GET_OP>(PATH) < 0) {
//                    printf("Error in second send request, %s\n", fws::GetErrorStrP());
//                    std::exit(-1);
//                }
            };

            auto on_error = [](fws::HTTPClientPool<true>::ClientType &http, std::string_view reason) {
                printf("HTTP OnError, err: %s\n", std::string(reason).c_str());
            };
            ctx.on_recv_msg = std::move(on_recv_msg);
            ctx.on_error = std::move(on_error);

//            http_client_ptr = client;

        }
        loop.SetOnEventFunc([&ctx](fws::FLoop<>& loop) {
            if (ctx.conn_cnt < TEST_TARGET_CONN_CNT_SAME_TIME && ctx.send_cnt < REQUEST_COUNT) {
                int64_t now_ns = fws::GetNowNsFromEpoch();
                if (now_ns - ctx.start_ns > WAIT_TO_SEND_NS) {
                    ++ctx.send_cnt;
                    if (ctx.http_pool_ptr->template SendRequest<fws::HTTP_GET_OP>(PATH, ctx.on_recv_msg, ctx.on_error) < 0) {
                        printf("Error in send request, %s\n", fws::GetErrorStrP());
                        ctx.loop_ptr->StopRun();
                    }
                    ++ctx.conn_cnt;
                }
            }
            if (ctx.send_cnt >= REQUEST_COUNT && ctx.end_ns != 0) {
                int64_t now_ns = fws::GetNowNsFromEpoch();
                if (now_ns - ctx.end_ns > PRE_EXIT_WAIT_NS) {
                    ctx.loop_ptr->StopRun();
                }
            }

        });

        loop.Run();
        return 0;
    }

} // namespace test

int main() {
    return  test::TestHTTPClient();
    return 0;
}