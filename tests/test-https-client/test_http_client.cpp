#include "flashws/flashws.h"
#include "flashws/net/floop.h"
#include "flashws/net/http_client.h"

namespace test {





    struct Context {
        int send_cnt = 0;
        fws::FLoop<> *loop_ptr = nullptr;
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

//        constexpr static std::string_view HOST = "www.google.com";
//        constexpr static std::string_view HOST = "www.baidu.com";
        constexpr static std::string_view HOST = "www.cloudflare.com";
        constexpr static std::string_view PATH = "/";
//        constexpr static std::string_view IP_STR = "74.125.138.99"; // google
//        constexpr static std::string_view IP_STR = "103.235.47.103"; // baidu
        constexpr static std::string_view IP_STR = "104.16.124.96"; // cloudflare
        constexpr static int PORT = 443;
        fws::HTTPClient<true, Context> *http_client_ptr = nullptr;
        constexpr size_t REQUEST_COUNT = 4;
//        size_t cur_request_count = 0;
        {
            Context ctx{0, &loop};
            auto [create_ret, client] = fws::HTTPClient<true, Context>::Create(loop, HOST,
                                                                               IP_STR, PORT, std::move(ctx));
            if (create_ret < 0) {
                printf("Error in create http client, %s\n", fws::GetErrorStrP());
                return -1;
            }
//            client->SetOnRecvMsg([](fws::HTTPClient<true, Context> &http, int status_code,
//                    fws::IOBuffer &&buf,  Context &ctx){
//                printf("HTTP OnRecvMsg, status: %d, msg size %ld\n", status_code, buf.size);
//                fwrite(buf.data + buf.start_pos, 1, buf.size, stdout);
//                constexpr char ENDLINE = '\n';
//                fwrite(&ENDLINE, 1, 1, stdout);
//
//                auto [hdr_arr, hdr_cnt] = http.headers();
//                for (size_t i = 0; i < hdr_cnt; ++i) {
//                    printf("%s: %s\n", std::string(hdr_arr[i].key).c_str(),
//                           std::string(hdr_arr[i].value).c_str());
//                }
//                ++ctx.send_cnt;
//                if (ctx.send_cnt == REQUEST_COUNT) {
//                    http.Close();
//                    ctx.loop_ptr->StopRun();
//                    return;
//                }
//                if (http.SendRequest<fws::HTTP_GET_OP>(PATH) < 0) {
//                    printf("Error in second send request, %s\n", fws::GetErrorStrP());
//                    std::exit(-1);
//                }
//            });
            client->SetOnRecvPart([](fws::HTTPClient<true, Context> &http, int status_code,
                    bool is_msg_end, fws::IOBuffer &&buf,  Context& ctx) {
                printf("HTTP OnRead, status: %d, is_end: %d, buf size %ld\n",
                       status_code, is_msg_end, buf.size);
                fwrite(buf.data + buf.start_pos, 1, buf.size, stdout);
                constexpr char ENDLINE = '\n';
                fwrite(&ENDLINE, 1, 1, stdout);
                if (is_msg_end) {
                    auto [hdr_arr, hdr_cnt] = http.headers();
                    for (size_t i = 0; i < hdr_cnt; ++i) {
                        printf("%s: %s\n", std::string(hdr_arr[i].key).c_str(),
                               std::string(hdr_arr[i].value).c_str());
                    }
                    ++ctx.send_cnt;
                    if (ctx.send_cnt == REQUEST_COUNT) {
                        http.Close();
                        ctx.loop_ptr->StopRun();
                        return;
                    }
                    if (http.SendRequest<fws::HTTP_GET_OP>(PATH) < 0) {
                        printf("Error in second send request, %s\n", fws::GetErrorStrP());
                        std::exit(-1);
                    }
                }
                fflush(stdout);

            });
            client->SetOnClose([](fws::HTTPClient<true, Context> &http, Context&) {
                printf("HTTP OnClose\n");
            });
            client->SetOnOpen([](fws::HTTPClient<true, Context> &http, Context&) {
                printf("HTTP OnOpen\n");
                if (http.SendRequest<fws::HTTP_GET_OP>(PATH) < 0) {
                    printf("Error in send request, %s\n", fws::GetErrorStrP());
                    std::exit(-1);
                }
            });
            client->SetOnError([](fws::HTTPClient<true, Context> &http, std::string_view reason, Context&) {
                printf("HTTP OnError, err: %s\n", std::string(reason).c_str());
            });
            http_client_ptr = client;

        }

        loop.Run();
        return 0;
    }

} // namespace test

int main() {
    return  test::TestHTTPClient();
    return 0;
}