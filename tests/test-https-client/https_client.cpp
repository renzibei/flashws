#include "test_def.h"
#include "flashws/net/tls_socket.h"
#include "flashws/net/fevent.h"
#include "flashws/flashws.h"
#include "flashws/net/floop.h"

namespace test {

    struct ClientContext {
        size_t sent_size;
    };

    int TestHTTPSClient(int argc, char** argv) {

        if (fws::InitEnv(argc, argv) < 0) {
            printf("Error in init env: %s\n", fws::GetErrorString().c_str());
            return -1;
        }

        int ssl_manager_init_ret = fws::SSLManager::instance().Init(true, nullptr, nullptr, nullptr);
        if (ssl_manager_init_ret < 0) {
            printf("Error in ssl manager init, return %d, %s\n",
                   ssl_manager_init_ret, fws::GetErrorStrP());
            std::abort();
        }

        fws::FLoop loop;
        if (loop.Init<true>() < 0) {
            printf("Failed to init floop, %s\n", fws::GetErrorStrP());
            return -1;
        }



        fws::TLSSocket socket{};
        if (socket.Init<false>(REAL_HOST) < 0) {
            printf("Failed to init tls socket, %s\n", fws::GetErrorStrP());
            return -1;
        }



        socket.SetOnOpen([](fws::TLSSocket &sock, void *user_data){
            new (user_data) ClientContext{};
            ClientContext *ctx = static_cast<ClientContext*>(user_data);
            ctx->sent_size = 0;
            printf("On open called in tls socket\n");
            size_t target_size = sizeof(https_request) - 1;
            int write_ret = sock.Write(https_request + ctx->sent_size, target_size - ctx->sent_size);
            if (write_ret < 0) {
                printf("Error in tls write, return %d, %s\n",
                       write_ret, fws::GetErrorStrP());
                std::abort();
            }
            ctx->sent_size += write_ret;
            printf("Sent size: %d\n", write_ret);
        });

        socket.SetOnWritable([](fws::TLSSocket &sock, size_t writable_size, void *user_data){
            printf("On writable called in tls socket, writable size: %zu\n", writable_size);
            ClientContext *ctx = static_cast<ClientContext*>(user_data);
            size_t target_size = sizeof(https_request) - 1;
            if (ctx->sent_size < target_size) {
                int write_ret = sock.Write(https_request + ctx->sent_size, target_size - ctx->sent_size);
                if (write_ret < 0) {
                    printf("Error in tls write, return %d, %s\n",
                           write_ret, fws::GetErrorStrP());
                    std::abort();
                }
                ctx->sent_size += write_ret;
                printf("Sent size: %d\n", write_ret);
            }
        });

        socket.SetOnReadable([](fws::TLSSocket & /*sock*/, fws::IOBuffer &&buf, void * /*user_data*/){
            printf("On readable called in tls socket, get %ld bytes\n", buf.size);
            if (buf.size > 0) {
                fwrite(buf.data + buf.start_pos, 1, buf.size, stdout);
            }

        });

        socket.SetOnClose([&loop](fws::TLSSocket & /*sock*/, void * /*user_data*/){
            printf("On close called in tls socket\n");
            loop.StopRun();
        });

        socket.SetOnError([](fws::TLSSocket& , int code, std::string_view reason, void *) {
            printf("On error called in tls socket, code: %d, reason: %s\n", code, reason.data());
        });

        int con_ret = socket.Connect(host_ip, host_port);
        if FWS_UNLIKELY(con_ret < 0 && errno != EINPROGRESS) {
            printf("Error in connect, return %d, %s\n",
                   con_ret, fws::GetErrorStrP());
            std::abort();
        }

        auto [add_ret, _] = loop.AddSocket(std::move(socket), sizeof(ClientContext), false);
        if (add_ret < 0) {
            printf("Failed to add tls socket to loop, %s\n", fws::GetErrorStrP());
            return -1;
        }

        loop.Run();

        return 0;
    }


} // namespace test

int main(int argc, char** argv) {

    return test::TestHTTPSClient(argc, argv);
}