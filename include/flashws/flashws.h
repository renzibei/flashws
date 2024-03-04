#pragma once

#include <cstdint>
#include <cstddef>

#include "flashws/base/base_include.h"
#include "flashws/net/fevent.h"
#include "flashws/net/floop.h"
#include "flashws/net/ws_client_socket.h"
#include "flashws/net/ws_server_socket.h"



namespace fws {


    inline int InitEnv(int argc, char * argv[]) {
        int ret = 0;
#ifdef FWS_ENABLE_FSTACK
        ret = ff_init(argc, argv);
#else
        (void)argc;
        (void)argv;
#endif
        return ret;
    }

    using OneLoopFunc = int (*)(void*);

    inline void StartRunLoop(OneLoopFunc loop_func, void *arg) {
#ifdef FWS_ENABLE_FSTACK
        ff_run(loop_func, arg);
#else
        while (true) {
            loop_func(arg);
        }
#endif
    }

} // namespace fws

