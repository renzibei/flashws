cmake_minimum_required(VERSION 3.13)
project(new_ws_client_basic)

set(CMAKE_CXX_STANDARD 17)

add_executable(test_ws_client test_ws_client.cpp)
add_executable(test_ws_server test_ws_server.cpp)

target_link_libraries(test_ws_client
        PRIVATE ${HDR_HIST_LIB}
        )

#add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)


target_link_libraries(test_ws_client PRIVATE fws::flashws)
target_link_libraries(test_ws_server PRIVATE fws::flashws)

if(NOT MSVC)
    target_compile_options(
            test_ws_client
            PRIVATE
#            -O3
            -g
            -Wall -Wextra
#            -fsanitize=address
#            -rdynamic
#            -fno-omit-frame-pointer
#            -fsanitize=undefined
    )

    target_compile_options(
            test_ws_server
            PRIVATE
#            -Og
            -g
            -Wall -Wextra
#            -fsanitize=address
#            -rdynamic
#            -fno-omit-frame-pointer
#            -fsanitize=undefined
    )
endif()


target_link_options(test_ws_client
        PRIVATE
        -flto
#        -fsanitize=address
#        -fsanitize=undefined
        )



target_link_options(test_ws_server
        PRIVATE
        -flto
#        -fsanitize=address
#        -fsanitize=undefined
        )