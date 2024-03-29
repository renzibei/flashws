cmake_minimum_required(VERSION 3.13)
project(test_new_tcp_echo)

set(CMAKE_CXX_STANDARD 17)

add_executable(tcp_echo_client client.cpp)
add_executable(tcp_echo_server server.cpp)

target_link_libraries(tcp_echo_client
        PRIVATE ${HDR_HIST_LIB}
)

#add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)
target_link_libraries(tcp_echo_client PRIVATE fws::flashws)
target_link_libraries(tcp_echo_server PRIVATE fws::flashws)

if(NOT MSVC)
    target_compile_options(tcp_echo_client
        PRIVATE
        -Wall -Wextra
        -g
#        -O3
#            -fsanitize=address
    )

    target_compile_options(tcp_echo_server
        PRIVATE
        -Wall -Wextra
        -g
#        -O3
#            -fsanitize=address
    )
endif()

target_link_options(tcp_echo_client
        PRIVATE
#        -fsanitize=address
        )

target_link_options(tcp_echo_server
        PRIVATE
#        -fsanitize=address
        )