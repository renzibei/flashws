cmake_minimum_required(VERSION 3.13)
project(test_ws_client_basic)

set(CMAKE_CXX_STANDARD 17)

add_executable(test_ws_client test_ws_client.cpp)
add_executable(test_ws_server test_ws_server.cpp)

OPTION(USE_RAW_HISTOGRAM "Use raw_histogram, otherwise use HdrHistogram_c" OFF)

if(USE_RAW_HISTOGRAM)
    ADD_DEFINITIONS(-DUSE_RAW_HISTOGRAM)
    SET(HDR_HIST_LIB "")
else()
    add_subdirectory(../../thirdparty/HdrHistogram_c ${CMAKE_CURRENT_BINARY_DIR}/HdrHistogram_c)
    SET(HDR_HIST_LIB hdr_histogram_static)
endif()

target_link_libraries(test_ws_client
        PRIVATE ${HDR_HIST_LIB}
        )

add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)


target_link_libraries(test_ws_client PRIVATE fws::flashws)
target_link_libraries(test_ws_server PRIVATE fws::flashws)

if(NOT MSVC)
    target_compile_options(
            test_ws_client
            PRIVATE
            -O3
#            -g
            -Wall -Wextra
#            -fsanitize=address
    )

    target_compile_options(
            test_ws_server
            PRIVATE
            -O3
#            -g
            -Wall -Wextra
#            -fsanitize=address
    )
endif()


target_link_options(test_ws_client
        PRIVATE
#        -fsanitize=address
        )



target_link_options(test_ws_server
        PRIVATE
#        -fsanitize=address

        )