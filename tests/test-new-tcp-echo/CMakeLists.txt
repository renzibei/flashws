cmake_minimum_required(VERSION 3.13)
project(test_new_tcp_echo)

set(CMAKE_CXX_STANDARD 17)

add_executable(client client.cpp)
add_executable(server server.cpp)

OPTION(USE_RAW_HISTOGRAM "Use raw_histogram, otherwise use HdrHistogram_c" OFF)

if(USE_RAW_HISTOGRAM)
    ADD_DEFINITIONS(-DUSE_RAW_HISTOGRAM)
    SET(HDR_HIST_LIB "")
else()
    add_subdirectory(../../thirdparty/HdrHistogram_c ${CMAKE_CURRENT_BINARY_DIR}/HdrHistogram_c)
    SET(HDR_HIST_LIB hdr_histogram_static)
endif()

target_link_libraries(client
        PRIVATE ${HDR_HIST_LIB}
)

add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)
target_link_libraries(client PRIVATE fws::flashws)
target_link_libraries(server PRIVATE fws::flashws)

if(NOT MSVC)
    target_compile_options(client
        PRIVATE
        -Wall -Wextra
        -g
#        -O3
#            -fsanitize=address
    )

    target_compile_options(server
        PRIVATE
        -Wall -Wextra
        -g
#        -O3
#            -fsanitize=address
    )
endif()

target_link_options(client
        PRIVATE
#        -fsanitize=address
        )

target_link_options(server
        PRIVATE
#        -fsanitize=address
        )