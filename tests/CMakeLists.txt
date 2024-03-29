cmake_minimum_required(VERSION 3.13)
project(flashws_tests)


add_subdirectory(.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)

OPTION(USE_RAW_HISTOGRAM "Use raw_histogram, otherwise use HdrHistogram_c" OFF)

if(USE_RAW_HISTOGRAM)
    ADD_DEFINITIONS(-DUSE_RAW_HISTOGRAM)
    SET(HDR_HIST_LIB "")
else()
    add_subdirectory(../thirdparty/HdrHistogram_c ${CMAKE_CURRENT_BINARY_DIR}/HdrHistogram_c)
    SET(HDR_HIST_LIB hdr_histogram_static)
endif()

add_subdirectory(test-new-tcp-echo)
add_subdirectory(test-https-client)
add_subdirectory(new-ws-echo)
add_subdirectory(test_ring_buffer)
add_subdirectory(test-utils)