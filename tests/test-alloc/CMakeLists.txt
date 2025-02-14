cmake_minimum_required(VERSION 3.13)
project(test_alloc)

set(CMAKE_CXX_STANDARD 17)

add_executable(alloc_latency alloc_latency.cpp
        )

target_include_directories(alloc_latency
        PRIVATE
        ../../include
        )


target_link_libraries(alloc_latency
        PRIVATE ${HDR_HIST_LIB}
        )


if(NOT MSVC)
    target_compile_options(alloc_latency
            PRIVATE
            -Wall -Wextra
            )

endif()

#target_compile_options(alloc_latency
#        PRIVATE
#        -fsanitize=address
#)
#
#target_link_options(alloc_latency
#        PRIVATE
#        -fsanitize=address
#        )

add_executable(alloc_speed_compare alloc_speed_compare.cpp)
target_include_directories(alloc_speed_compare
        PRIVATE
        ../../include
)

if(NOT MSVC)
    target_compile_options(alloc_speed_compare
            PRIVATE
            -Wall -Wextra
    )

endif()