cmake_minimum_required(VERSION 3.13)
project(test_utils)

set(CMAKE_CXX_STANDARD 17)

add_executable(test_utils test_utils.cpp)
add_executable(test_mask test_mask.cpp)

add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)
#add_subdirectory(../../thirdparty/Compile-time-hash-functions ${CMAKE_CURRENT_BINARY_DIR}/compile_time_hash_functions)
target_link_libraries(test_utils PRIVATE
        fws::flashws
#        compile_time_hash
)

target_link_libraries(test_mask PRIVATE fws::flashws)

if(NOT MSVC)
    target_compile_options(test_utils
            PRIVATE
            -Wall -Wextra
            -g
#            -O3
#            -march=native
#                        -fsanitize=address
            )

    target_compile_options(test_mask
            PRIVATE
            -Wall -Wextra
            -g
#            -O3
#            -march=native
            #                        -fsanitize=address
    )

endif()

target_link_options(test_utils
        PRIVATE
#                -fsanitize=address
        )

