cmake_minimum_required(VERSION 3.13)
project(test_rb)

set(CMAKE_CXX_STANDARD 17)

add_executable(test_rb test_rb.cpp)
add_executable(test_block_queue test_block_queue.cpp)

#add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)

target_link_libraries(test_rb PRIVATE fws::flashws)
target_link_libraries(test_block_queue PRIVATE fws::flashws)



target_link_libraries(test_rb
        PRIVATE ${HDR_HIST_LIB}
        )

target_link_libraries(test_block_queue
        PRIVATE ${HDR_HIST_LIB}
        )


if(NOT MSVC)
    target_compile_options(test_rb
            PRIVATE
            -Wall -Wextra
            -g
#            -O3
#                                    -fsanitize=address
            )

    target_compile_options(test_block_queue
            PRIVATE
            -Wall -Wextra
            -g
#            -O3
#            -fsanitize=address

            )



endif()

target_link_options(test_rb
        PRIVATE
                        -fsanitize=address
        )

target_link_options(test_block_queue
        PRIVATE
                        -fsanitize=address
        )