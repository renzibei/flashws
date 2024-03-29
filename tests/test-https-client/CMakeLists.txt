cmake_minimum_required(VERSION 3.13)
project(test_ws_client_basic)

set(CMAKE_CXX_STANDARD 17)

add_executable(new_https_client https_client.cpp)
#add_executable(http_client test_http_client.cpp)
add_executable(test_search test_search.cpp)
add_executable(http_pool test_http_pool.cpp)




#add_subdirectory(../.. ${CMAKE_CURRENT_BINARY_DIR}/flashws)


target_link_libraries(new_https_client PRIVATE fws::flashws)
#target_link_libraries(http_client PRIVATE fws::flashws)
target_link_libraries(test_search PRIVATE fws::flashws)
target_link_libraries(http_pool PRIVATE fws::flashws)

if(NOT MSVC)

    target_compile_options(
            new_https_client
            PRIVATE
            -g
            -Wall -Wextra
            -fsanitize=address

    )


#    target_compile_options(
#            http_client
#            PRIVATE
#            -g
#            -Wall -Wextra
#            -fsanitize=address
#    )

    target_compile_options(
            test_search
            PRIVATE
            -g
            -Wall -Wextra
    )

    target_compile_options(
            http_pool
            PRIVATE
            -g
            -Wall -Wextra
            -fsanitize=address
    )


endif()



target_link_options(new_https_client
        PRIVATE
        -fsanitize=address
        )

#target_link_options(http_client
#        PRIVATE
#        -fsanitize=address
#        )


target_link_options(http_pool
        PRIVATE
        -fsanitize=address
)