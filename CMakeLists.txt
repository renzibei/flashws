cmake_minimum_required(VERSION 3.13)
project(flashws)



add_library(flashws INTERFACE)

add_library(fws::flashws ALIAS flashws)

find_package(OpenSSL REQUIRED)

target_include_directories(flashws INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

OPTION(FWS_ENABLE_FSTACK "Use f-stack, other wise system api" ON)
OPTION(FWS_DEBUG "In Debug Mode" ON)
OPTION(FWS_DEV_DEBUG "Debug Mode For Development" OFF)

if(FWS_DEBUG)
    target_compile_definitions(flashws
            INTERFACE -DFWS_DEBUG)
endif()

if(FWS_DEV_DEBUG)
    target_compile_definitions(flashws
            INTERFACE -DFWS_DEV_DEBUG)
endif()

MESSAGE(STATUS "FWS_ENABLE_FSTACK ${FWS_ENABLE_FSTACK}")
MESSAGE(STATUS "FWS_DEBUG: ${FWS_DEBUG}")
MESSAGE(STATUS "FWS_DEV_DEBUG ${FWS_DEV_DEBUG}")

# Check if the compiler supports AVX2
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-mavx2" COMPILER_SUPPORTS_AVX2)

if(COMPILER_SUPPORTS_AVX2 AND (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64"))
    message(STATUS "AVX2 supported. Adding -mavx2 flag.")
    target_compile_options(flashws
            INTERFACE
            -mavx2
            )
else()
    message(STATUS "AVX2 not supported by the compiler.")
endif()

target_link_libraries(
        flashws
        INTERFACE
        OpenSSL::SSL
)

if(FWS_ENABLE_FSTACK)
    target_compile_definitions(flashws
            INTERFACE
            -DFWS_ENABLE_FSTACK)

    find_package(PkgConfig REQUIRED)

    pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

    target_compile_options(flashws
            INTERFACE
            ${DPDK_CFLAGS}
            )



    target_link_options(flashws
            INTERFACE
            ${DPDK_STATIC_LDFLAGS}
            "SHELL:-Wl,--whole-archive,-lfstack,--no-whole-archive"
            )

    target_link_options(flashws
            INTERFACE
            -pthread
            -lm
            -lrt
            -ldl
            -lcrypto
            -lnuma
            )
endif()


