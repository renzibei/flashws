cmake_minimum_required(VERSION 3.13)
project(flashws)



add_library(flashws INTERFACE)

add_library(fws::flashws ALIAS flashws)



target_include_directories(flashws INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

OPTION(FWS_ENABLE_FSTACK "Use f-stack, other wise system api" ON)
OPTION(FWS_DEBUG "In Debug Mode" ON)
OPTION(FWS_DEV_DEBUG "Debug Mode For Development" OFF)
OPTION(FWS_USE_BORINGSSL "Use BoringSSL" OFF)

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
MESSAGE(STATUS "FWS_USE_BORINGSSL ${FWS_USE_BORINGSSL}")


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

if (FWS_USE_BORINGSSL AND NOT FWS_ENABLE_FSTACK)
    add_subdirectory(thirdparty/boringssl)
    target_link_libraries(
            flashws
            INTERFACE
            crypto
            ssl
    )
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(
            flashws
            INTERFACE
            OpenSSL::SSL
            OpenSSL::Crypto
    )
endif()




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
            -lnuma
            )

endif()


