cmake_minimum_required(VERSION 3.14)

project(tlsfp CXX)

# ------------------------------------------------------------------------------
# Build configuration
# ------------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug"
        "Release"
        "RelWithDebInfo"
        "MinSizeRel"
    )
endif()


# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

find_path(PCAP_INCLUDE_DIR NAMES pcap.h)

find_library(
    PCAP_LIBRARY
    NAMES pcap wpcap
)

if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR
        "libpcap/npcap development files not found."
    )
endif()

add_library(pcap::pcap UNKNOWN IMPORTED)

set_target_properties(pcap::pcap PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)


# ------------------------------------------------------------------------------
# Static Library Target
# ------------------------------------------------------------------------------

add_library(tlsfp_lib STATIC
    src/capture.cpp
    src/db.cpp
    src/parser.cpp
    src/ja3.cpp
    src/ja4.cpp
)

target_include_directories(tlsfp_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
)

target_link_libraries(tlsfp_lib
    PUBLIC
        pcap::pcap
        OpenSSL::Crypto
        Threads::Threads
)


# ------------------------------------------------------------------------------
# Compiler flags
# ------------------------------------------------------------------------------

if(MSVC)

    target_compile_options(tlsfp_lib PRIVATE
        /W4
        /permissive-
    )

elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")

    target_compile_options(tlsfp_lib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual

        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>

        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )

    target_link_options(tlsfp_lib PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )

endif()


# ------------------------------------------------------------------------------
# Main Binary Target
# ------------------------------------------------------------------------------

add_executable(tlsfp_engine
    src/main.cpp
)

target_link_libraries(tlsfp_engine
    PRIVATE
        tlsfp_lib
)


# ------------------------------------------------------------------------------
# CTest / GoogleTest
# ------------------------------------------------------------------------------

include(CTest)

if(BUILD_TESTING)

    include(FetchContent)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )

    FetchContent_MakeAvailable(googletest)


    # Unit tests
    add_executable(tlsfp_unit_tests
        tests/test_fingerprints.cpp
    )

    target_link_libraries(tlsfp_unit_tests
        PRIVATE
            tlsfp_lib
            GTest::gtest_main
    )


    # Register GoogleTest tests with CTest
    include(GoogleTest)

    gtest_discover_tests(tlsfp_unit_tests)

endif()