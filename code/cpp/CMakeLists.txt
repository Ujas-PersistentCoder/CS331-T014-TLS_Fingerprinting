cmake_minimum_required(VERSION 3.14)
<<<<<<< HEAD
project(tlsfp LANGUAGES CXX)

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Dependencies
find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
=======

project(tlsfp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()


# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

find_path(PCAP_INCLUDE_DIR pcap.h)

find_library(
    PCAP_LIBRARY
    NAMES pcap wpcap
)

>>>>>>> 7cb597c (Satyakam: Some CTests have been added)
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

<<<<<<< HEAD
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Executable Target
add_executable(tlsfp_engine
    src/main.cpp
=======

# ------------------------------------------------------------------------------
# Static Library Target
# ------------------------------------------------------------------------------

add_library(tlsfp_lib STATIC
>>>>>>> 7cb597c (Satyakam: Some CTests have been added)
    src/capture.cpp
    src/db.cpp
    src/parser.cpp
    src/ja3.cpp
    src/ja4.cpp
    src/db.cpp
)

<<<<<<< HEAD
target_compile_features(tlsfp_engine PRIVATE cxx_std_17)

# Compiler Warnings and Strict Dialect Enforcement
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tlsfp_engine PRIVATE
=======
target_include_directories(tlsfp_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
)

target_link_libraries(tlsfp_lib
    PUBLIC
        ${PCAP_LIBRARY}
        OpenSSL::Crypto
)


# ------------------------------------------------------------------------------
# Cross-Platform Compiler Flags
# ------------------------------------------------------------------------------

if(MSVC)

    target_compile_options(tlsfp_lib PRIVATE
        /W4
        /permissive-
    )

elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")

    target_compile_options(tlsfp_lib PRIVATE
>>>>>>> 7cb597c (Satyakam: Some CTests have been added)
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
<<<<<<< HEAD
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        $<$<CONFIG:Debug>:-O0 -g3 -fsanitize=address,undefined>
    )
    target_link_options(tlsfp_engine PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
=======

        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>

        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
>>>>>>> 7cb597c (Satyakam: Some CTests have been added)
    )

endif()

<<<<<<< HEAD
target_include_directories(tlsfp_engine PRIVATE
    include
)

target_link_libraries(tlsfp_engine PRIVATE
    pcap::pcap
    OpenSSL::Crypto
    Threads::Threads
)

=======

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
>>>>>>> 7cb597c (Satyakam: Some CTests have been added)
