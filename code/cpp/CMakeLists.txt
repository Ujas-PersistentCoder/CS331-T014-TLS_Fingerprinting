cmake_minimum_required(VERSION 3.14)
project(tlsfp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Release build (-O3) if no build type is specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Strict compiler warnings & aggressive optimization flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        $<$<CONFIG:Release>:-O3 -march=native>
        $<$<CONFIG:Debug>:-g -O0>
    )
endif()

# Locate libpcap
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap development files not found. Run: sudo apt install libpcap-dev")
endif()

# Locate OpenSSL (libcrypto for EVP MD5 and SHA-256)
find_package(OpenSSL REQUIRED)

# Target executable definition
add_executable(tlsfp_engine
    src/main.cpp
    src/capture.cpp
    src/parser.cpp
    src/ja3.cpp
    src/ja4.cpp
)

# Target-specific include directories (No global directory leakage)
target_include_directories(tlsfp_engine PRIVATE
    include
    ${PCAP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Target linkage
target_link_libraries(tlsfp_engine PRIVATE
    ${PCAP_LIBRARY}
    OpenSSL::Crypto
)