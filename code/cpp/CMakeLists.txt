cmake_minimum_required(VERSION 3.14)
project(tlsfp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Locate libpcap
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap development files not found. Run: sudo apt install libpcap-dev")
endif()

# Locate OpenSSL (libcrypto)
find_package(OpenSSL REQUIRED)

# 1. Define the executable target FIRST
add_executable(tlsfp_engine
    src/main.cpp
    src/capture.cpp
    src/parser.cpp
    src/ja3.cpp
    src/ja4.cpp
)

# 2. Attach compiler options to the defined target
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tlsfp_engine PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
    )
endif()

# 3. Attach include search paths
target_include_directories(tlsfp_engine PRIVATE
    include
    ${PCAP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# 4. Link external libraries
target_link_libraries(tlsfp_engine PRIVATE
    ${PCAP_LIBRARY}
    OpenSSL::Crypto
)