cmake_minimum_required(VERSION 3.14)
project(tlsfp LANGUAGES CXX)

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Dependencies
find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap development files not found. Run: sudo apt install libpcap-dev")
endif()

add_library(pcap::pcap UNKNOWN IMPORTED)
set_target_properties(pcap::pcap PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Executable Target
add_executable(tlsfp_engine
    src/main.cpp
    src/capture.cpp
    src/parser.cpp
    src/ja3.cpp
    src/ja4.cpp
)

target_compile_features(tlsfp_engine PRIVATE cxx_std_17)

# Compiler Warnings and Strict Dialect Enforcement
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tlsfp_engine PRIVATE
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
        $<$<CONFIG:Debug>:-O0 -g3 -fsanitize=address,undefined>
    )
    target_link_options(tlsfp_engine PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
endif()

target_include_directories(tlsfp_engine PRIVATE
    include
)

target_link_libraries(tlsfp_engine PRIVATE
    pcap::pcap
    OpenSSL::Crypto
    Threads::Threads
)