cmake_minimum_required(VERSION 3.14)
project(tlsfp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

find_package(PkgConfig REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Run: sudo apt-get install libpcap-dev")
endif()

add_executable(tlsfp_engine
    src/main.cpp
    src/capture.cpp
)

target_link_libraries(tlsfp_engine PRIVATE ${PCAP_LIBRARY})