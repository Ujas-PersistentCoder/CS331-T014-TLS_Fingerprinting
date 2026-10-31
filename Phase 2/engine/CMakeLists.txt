cmake_minimum_required(VERSION 3.14)

project(tlsfp_engine_phase2 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose build type" FORCE)
endif()

# Dependencies
find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap wpcap)

if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap development files (pcap.h, libpcap.so/a) not found.")
endif()

add_library(pcap::pcap UNKNOWN IMPORTED)
set_target_properties(pcap::pcap PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Static Library Target
add_library(tlsfp_phase2_lib STATIC
    src/accumulator.cpp
    src/capture.cpp
    src/parser.cpp
    src/ja3.cpp
    src/ja4.cpp
    src/ja4t.cpp
    src/db.cpp
)

target_include_directories(tlsfp_phase2_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
)

target_link_libraries(tlsfp_phase2_lib
    PUBLIC
        pcap::pcap
        OpenSSL::Crypto
        Threads::Threads
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tlsfp_phase2_lib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
    # PUBLIC: executables linking this static lib need the sanitizer runtimes too
    target_link_options(tlsfp_phase2_lib PUBLIC
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
endif()

# CLI Executable
add_executable(tlsfp_phase2
    src/main.cpp
)

target_link_libraries(tlsfp_phase2
    PRIVATE
        tlsfp_phase2_lib
)

# Unit tests (ctest)
enable_testing()
add_executable(tlsfp_phase2_tests
    tests/test_ja4t.cpp
)
target_link_libraries(tlsfp_phase2_tests
    PRIVATE
        tlsfp_phase2_lib
)
add_test(NAME ja4t COMMAND tlsfp_phase2_tests)
