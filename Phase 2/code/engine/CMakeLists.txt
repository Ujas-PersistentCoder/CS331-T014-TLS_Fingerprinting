cmake_minimum_required(VERSION 3.14)

project(tlsfp_engine_phase2 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose build type" FORCE)
endif()

# macOS dynamic linker (dyld) RPATH configuration
if(APPLE)
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    list(APPEND CMAKE_BUILD_RPATH "/opt/homebrew/lib" "/usr/local/lib")
endif()

# 1. OS-Agnostic Packet Capture Dependency
find_path(PCAP_INCLUDE_DIR NAMES pcap.h PATH_SUFFIXES pcap include)
find_library(PCAP_LIBRARY NAMES pcap wpcap Packet)

if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "libpcap / Npcap development files (pcap.h, libpcap.so/dylib/a or wpcap.lib) not found.")
endif()

add_library(pcap::pcap UNKNOWN IMPORTED)
set_target_properties(pcap::pcap PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
)

# 2. Cryptographic and Socket Dependencies
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 3. Static Library Target
add_library(tlsfp_phase2_lib STATIC
    src/accumulator.cpp
    src/capture.cpp
    src/parser.cpp
    src/ech_parser.cpp
    src/ech_analysis.cpp
    src/ja3.cpp
    src/ja4.cpp
    src/ja4t.cpp
    src/db.cpp
    src/pqtls_parser.cpp
    src/pqtls_analysis.cpp
)

target_include_directories(tlsfp_phase2_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(tlsfp_phase2_lib
    PUBLIC
        pcap::pcap
        OpenSSL::Crypto
        Threads::Threads
)

# Link Windows Socket API library when compiling on Windows
if(WIN32)
    target_link_libraries(tlsfp_phase2_lib PUBLIC ws2_32)
endif()

# 4. OS-Agnostic Compiler Flags
if(MSVC)
    target_compile_options(tlsfp_phase2_lib PRIVATE /W4 /O2)
else()
    target_compile_options(tlsfp_phase2_lib PRIVATE
        -Wall -Wextra -Wpedantic
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Debug>:-g3>
    )
    target_compile_options(tlsfp_phase2_lib PUBLIC
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
    # Static libraries do not link; propagate sanitizer runtime flags to consumers.
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

# 1. JA4T standalone test runner
add_executable(tlsfp_phase2_tests
    tests/test_ja4t.cpp
)
target_link_libraries(tlsfp_phase2_tests
    PRIVATE
        tlsfp_phase2_lib
)
add_test(NAME ja4t COMMAND tlsfp_phase2_tests)

# 2. GoogleTest-based unit tests
# Always build GoogleTest from source via FetchContent as static libraries.
# This eliminates macOS dyld @rpath errors, Conda/Homebrew shared dylib conflicts,
# and SIP stripping DYLD_LIBRARY_PATH during test execution.
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# GoogleTest must use the same container annotations and sanitizer runtime as
# its consumers; prebuilt Homebrew libraries are not compatible with ASan here.
if(NOT MSVC)
    add_compile_options($<$<CONFIG:Debug>:-fsanitize=address,undefined>)
    add_link_options($<$<CONFIG:Debug>:-fsanitize=address,undefined>)
endif()
FetchContent_MakeAvailable(googletest)

if(NOT TARGET GTest::gtest)
    add_library(GTest::gtest ALIAS gtest)
endif()
if(NOT TARGET GTest::gtest_main)
    add_library(GTest::gtest_main ALIAS gtest_main)
endif()

add_executable(unit_tests
    tests/test_fingerprints.cpp
    tests/test_ech_parser.cpp
    tests/test_ech_analysis.cpp
    tests/test_ech_connections.cpp
    tests/test_pqtls_parser.cpp
    tests/test_pqtls_analysis.cpp
)

target_compile_definitions(unit_tests PRIVATE
    TLSFP_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures"
)
target_link_libraries(unit_tests
    PRIVATE
        tlsfp_phase2_lib
        GTest::gtest
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(unit_tests
    DISCOVERY_MODE PRE_TEST
)
