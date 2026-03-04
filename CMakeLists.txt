cmake_minimum_required(VERSION 3.16)
project(iot_quic_testbed C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_definitions(_DEFAULT_SOURCE _POSIX_C_SOURCE=200809L)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
include(FetchContent)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap headers/library not found. Install libpcap-dev.")
endif()

add_library(iot_quic_core
    src/alias.c
    src/traffic_profile.c
    src/quic_cid.c
    src/quic_secure_channel.c
    src/microburst_scheduler.c
)

add_library(pico_cid_secure
    src/pico_cid_secure.c
)

target_include_directories(iot_quic_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
)

target_include_directories(pico_cid_secure
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(iot_quic_core
    PUBLIC
        ${PCAP_LIBRARY}
        Threads::Threads
        OpenSSL::Crypto
)

target_link_libraries(pico_cid_secure
    PUBLIC
        OpenSSL::Crypto
)

target_compile_options(iot_quic_core PRIVATE -Wall -Wextra -Wpedantic)
target_compile_options(pico_cid_secure PRIVATE -Wall -Wextra -Wpedantic)

set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "" FORCE)
set(BUILD_DEMO OFF CACHE BOOL "" FORCE)
set(BUILD_HTTP OFF CACHE BOOL "" FORCE)
set(BUILD_PQBENCH OFF CACHE BOOL "" FORCE)
set(BUILD_LOGLIB OFF CACHE BOOL "" FORCE)
set(BUILD_LOGREADER OFF CACHE BOOL "" FORCE)
set(picoquic_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    picoquic
    GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
    GIT_TAG 07ef7cb3b1d28f841a140332cf9daa2fb0f3630d
)
FetchContent_MakeAvailable(picoquic)

add_executable(module_a_profiler tools/profile_sampler_main.c)
target_link_libraries(module_a_profiler PRIVATE iot_quic_core)

add_executable(module_b_replay tools/quic_replay.c)
target_link_libraries(module_b_replay PRIVATE iot_quic_core)

add_executable(module_c_scheduler tools/microburst_main.c)
target_link_libraries(module_c_scheduler PRIVATE iot_quic_core)

add_executable(quic_secure_server tools/quic_secure_server.c)
target_compile_definitions(quic_secure_server PRIVATE QSC_PROJECT_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(quic_secure_server
    PRIVATE
        iot_quic_core
        pico_cid_secure
        picoquic-core
)

add_executable(quic_secure_client tools/quic_secure_client.c)
target_compile_definitions(quic_secure_client PRIVATE QSC_PROJECT_ROOT="${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(quic_secure_client
    PRIVATE
        iot_quic_core
        pico_cid_secure
        picoquic-core
)
