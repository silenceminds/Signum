cmake_minimum_required(VERSION 3.16)
project(signum_agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(signum-agent
    src/agent.c
    src/smpv2.c
    src/tls_client.c
    src/platform.c
    src/ring_buffer.c
)

target_include_directories(signum-agent PRIVATE include)
target_link_libraries(signum-agent PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

add_executable(signum-ctl
    src/ctl.c
    src/platform.c
)

target_include_directories(signum-ctl PRIVATE include)
target_link_libraries(signum-ctl PRIVATE Threads::Threads)

if(WIN32)
    target_link_libraries(signum-agent PRIVATE ws2_32 crypt32)
    target_link_libraries(signum-ctl PRIVATE ws2_32)
    target_compile_definitions(signum-agent PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN)
    target_compile_definitions(signum-ctl PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(signum-agent PRIVATE -Wall -Wextra)
    target_compile_options(signum-ctl PRIVATE -Wall -Wextra)
endif()
