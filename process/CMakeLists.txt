cmake_minimum_required(VERSION 3.16)
project(process C)

set(CMAKE_C_STANDARD 99)

add_executable(process main.c
        identify_listening_process_details.c
        identify_listening_process_details.h
        injector.c
        injector.h
        inject_payload.c
        )

target_compile_options(process PRIVATE -Wall -Wextra)
target_link_libraries(process PRIVATE dl)
