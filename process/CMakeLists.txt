cmake_minimum_required(VERSION 3.16)
project(process C)

set(CMAKE_C_STANDARD 99)

add_executable(process main.c
        utils/identify_listening_process_details.c
        utils/identify_listening_process_details.h
        injection/injector.c
        injection/injector.h
        injection/utils/got_injection.c
        injection/utils/got_injection.h
        utils/envs.h
        utils/helpers.c
        utils/helpers.h
        utils/unix_socket.c
        utils/unix_socket.h
        connection_management.c
        connection_management.h
)

target_compile_options(process PRIVATE -Wall -Wextra)

add_library(payload SHARED
        injection/inject_payload.c
        injection/utils/got_injection.c
        injection/utils/got_injection.h
        utils/envs.h
        utils/helpers.c
        utils/helpers.h
        utils/unix_socket.c
        utils/unix_socket.h
        injection/utils/hooks/hooked_accept.c
        injection/utils/hooks/hooked_accept.h
        injection/utils/hooks/hook_global_state.h
        injection/utils/hooks/hook_read.c
        injection/utils/hooks/hook_read.h
        injection/utils/hooks/hook_global_state.c
        injection/utils/connection_storage.c
        injection/utils/connection_storage.h
)
set_target_properties(payload PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "/tmp"
        OUTPUT_NAME "inject"
        PREFIX ""
)
target_link_libraries(payload PRIVATE dl)
