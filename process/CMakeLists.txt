cmake_minimum_required(VERSION 3.16)
project(process C)

set(CMAKE_C_STANDARD 99)

add_executable(process main.c
        identify_listening_process_details.c
        identify_listening_process_details.h)
