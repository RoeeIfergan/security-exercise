cmake_minimum_required(VERSION 4.0)
project(web_server C)

set(CMAKE_C_STANDARD 99)

add_executable(web_server main.c)
target_link_options(web_server PRIVATE -Wl,--no-as-needed)
target_link_libraries(web_server PRIVATE dl)
