cmake_minimum_required(VERSION 3.12)
project(cosc340ass4 C)

set(CMAKE_C_STANDARD 99)
set(SOURCE_FILES
        client.c
        server.c)
include_directories(.)

link_libraries(ssl)
link_libraries(crypto)
add_executable(server server.c )

add_executable(client client.c )