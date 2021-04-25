cmake_minimum_required(VERSION 3.16)
project(Linux_2021Spring C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(
        SOURCES
        ${CMAKE_SOURCE_DIR}/src/fs.c
        ${CMAKE_SOURCE_DIR}/src/net_front.c
        ${CMAKE_SOURCE_DIR}/src/net_back.c
        ${CMAKE_SOURCE_DIR}/src/util.c
        ${CMAKE_SOURCE_DIR}/src/net_common.c
)

add_executable(front ${CMAKE_SOURCE_DIR}/src/main_front.c ${SOURCES})


add_executable(fs_daemon ${CMAKE_SOURCE_DIR}/src/main_daemon.c ${SOURCES})
target_link_libraries(fs_daemon PRIVATE Threads::Threads)
target_link_libraries(front PRIVATE Threads::Threads)
