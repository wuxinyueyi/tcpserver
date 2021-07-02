cmake_minimum_required(VERSION 3.0.0)
project(tcpserver VERSION 0.1.0)


string(TIMESTAMP COMPILE_TIME %Y%m%d_%H%M%S)
set(BUILD_TIME ${COMPILE_TIME})
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_SOURCE_DIR}/src/version.h")

set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Werror -ggdb3 -fno-stack-protector -pthread"
)

add_executable(tcpserver ${PROJECT_SOURCE_DIR}/src/tcp_server.cpp)

target_include_directories(tcpserver PUBLIC ${PROJECT_SOURCE_DIR}/../stdx/include)

target_link_libraries(tcpserver ${PROJECT_SOURCE_DIR}/../stdx/build/libstdx.a)
target_link_libraries(tcpserver -static-libgcc -static-libstdc++)


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED true)


add_executable(stress_client ${PROJECT_SOURCE_DIR}/src/stress_client.cpp)
target_include_directories(stress_client PUBLIC ${PROJECT_SOURCE_DIR}/../stdx/include)

target_link_libraries(stress_client ${PROJECT_SOURCE_DIR}/../stdx/build/libstdx.a)
target_link_libraries(stress_client -static-libgcc -static-libstdc++)

#message("CMAKE_CXX_FLAGS:" ${CMAKE_CXX_FLAGS})
#message("BUILD_TIME:" ${BUILD_TIME})