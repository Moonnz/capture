cmake_minimum_required(VERSION 3.10)
project(capture)

set(CMAKE_CXX_STANDARD 11)
add_compile_options(-fpermissive)
include(FindPCAP.cmake)

add_executable(capture main.cpp)
target_link_libraries(capture ${PCAP_LIBRARY})