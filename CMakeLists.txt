cmake_minimum_required(VERSION 3.7)
project(project_by_sniffer)

set(CMAKE_CXX_STANDARD 11)


include(FindPCAP.cmake)

set(SOURCE_FILES README.md main.cpp)

add_executable(project_by_sniffer ${SOURCE_FILES})

target_link_libraries(project_by_sniffer ${PCAP_LIBRARY})