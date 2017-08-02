cmake_minimum_required(VERSION 3.7)
project(project_by_sniffer)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        README.md main.cpp)

add_executable(project_by_sniffer ${SOURCE_FILES})