cmake_minimum_required(VERSION 3.6)
project(DeviceUniqueId)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(DeviceUniqueId
    src/main.cpp
)
