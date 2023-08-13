cmake_minimum_required(VERSION 3.10)

project(ADBProtocol LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

include_directories(
    modules
    includes
    third_party
    third_party/yasio
)

# Scan common sources
aux_source_directory(src/common COMMON_SOURCES)

# Build core program
add_executable(main src/core/main.cc ${COMMON_SOURCES})