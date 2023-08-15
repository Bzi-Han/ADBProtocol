cmake_minimum_required(VERSION 3.21)

project(ADBProtocol LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -utf-8")
endif()

add_definitions(-DYASIO_HEADER_ONLY -DNOMINMAX)

include_directories(
    modules
    includes
    third_party
    third_party/yasio
    third_party/boringssl/include
)

# Scan common sources
aux_source_directory(src/common COMMON_SOURCES)

# Build boringssl
add_subdirectory(third_party/boringssl)

# Addtional libs
set(ADDTIONAL_LIBS "")
if (CMAKE_SYSTEM_NAME MATCHES "Android")
    find_library(liblog log NO_CACHE)
    set(ADDTIONAL_LIBS "${liblog}")
endif()

# Build core program
add_executable(main src/core/main.cc ${COMMON_SOURCES})
target_link_libraries(main ssl ${ADDTIONAL_LIBS})
if (CMAKE_SYSTEM_NAME MATCHES "Android")
set_target_properties(main PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "tests/${ANDROID_ABI}"
)
endif()

# Build static library
add_library(${PROJECT_NAME} STATIC ${COMMON_SOURCES})
target_link_libraries(${PROJECT_NAME} ssl ${ADDTIONAL_LIBS})
if (CMAKE_SYSTEM_NAME MATCHES "Android")
set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "libs/${ANDROID_ABI}"
)
endif()

# Build test program
add_executable(test src/test/main.cc)
target_link_libraries(test ${PROJECT_NAME})
if (CMAKE_SYSTEM_NAME MATCHES "Android")
set_target_properties(test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "tests/${ANDROID_ABI}"
)
endif()
