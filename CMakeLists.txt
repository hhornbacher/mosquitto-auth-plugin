cmake_minimum_required(VERSION 3.3)

# Project settings

project(mosquitto-auth)

set(LIB_NAME ${PROJECT_NAME})

# Enable C++17 standard

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra")

# Check dependencies

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)
find_package(Mosquitto REQUIRED)
include_directories(${MOSQUITTO_INCLUDE_DIR})
find_package(Scrypt REQUIRED)
include_directories(${SCRYPT_INCLUDE_DIR})



# Define include dircectories

include_directories(
    ${INCLUDE_PATH} 
    src
)

# Define library

file(GLOB_RECURSE SOURCES_LIB "src/*.cpp")

add_library(
    ${LIB_NAME} SHARED
    ${SOURCES_LIB}
)

target_link_libraries(
    ${LIB_NAME}
    ${SCRYPT_LIBRARY}
)