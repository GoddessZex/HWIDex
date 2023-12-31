# basic info
cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
project(
    HWIDex
    DESCRIPTION "HWID hash generation library"
    LANGUAGES CXX
)


# compiler flags
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    set(CMAKE_CXX_FLAGS "/W4 /std:c++20 /EHsc")
else()
    set(CMAKE_CXX_FLAGS "-Wextra -Wall -Wextra -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion")
endif()


# fetch and set build type
set(available_build_types Debug Release)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build (Debug or Release)" FORCE)
endif()
if(NOT CMAKE_BUILD_TYPE IN_LIST available_build_types)
    MESSAGE(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}. Allowed values: ${available_build_types}")
endif()


# general variables
set(PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(BUILD_DIR "${PROJECT_DIR}/build")
set(TARGET "hwidex")


# debug/release CXX flag options
if (NOT MSVC)
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        MESSAGE(STATUS "Build set to debug mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DDEBUG -O0 -fsanitize=address")
    elseif(CMAKE_BUILD_TYPE MATCHES "Release")
        MESSAGE(STATUS "Build set to release mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g0")
        if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mtune=native")
        elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=native")
        endif()
    endif()
endif()


# add executable
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
add_executable(${TARGET} "src/test.cpp")
set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD 20)
set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD_REQUIRED ON)
#add_test(Test_1, "${CMAKE_SOURCE_DIR}/bin/${TARGET}")