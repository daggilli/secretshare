cmake_minimum_required(VERSION 3.17...4.1)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(SecretShare LANGUAGES CXX VERSION 0.0.1 DESCRIPTION "C++ class to perform secret sharing")

if(CMAKE_GENERATOR MATCHES "Ninja Multi-Config")
  set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)
  set(CMAKE_DEFAULT_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

option(ENABLE_ASAN "Enable AddressSanitizer in Debug" OFF)

# Suppress warnings about deprecated is_trivial_v in C++26
if(CMAKE_CXX_STANDARD GREATER_EQUAL 26)
    add_compile_options(-Wno-deprecated)
endif()

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(
  ${PROJECT_NAME}
  INTERFACE
  $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

add_subdirectory(commandline)
add_subdirectory(examples)
