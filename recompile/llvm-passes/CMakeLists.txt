cmake_minimum_required(VERSION 3.20)
project(re_bounds_pass LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
include(AddLLVM)

add_library(re_bounds_pass MODULE bounds_pass.cpp)
target_include_directories(re_bounds_pass PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(re_bounds_pass PRIVATE ${LLVM_DEFINITIONS})

