cmake_minimum_required(VERSION 3.8)
project(sha_1)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp SHA1.cpp SHA1.h)
add_executable(sha_1 ${SOURCE_FILES})