# cmake version
cmake_minimum_required(VERSION 3.5)

# project name
project(cryptocpp C CXX)

# source file
aux_source_directory(src SRC)

# shared library
add_library(${CMAKE_PROJECT_NAME} SHARED ${SRC})

# compile options
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -std=c++11 -fsanitize=address -Wall)

# include test
