# cmake version
cmake_minimum_required(VERSION 3.5)

# project name
project(cryptocpp C CXX)

# source file
aux_source_directory(src SRC)

# shared library
add_library(${CMAKE_PROJECT_NAME} SHARED ${SRC})

# compile options
target_compile_options(${PROJECT_NAME} PRIVATE -std=c++11 -Wall)

target_link_libraries(${PROJECT_NAME} PRIVATE -lcrypt)

# include test
add_subdirectory(test)
