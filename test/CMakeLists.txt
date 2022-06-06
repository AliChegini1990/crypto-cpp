# project name
project(test CXX)

# source file
aux_source_directory(${CMAKE_SOURCE_DIR}/test SRCTEST)

# add exec
add_executable(${PROJECT_NAME} ${SRCTEST})

# compile options
target_compile_options(${PROJECT_NAME} PRIVATE -std=c++11 -Wall)

# add lib
target_link_libraries(${PROJECT_NAME} PRIVATE cryptocpp)

# include
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)


