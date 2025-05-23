cmake_minimum_required(VERSION 3.13)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

# Create executable
add_executable(parse_trace parse_trace.cpp)

# add `include` directory to the include path
target_include_directories(parse_trace PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../backend/include)

# Install target
install(TARGETS parse_trace
        DESTINATION $ENV{HOME}/.local/dynamorio/tools)
