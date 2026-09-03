cmake_minimum_required(VERSION 3.10)
project(imz2raw C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(imz2raw imz2raw.c)

if(MSVC)
    target_compile_options(imz2raw PRIVATE /W4)
else()
    target_compile_options(imz2raw PRIVATE -Wall -Wextra)
endif()

install(TARGETS imz2raw RUNTIME DESTINATION bin)
