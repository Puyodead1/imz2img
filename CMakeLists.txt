cmake_minimum_required(VERSION 3.16)

project(dfsee_imz2img VERSION 1.0.0 LANGUAGES CXX)

add_executable(imz2img imz2img.cpp)
target_compile_features(imz2img PRIVATE cxx_std_17)
set_target_properties(imz2img PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_STANDARD_REQUIRED ON
)

if(MSVC)
    target_compile_options(imz2img PRIVATE /W4 /permissive-)
else()
    target_compile_options(imz2img PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS imz2img RUNTIME DESTINATION bin)
