cmake_minimum_required(VERSION 3.21)

project(TrayKeeper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TrayKeeper WIN32
    src/main.cpp
    src/app.rc
)

target_compile_definitions(TrayKeeper PRIVATE UNICODE _UNICODE)

target_link_libraries(TrayKeeper PRIVATE user32 shell32 gdi32 advapi32)

if (MSVC)
    target_compile_options(TrayKeeper PRIVATE /W4 /permissive- /utf-8)
endif()
