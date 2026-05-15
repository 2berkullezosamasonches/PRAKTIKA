cmake_minimum_required(VERSION 3.21)

project(TrayKeeper LANGUAGES C CXX RC)

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/TrayKeeperRpc.cmake")

traykeeper_generate_rpc(TrayKeeper client RPC_INCLUDE_DIR RPC_CLIENT_STUB)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TrayKeeper WIN32
    src/main.cpp
    src/app.rc
    "${RPC_CLIENT_STUB}"
)

target_include_directories(TrayKeeper PRIVATE "${RPC_INCLUDE_DIR}")
target_compile_definitions(TrayKeeper PRIVATE UNICODE _UNICODE)

target_link_libraries(TrayKeeper PRIVATE user32 shell32 gdi32 advapi32 rpcrt4 comdlg32 ole32)

set_target_properties(TrayKeeper PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if (MSVC)
    target_compile_options(TrayKeeper PRIVATE /W4 /permissive- /utf-8 /wd4828)
    set_source_files_properties("${RPC_CLIENT_STUB}" PROPERTIES COMPILE_OPTIONS "/wd4828")
endif()
