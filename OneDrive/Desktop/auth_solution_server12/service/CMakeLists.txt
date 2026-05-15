cmake_minimum_required(VERSION 3.21)

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/TrayKeeperRpc.cmake")

traykeeper_generate_rpc(TrayKeeperService server RPC_INCLUDE_DIR RPC_SERVER_STUB)

add_executable(TrayKeeperService
    src/main.cpp
    "${RPC_SERVER_STUB}"
)

target_compile_features(TrayKeeperService PRIVATE cxx_std_17)
target_include_directories(TrayKeeperService PRIVATE "${RPC_INCLUDE_DIR}")
target_compile_definitions(TrayKeeperService PRIVATE UNICODE _UNICODE)

target_link_libraries(TrayKeeperService PRIVATE
    advapi32
    rpcrt4
    userenv
    wtsapi32
    winhttp
)

set_target_properties(TrayKeeperService PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if (MSVC)
    target_compile_options(TrayKeeperService PRIVATE /W4 /permissive- /utf-8 /wd4828)
    set_source_files_properties("${RPC_SERVER_STUB}" PROPERTIES COMPILE_OPTIONS "/wd4828")
endif()

install(TARGETS TrayKeeperService RUNTIME DESTINATION .)
