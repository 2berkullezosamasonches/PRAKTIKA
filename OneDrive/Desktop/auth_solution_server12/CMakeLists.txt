cmake_minimum_required(VERSION 3.21)

if (POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

project(TrayKeeperSuite LANGUAGES C CXX RC)

# The installer ships self-contained native executables. On MSVC builds this
# links the C/C++ runtime statically, so no separate VC++ redistributable is
# required at runtime.
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_subdirectory(tray_app)
add_subdirectory(service)
