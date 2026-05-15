function(traykeeper_generate_rpc target_name stub_kind out_include_dir out_stub_source)
    file(GLOB windows_sdk_midl_candidates
        "$ENV{ProgramFiles\(x86\)}/Windows Kits/10/bin/*/x64/midl.exe"
        "$ENV{ProgramFiles}/Windows Kits/10/bin/*/x64/midl.exe"
    )
    list(SORT windows_sdk_midl_candidates COMPARE NATURAL ORDER DESCENDING)

    find_program(MIDL_EXECUTABLE NAMES midl midl.exe)

    if (NOT MIDL_EXECUTABLE AND windows_sdk_midl_candidates)
        list(GET windows_sdk_midl_candidates 0 MIDL_EXECUTABLE)
    endif()

    if (NOT MIDL_EXECUTABLE)
        message(FATAL_ERROR "Could not find midl.exe. Install the Windows SDK or run CMake from a Visual Studio developer environment.")
    endif()

    cmake_path(GET CMAKE_CURRENT_FUNCTION_LIST_DIR PARENT_PATH repo_root)
    set(idl_file "${repo_root}/common/rpc/TrayKeeperControl.idl")
    set(gen_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/${target_name}/rpc")
    set(header "${gen_dir}/TrayKeeperControl.h")
    set(client_stub "${gen_dir}/TrayKeeperControl_c.c")
    set(server_stub "${gen_dir}/TrayKeeperControl_s.c")

    add_custom_command(
        OUTPUT "${header}" "${client_stub}" "${server_stub}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${gen_dir}"
        COMMAND "${MIDL_EXECUTABLE}" /nologo /env x64 /char signed /app_config /out "${gen_dir}" "${idl_file}"
        DEPENDS "${idl_file}"
        VERBATIM
    )

    if (stub_kind STREQUAL "client")
        set(selected_stub "${client_stub}")
    elseif (stub_kind STREQUAL "server")
        set(selected_stub "${server_stub}")
    else()
        message(FATAL_ERROR "Unknown RPC stub kind: ${stub_kind}")
    endif()

    set_source_files_properties("${selected_stub}" PROPERTIES GENERATED TRUE LANGUAGE C)

    set(${out_include_dir} "${gen_dir}" PARENT_SCOPE)
    set(${out_stub_source} "${selected_stub}" PARENT_SCOPE)
endfunction()
