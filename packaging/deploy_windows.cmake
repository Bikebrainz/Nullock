# Run after windeployqt. Qt's tool does not deploy nghttp2 or the OpenSSL CLI.
set(CMAKE_GET_RUNTIME_DEPENDENCIES_PLATFORM windows+pe)
set(CMAKE_GET_RUNTIME_DEPENDENCIES_TOOL dumpbin)
set(CMAKE_GET_RUNTIME_DEPENDENCIES_COMMAND "${DUMPBIN}")
file(COPY "${OPENSSL_EXE}" DESTINATION "${DEST}")
file(GET_RUNTIME_DEPENDENCIES
    EXECUTABLES "${APP_EXE}" "${OPENSSL_EXE}"
    DIRECTORIES "${QT_BIN}" "${NGHTTP2_BIN}" "${OPENSSL_BIN}" "${OPENSSL_ROOT}/bin"
    RESOLVED_DEPENDENCIES_VAR resolved
    UNRESOLVED_DEPENDENCIES_VAR unresolved
    PRE_EXCLUDE_REGEXES "api-ms-.*" "ext-ms-.*"
    # Match a complete directory, not vcpkg's "x64-windows" triplet directory.
    POST_EXCLUDE_REGEXES ".*[/\\][Ww][Ii][Nn][Dd][Oo][Ww][Ss][/\\].*")
if(unresolved)
    message(FATAL_ERROR "Missing Windows runtime dependencies: ${unresolved}")
endif()
foreach(dll IN LISTS resolved)
    get_filename_component(source_dir "${dll}" DIRECTORY)
    if(NOT source_dir STREQUAL DEST)
        file(COPY "${dll}" DESTINATION "${DEST}")
    endif()
endforeach()
