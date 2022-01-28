add_subdirectory(build)

find_program(CLANG_FORMAT_BIN NAMES clang-format-10 clang-format)
if ("${CLANG_FORMAT_BIN}" STREQUAL "CLANG_FORMAT_BIN-NOTFOUND")
    message(STATUS "[MISSING] clang-format not found, no format and no check-format.")
else ()
    # The files to be formatted.
    # Note that you can't use regex, only basic (not extended!) globbing.
    file(GLOB_RECURSE FORMAT_FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/tscout/*.[ch]"
            "${CMAKE_SOURCE_DIR}/src/include/tscout/*.[ch]"
            )

    # Run clang-format and update files in place.
    add_custom_target(format
            ${CLANG_FORMAT_BIN}
            -i
            ${FORMAT_FILES}
            USES_TERMINAL
            )

    # Run clang-format and exit with a non-zero exit code if any files need to be reformatted.
    add_custom_target(format-check
            ${CLANG_FORMAT_BIN}
            --dry-run -Werror
            ${FORMAT_FILES}
            USES_TERMINAL
            )

    message(STATUS "[ADDED] clang-format and check-clang-format (${CLANG_FORMAT_BIN}).")
    unset(FORMAT_DIRS)
endif ()
unset(CLANG_FORMAT_BIN)
