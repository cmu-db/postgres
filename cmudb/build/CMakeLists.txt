add_custom_target(
        configure_debug
        COMMAND ./cmudb/build/configure.sh debug
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
)

add_custom_target(
        configure_release
        COMMAND ./cmudb/build/configure.sh release
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
)

message(STATUS "[ADDED] build components (prefix: configure_).")