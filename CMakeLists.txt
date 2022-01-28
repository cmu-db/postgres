cmake_minimum_required(VERSION 3.16)

project(
        NoisePage
        VERSION 0.1.0.0
        DESCRIPTION "NoisePage project."
        HOMEPAGE_URL "https://noise.page/"
        LANGUAGES CXX
)

add_subdirectory(cmudb)

add_custom_target(
        pg_clean
        COMMAND env --ignore-environment PATH='$(PATH)' LANG='$(LANG)' make -j clean
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
)

add_custom_target(
        pg_build
        COMMAND env --ignore-environment PATH='$(PATH)' LANG='$(LANG)' make -j install-world-bin
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
)

add_custom_target(
        pg_test_core
        COMMAND env --ignore-environment PATH='$(PATH)' LANG='$(LANG)' make -j check
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
)

add_custom_target(
        pg_test_all
        COMMAND env --ignore-environment PATH='$(PATH)' LANG='$(LANG)' make -j check-world
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
)

message(STATUS "[ADDED] PostgreSQL Makefile wrapper (prefix: pg_).")