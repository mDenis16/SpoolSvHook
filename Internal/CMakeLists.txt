# CMakeList.txt : CMake project for SpoolSvHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)


project ("Internal")

# Add the source files
set(SOURCES
    dllmain.cpp
    # Add other source files if needed
)


add_library(Internal SHARED ${SOURCES})

if(NOT TARGET spdlog)
    # Stand-alone build
    find_package(spdlog REQUIRED)
endif()


if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Internal PROPERTY CXX_STANDARD 20)
endif()


get_filename_component(PARENT_DIR ../ ABSOLUTE)
message(${PARENT_DIR})
add_custom_command(TARGET Internal POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:Internal> ${PARENT_DIR}/build/stub.dll
    COMMENT "Created ${PARENT_DIR}/build/stub.dll"
)

# TODO: Add tests and install targets if needed.
