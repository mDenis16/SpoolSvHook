# CMakeList.txt : CMake project for SpoolSvHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)


project ("Internal")

set(SPDLOG_WCHAR_TO_UTF8_SUPPORT ON)
add_compile_definitions(SPDLOG_WCHAR_TO_UTF8_SUPPORT)
add_compile_definitions(_SILENCE_ALL_MS_EXT_DEPRECATION_WARNINGS)
# Add the source files
set(SOURCES
    Hooking/HookFunction.cpp
    Hooking/Hooking.cpp
    Hooking/Hooking.Patterns.cpp
    Hooking/IATHook.cpp

    marshaling.cpp
    CSpoolSVHooks.cpp
    CHooks.cpp
    CBootstrap.cpp

    dllmain.cpp
    # Add other source files if needed
)


add_library(Internal SHARED ${SOURCES})



if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Internal PROPERTY CXX_STANDARD 20)
endif()


# link libraries
target_link_libraries(Internal minhook spdlog)


get_filename_component(PARENT_DIR ../ ABSOLUTE)
message(${PARENT_DIR})
add_custom_command(TARGET Internal POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:Internal> ${PARENT_DIR}/build/stub.dll
    COMMENT "Created ${PARENT_DIR}/build/stub.dll"
)

# TODO: Add tests and install targets if needed.
