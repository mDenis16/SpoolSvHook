# CMakeList.txt : CMake project for SpoolSvHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()
if(MSVC)
    # Disable specific warnings
    add_compile_options(/wd4996)  # Example: Disable warning C4996

    # Or, to disable all warnings
    # add_compile_options(/w)
endif()
project ("ALPCInjector")

add_library(ntdll STATIC IMPORTED GLOBAL)



include_directories("../RE_ntlib")
add_executable(ALPCInjector main.cpp ALPCInjector.cpp)

set_target_properties(ALPCInjector PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
        IMPORTED_LOCATION_DEBUG "./RE_ntlib/x64/ntdll.lib")


set_property(TARGET ALPCInjector PROPERTY CXX_STANDARD 20)


target_link_libraries(ALPCInjector PRIVATE spdlog::spdlog absl::strings)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
message(${PARENT_DIR})
add_custom_command(TARGET ALPCInjector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ALPCInjector> ${PARENT_DIR}/build/alpc_injector.exe
    COMMENT "Created ${PARENT_DIR}/build/alpc_injector.exe"
)

# TODO: Add tests and install targets if needed.
