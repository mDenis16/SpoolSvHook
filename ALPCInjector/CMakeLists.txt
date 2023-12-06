# CMakeList.txt : CMake project for SpoolSvHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("ALPCInjector")
add_library(ntdll STATIC IMPORTED GLOBAL)

include_directories("../RE_ntlib")
add_executable(ALPCInjector main.cpp ALPCInjector.cpp)

set_target_properties(ALPCInjector PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
        IMPORTED_LOCATION_DEBUG "./RE_ntlib/x64/ntdll.lib")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ALPCInjector PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
