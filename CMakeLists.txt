# CMakeList.txt : CMake project for SpoolSvHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("SpoolSvHook")
add_compile_definitions(SPDLOG_WCHAR_TO_UTF8_SUPPORT)
set(SPDLOG_WCHAR_TO_UTF8_SUPPORT ON)
# Add MinHook as a subdirectory
add_subdirectory(Libs/minhook)
add_subdirectory(Libs/spdlog)
add_subdirectory(ALPCInjector)
add_subdirectory(SpoolerStub)
#

#

# TODO: Add tests and install targets if needed.