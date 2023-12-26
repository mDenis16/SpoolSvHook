# CMakeList.txt : CMake project for SpoolSvHook, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("SpoolSvHook")
add_compile_definitions(SPDLOG_WCHAR_TO_UTF8_SUPPORT ASIO_STANDALONE ABSL_USES_STD_STRING_VIEW)
set(SPDLOG_WCHAR_TO_UTF8_SUPPORT ON)

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(CMAKE_CXX_STANDARD 14)

set(ABSL_ENABLE_INSTALL ON)
set(protobuf_BUILD_TESTS OFF)
set(ABSL_PROPAGATE_CXX_STD ON)
set(RPC_INSTALL ON)
set(protobuf_BUILD_TESTS OFF CACHE INTERNAL "")

set(GRPC_AS_SUBMODULE ON)


# Add MinHook as a subdirectory
add_subdirectory(Libs/minhook)
add_subdirectory(Libs/spdlog)
add_subdirectory(Libs/json)

add_subdirectory(Libs/grpc EXCLUDE_FROM_ALL)
message(STATUS "Using gRPC via add_subdirectory.")
set(_PROTOBUF_LIBPROTOBUF libprotobuf)
set(_REFLECTION grpc++_reflection)
set(_ORCA_SERVICE grpcpp_orca_service)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
set(_GRPC_GRPCPP grpc++)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)


add_subdirectory(ProtoArtefacts)
add_subdirectory(ALPCInjector)
add_subdirectory(SpoolerStub)




#

#

# TODO: Add tests and install targets if needed.