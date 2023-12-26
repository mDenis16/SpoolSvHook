cmake_minimum_required(VERSION 3.8)
# Get proto files
get_filename_component(PROTO_PATH_DIR "../../AnyPrint_Proto" ABSOLUTE)
get_filename_component(hw_proto "../../AnyPrint_Proto/spool.proto" ABSOLUTE)
message(${PROTO_PATH_DIR})


get_filename_component(hw_proto_path "${hw_proto}" PATH)


set(hw_proto_srcs "${PROTO_PATH_DIR}/spool.pb.cc")
set(hw_proto_hdrs "${PROTO_PATH_DIR}/spool.pb.h")
set(hw_grpc_srcs "${PROTO_PATH_DIR}/spool.grpc.pb.cc")
set(hw_grpc_hdrs "${PROTO_PATH_DIR}/spool.grpc.pb.h")
add_custom_command(
      OUTPUT "${hw_proto_srcs}" "${hw_proto_hdrs}" "${hw_grpc_srcs}" "${hw_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${PROTO_PATH_DIR}"
        --cpp_out "${PROTO_PATH_DIR}"
        -I "${hw_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hw_proto}"
      DEPENDS "${hw_proto}")

# Include generated *.pb.h files
include_directories("${PROTO_PATH_DIR}")

# hw_grpc_proto
add_library(hw_grpc_proto
  ${hw_grpc_srcs}
  ${hw_grpc_hdrs}
  ${hw_proto_srcs}
  ${hw_proto_hdrs})
target_link_libraries(hw_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

# Targets greeter_[async_](client|server)
