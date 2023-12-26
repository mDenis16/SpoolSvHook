#include <memory>
#include "../../AnyPrint_Proto/spool.grpc.pb.h"

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;

class CSpoolClient
{
public:
    explicit CSpoolClient(std::shared_ptr<grpc::ChannelInterface> channel)
        : stub_(SpoolSvc::NewStub(channel)) {}
    std::unique_ptr<SpoolSvc::Stub> stub_;
};