#include "CPortMon.hpp"
#include <spdlog/spdlog.h>


 void CPortMon::Start(int port)
{
    m_port = port;
    io_ctx = std::make_unique<asio::io_context>(1);

    signals = std::make_unique<asio::signal_set>(*(io_ctx.get()), SIGINT, SIGTERM);

    signals->async_wait([&](auto, auto)
                       { io_ctx->stop(); });

     asio::co_spawn(*(io_ctx.get()), Listener(), detached);

    
    thread = std::thread([&]() {
        io_ctx->run();
    });
    spdlog::info("started ioctx thread");
    thread.detach();
}

awaitable<void> CPortMon::Echo(tcp_socket socket)
{
    try
    {
        char data[1024];
        for (;;)
        {
            std::size_t n = co_await socket.async_read_some(asio::buffer(data));
            spdlog::info("got data {}", n);
     //      co_await async_write(socket, asio::buffer(data, n));
        }
    }
    catch (std::exception &e)
    {
        std::printf("echo Exception: %s\n", e.what());
    }
}
awaitable<void> CPortMon::Listener()
{
    spdlog::info("Listening CPortMon!" );
    auto executor = co_await this_coro::executor;
    tcp_acceptor acceptor(executor, {tcp::v4(), ( asio::ip::port_type)m_port});
    for (;;)
    {
        auto socket = co_await acceptor.async_accept();
        spdlog::info("new client connected");
         asio::co_spawn(executor, Echo(std::move(socket)), detached);
    }
   
}