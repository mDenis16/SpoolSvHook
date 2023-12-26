#include <iostream>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/signal_set.hpp>
#include <asio/write.hpp>

using asio::awaitable;
using asio::detached;
using asio::use_awaitable_t;
using asio::ip::tcp;
using tcp_acceptor = use_awaitable_t<>::as_default_on_t<tcp::acceptor>;
using tcp_socket = use_awaitable_t<>::as_default_on_t<tcp::socket>;
namespace this_coro = asio::this_coro;
#include <thread>

class CPortMon
{
public:
    void Start(int port);

private:
     asio::awaitable<void> Echo(tcp_socket socket);
     asio::awaitable<void> Listener();

private:
    std::unique_ptr<asio::io_context> io_ctx;
    std::unique_ptr<asio::signal_set> signals;
    std::thread thread;
    int m_port;
};
