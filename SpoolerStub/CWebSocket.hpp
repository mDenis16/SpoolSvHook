
#define ASIO_STANDALONE
#define _WEBSOCKETPP_CPP11_INTERNAL_

#include <websocketpp/config/asio_no_tls.hpp>

#include <websocketpp/server.hpp>

#include <iostream>
#include <set>

#include <websocketpp/common/thread.hpp>

typedef websocketpp::server<websocketpp::config::asio> server;

using websocketpp::connection_hdl;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

using websocketpp::lib::thread;
using websocketpp::lib::mutex;
using websocketpp::lib::lock_guard;
using websocketpp::lib::unique_lock;
using websocketpp::lib::condition_variable;

class CWebSocket {
public:
    CWebSocket();

    void Run(uint16_t port);

    void OnOpen(connection_hdl hdl);

    void OnClose(connection_hdl hdl);

    void OnMessage(connection_hdl hdl,  server::message_ptr msg);

    void ProcessMessages() ;
private:
    typedef std::set<connection_hdl,std::owner_less<connection_hdl> > con_list;

    server mServer;
    con_list mConnections;
   
    mutex mActionLock;
    mutex mConnectionsLock;
    condition_variable mActionsCond;
};
