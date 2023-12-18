#include "CWebSocket.hpp"
#include <spdlog/spdlog.h>

CWebSocket::CWebSocket()
{
    // Initialize Asio Transport
    mServer.init_asio();


     mServer.set_open_handler(bind(&CWebSocket::OnOpen, this, ::_1));
     mServer.set_close_handler(bind(&CWebSocket::OnClose, this, ::_1));
     mServer.set_message_handler(bind(&CWebSocket::OnMessage, this, ::_1, ::_2));
}
void CWebSocket::Run(uint16_t port)
{
    spdlog::info("Listening websocket on port {}", port);
    // listen on specified port
    mServer.listen(port);

    // Start the server accept loop
    mServer.start_accept();

    // Start the ASIO io_service run loop
    try
    {
        mServer.run();
    }
    catch (const std::exception &e)
    {
        spdlog::error(e.what());
    }
}

/*no need to use another queue for simpel processing actions like inserting a new connection*/
// locking and unlocking may consume more resources than actual execution
void CWebSocket::OnOpen(connection_hdl hdl)
{
    lock_guard<mutex> guard(mConnectionsLock);
    mConnections.insert(hdl);
    auto con =  mServer.get_con_from_hdl(hdl);
    spdlog::info("New connection from host: {}", con->get_host() );
}
void CWebSocket::OnClose(connection_hdl hdl)
{
    lock_guard<mutex> guard(mConnectionsLock);
   
    mConnections.erase(hdl);
}

void CWebSocket::OnMessage(connection_hdl hdl, server::message_ptr msg)
{
    // // queue message up for sending by processing thread
    // {
    //     lock_guard<mutex> guard(m_action_lock);
    //     // std::cout << "on_message" << std::endl;
    //     m_actions.push(action(MESSAGE, hdl, msg));
    // }
    // m_action_cond.notify_one();
}
void CWebSocket::ProcessMessages()
{
    // may process rpc requests here in future
    //  while (1)
    //  {
    //      std::unique_lock<mutex> lock(m_action_lock);

    //     while (m_actions.empty())
    //     {
    //         m_action_cond.wait(lock);
    //     }

    //     CAction a = m_actions.front();
    //     m_actions.pop();

    //     lock.unlock();

    //     if (a.mType == EActionType::SUBSCRIBE)
    //     {
    //         lock_guard<mutex> guard(m_connection_lock);
    //         m_connections.insert(a.hdl);
    //     }
    //     else if (a.mType == EActionType::UNSUBSCRIBE)
    //     {
    //         lock_guard<mutex> guard(m_connection_lock);
    //         m_connections.erase(a.hdl);
    //     }
    //     else if (a.mType == EActionType::MESSAGE)
    //     {
    //         std::lock_guard<mutex> guard(m_connection_lock);

    //         con_list::iterator it;
    //         for (it = m_connections.begin(); it != m_connections.end(); ++it)
    //         {
    //             m_server.send(*it, a.msg);
    //         }
    //     }
    //     else
    //     {
    //         // undefined.
    //     }
    // }
}
