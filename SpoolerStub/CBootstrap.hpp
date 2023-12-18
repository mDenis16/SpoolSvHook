
#pragma once

class CHooks;
class CWebSocket;

class CBootstrap
{
public:
    CBootstrap();
    ~CBootstrap();
    void Run();

    static CBootstrap &Get()
    {
        static CBootstrap INSTANCE;
        return INSTANCE;
    }
     std::unique_ptr<CWebSocket>& WebSocket(){
        return m_WebSocket;
     }
private:
    std::unique_ptr<CHooks> m_Hooks;
    std::unique_ptr<CWebSocket> m_WebSocket;
};