
#pragma once

class CHooks;
class CWebSocket;
class CPortMon;
class CSpoolClient;

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
    std::unique_ptr<CWebSocket> &WebSocket()
    {
        return m_WebSocket;
    }
    std::unique_ptr<CSpoolClient> &SpoolClient()
    {
        return m_SpoolClient;
    }

private:
    std::unique_ptr<CHooks> m_Hooks;
    std::unique_ptr<CWebSocket> m_WebSocket;
    std::unique_ptr<CPortMon> m_PortMonitor;
    std::unique_ptr<CSpoolClient> m_SpoolClient;
};