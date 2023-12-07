
#pragma once

class CHooks;
class CBootstrap {
public:
    CBootstrap();
    ~CBootstrap();
    void Run();
private:
    std::unique_ptr<CHooks> m_Hooks;
};