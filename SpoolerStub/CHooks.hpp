#pragma once
class CSpoolSVHooks;

class CHooks
{
public:
    CHooks();
    ~CHooks();
public:
    void HookAll();
private:
    std::unique_ptr<CSpoolSVHooks> m_SpoolSVHooks;
};