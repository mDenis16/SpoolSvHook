#include "CSpoolSVHooks.hpp"
#include "Hooking/Hooking.Patterns.h"
#include <MinHook.h>
#include <spdlog/spdlog.h>

CSpoolSVHooks::CSpoolSVHooks(){

}
CSpoolSVHooks::~CSpoolSVHooks(){

}



typedef BOOL(__stdcall* WritePrinter_t)(HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten);
WritePrinter_t oWritePrinter;
//48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60
BOOL __stdcall WritePrinter_HK(HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten){
    spdlog::info("WritePrinter called buffer size {}", cbBuf);
    return oWritePrinter(hPrinter, pBuf, cbBuf, pcWritten );
}




bool CSpoolSVHooks::EnableAll() {

    {
        auto target = hook::pattern("48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60").count(1).get(0).get<void>();

        MH_CreateHook(target, WritePrinter_HK, (void**)&oWritePrinter);

    }
    

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        spdlog::critical("Failed to enable hooks!");
        return false;
    }

    spdlog::info("Hooked succefsully!");
    return true;
}