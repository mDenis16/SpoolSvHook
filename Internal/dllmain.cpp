#include <iostream>
#include <MinHook.h>

#include <Windows.h>

unsigned long WINAPI initialize(void* instance) {


 
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    DisableThreadLibraryCalls(hModule);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (auto handle = CreateThread(nullptr, NULL, initialize, hModule, NULL, nullptr))
            CloseHandle(handle);
        break;
    case DLL_PROCESS_DETACH:
       
        break;
    }
    return TRUE;
}