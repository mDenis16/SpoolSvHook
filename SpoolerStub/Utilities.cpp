
#include <Windows.h>
#include <iostream>
#include <optional>

#include "Utilities.hpp"

#include <spdlog/spdlog.h>

namespace Utilities
{
    std::string WideStringToString(WCHAR *wideptr)
    {
        std::wstring wstr(wideptr);
        return std::string(wstr.begin(), wstr.end());
    }
    const char *DuplexToString(short dmDuplex)
    {
        switch (dmDuplex)
        {
        case 0:
            return "SingleSide";
            break;
        case 1:
        case 2:
            return "DoubleSide";
            break;

        default:
            break;
        }
    }

    std::optional<std::string> GenerateUniqueIdentifier()
    {
        HMODULE hRpcrt4 = LoadLibrary("rpcrt4.dll");

        if (hRpcrt4 != NULL)
        {
            typedef RPC_STATUS(__stdcall * UuidCreate_t)(UUID * Uuid);
            typedef RPC_STATUS(__stdcall * UuidToStringA_t)(const UUID *Uuid, RPC_CSTR *StringUuid);
            typedef RPC_STATUS(__stdcall * RpcStringFreeA_t)(RPC_CSTR * String);

            UuidCreate_t DI_UuidCreate = (UuidCreate_t)GetProcAddress(hRpcrt4, "UuidCreate");
            UuidToStringA_t DI_UuidToStringA = (UuidToStringA_t)GetProcAddress(hRpcrt4, "UuidToStringA");
            RpcStringFreeA_t DI_RpcStringFreeA = (RpcStringFreeA_t)GetProcAddress(hRpcrt4, "RpcStringFreeA");

            UUID uuid;

            auto rpc_result = DI_UuidCreate(&uuid);

            char *str;

            if (rpc_result == RPC_S_OK)
            {
                rpc_result = DI_UuidToStringA(&uuid, reinterpret_cast<RPC_CSTR *>(&str));

                if (rpc_result == RPC_S_OK)
                {

                    std::string stl_str(reinterpret_cast<const char *>(str));

                    DI_RpcStringFreeA(reinterpret_cast<RPC_CSTR *>(&str));

                    return stl_str;
                }
            }
        }
        else
        {
            spdlog::error("RPCRT4.dll is not present in spooler.");
        }

        return {};
    }
}