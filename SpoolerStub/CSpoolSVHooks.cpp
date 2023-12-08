#include "CSpoolSVHooks.hpp"
#include "Hooking/Hooking.Patterns.h"
#include <MinHook.h>
#include <spdlog/spdlog.h>
#include <fstream>
#include <Windows.h>
// static const MARSHALLING AddJobInfo1Marshalling = {
//     sizeof(ADDJOB_INFO_1W),
//     {
//         { FIELD_OFFSET(ADDJOB_INFO_1W, Path), RTL_FIELD_SIZE(ADDJOB_INFO_1W, Path), RTL_FIELD_SIZE(ADDJOB_INFO_1W, Path), TRUE },
//         { FIELD_OFFSET(ADDJOB_INFO_1W, JobId), RTL_FIELD_SIZE(ADDJOB_INFO_1W, JobId), RTL_FIELD_SIZE(ADDJOB_INFO_1W, JobId), FALSE },
//         { MAXDWORD, 0, 0, FALSE }
//     }
// };
 
// static const MARSHALLING JobInfo1Marshalling = {
//     sizeof(JOB_INFO_1W),
//     {
//         { FIELD_OFFSET(JOB_INFO_1W, JobId), RTL_FIELD_SIZE(JOB_INFO_1W, JobId), RTL_FIELD_SIZE(JOB_INFO_1W, JobId), FALSE },
//         { FIELD_OFFSET(JOB_INFO_1W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_1W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_1W, pPrinterName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_1W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_1W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_1W, pMachineName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_1W, pUserName), RTL_FIELD_SIZE(JOB_INFO_1W, pUserName), RTL_FIELD_SIZE(JOB_INFO_1W, pUserName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_1W, pDocument), RTL_FIELD_SIZE(JOB_INFO_1W, pDocument), RTL_FIELD_SIZE(JOB_INFO_1W, pDocument), TRUE },
//         { FIELD_OFFSET(JOB_INFO_1W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_1W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_1W, pDatatype), TRUE },
//         { FIELD_OFFSET(JOB_INFO_1W, pStatus), RTL_FIELD_SIZE(JOB_INFO_1W, pStatus), RTL_FIELD_SIZE(JOB_INFO_1W, pStatus), TRUE },
//         { FIELD_OFFSET(JOB_INFO_1W, Status), RTL_FIELD_SIZE(JOB_INFO_1W, Status), RTL_FIELD_SIZE(JOB_INFO_1W, Status), FALSE },
//         { FIELD_OFFSET(JOB_INFO_1W, Priority), RTL_FIELD_SIZE(JOB_INFO_1W, Priority), RTL_FIELD_SIZE(JOB_INFO_1W, Priority), FALSE },
//         { FIELD_OFFSET(JOB_INFO_1W, Position), RTL_FIELD_SIZE(JOB_INFO_1W, Position), RTL_FIELD_SIZE(JOB_INFO_1W, Position), FALSE },
//         { FIELD_OFFSET(JOB_INFO_1W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_1W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_1W, TotalPages), FALSE },
//         { FIELD_OFFSET(JOB_INFO_1W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_1W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_1W, PagesPrinted), FALSE },
//         { FIELD_OFFSET(JOB_INFO_1W, Submitted), RTL_FIELD_SIZE(JOB_INFO_1W, Submitted), sizeof(WORD), FALSE },
//         { MAXDWORD, 0, 0, FALSE }
//     }
// };
 
// static const MARSHALLING JobInfo2Marshalling = {
//     sizeof(JOB_INFO_2W),
//     {
//         { FIELD_OFFSET(JOB_INFO_2W, JobId), RTL_FIELD_SIZE(JOB_INFO_2W, JobId), RTL_FIELD_SIZE(JOB_INFO_2W, JobId), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_2W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_2W, pPrinterName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_2W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_2W, pMachineName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pUserName), RTL_FIELD_SIZE(JOB_INFO_2W, pUserName), RTL_FIELD_SIZE(JOB_INFO_2W, pUserName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pDocument), RTL_FIELD_SIZE(JOB_INFO_2W, pDocument), RTL_FIELD_SIZE(JOB_INFO_2W, pDocument), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pNotifyName), RTL_FIELD_SIZE(JOB_INFO_2W, pNotifyName), RTL_FIELD_SIZE(JOB_INFO_2W, pNotifyName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_2W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_2W, pDatatype), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pPrintProcessor), RTL_FIELD_SIZE(JOB_INFO_2W, pPrintProcessor), RTL_FIELD_SIZE(JOB_INFO_2W, pPrintProcessor), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pParameters), RTL_FIELD_SIZE(JOB_INFO_2W, pParameters), RTL_FIELD_SIZE(JOB_INFO_2W, pParameters), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pDriverName), RTL_FIELD_SIZE(JOB_INFO_2W, pDriverName), RTL_FIELD_SIZE(JOB_INFO_2W, pDriverName), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pDevMode), RTL_FIELD_SIZE(JOB_INFO_2W, pDevMode), RTL_FIELD_SIZE(JOB_INFO_2W, pDevMode), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pStatus), RTL_FIELD_SIZE(JOB_INFO_2W, pStatus), RTL_FIELD_SIZE(JOB_INFO_2W, pStatus), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, pSecurityDescriptor), RTL_FIELD_SIZE(JOB_INFO_2W, pSecurityDescriptor), RTL_FIELD_SIZE(JOB_INFO_2W, pSecurityDescriptor), TRUE },
//         { FIELD_OFFSET(JOB_INFO_2W, Status), RTL_FIELD_SIZE(JOB_INFO_2W, Status), RTL_FIELD_SIZE(JOB_INFO_2W, Status), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, Priority), RTL_FIELD_SIZE(JOB_INFO_2W, Priority), RTL_FIELD_SIZE(JOB_INFO_2W, Priority), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, Position), RTL_FIELD_SIZE(JOB_INFO_2W, Position), RTL_FIELD_SIZE(JOB_INFO_2W, Position), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, StartTime), RTL_FIELD_SIZE(JOB_INFO_2W, StartTime), RTL_FIELD_SIZE(JOB_INFO_2W, StartTime), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, UntilTime), RTL_FIELD_SIZE(JOB_INFO_2W, UntilTime), RTL_FIELD_SIZE(JOB_INFO_2W, UntilTime), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_2W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_2W, TotalPages), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, Size), RTL_FIELD_SIZE(JOB_INFO_2W, Size), RTL_FIELD_SIZE(JOB_INFO_2W, Size), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, Submitted), RTL_FIELD_SIZE(JOB_INFO_2W, Submitted), sizeof(WORD), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, Time), RTL_FIELD_SIZE(JOB_INFO_2W, Time), RTL_FIELD_SIZE(JOB_INFO_2W, Time), FALSE },
//         { FIELD_OFFSET(JOB_INFO_2W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_2W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_2W, PagesPrinted), FALSE },
//         { MAXDWORD, 0, 0, FALSE }
//     }
// };
 
// static const MARSHALLING* pJobInfoMarshalling[] = {
//     NULL,
//     &JobInfo1Marshalling,
//     &JobInfo2Marshalling
// };

CSpoolSVHooks::CSpoolSVHooks()
{
}
CSpoolSVHooks::~CSpoolSVHooks()
{
}
void appendBufferToFile(const char *filename, void *buffer, std::size_t bufferSize)
{
    // Open the file in binary mode for appending
    std::ofstream outFile(filename, std::ios::binary | std::ios::app);

    if (!outFile)
    {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    // Write the buffer to the end of the file
    outFile.write((char *)buffer, bufferSize);

    // Close the file
    outFile.close();

    if (outFile.fail())
    {
        std::cerr << "Error writing to file: " << filename << std::endl;
        return;
    }

    std::cout << "Data successfully appended to file: " << filename << std::endl;
}

typedef BOOL(__stdcall *WritePrinter_t)(HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten);
WritePrinter_t oWritePrinter;
// 48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60
BOOL __stdcall WritePrinter_HK(HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten)
{
    spdlog::info("WritePrinter called buffer size {}", cbBuf);
    appendBufferToFile("A:\\repos\\SpoolSvHook\\build\\print_data\\print_data.bin", pBuf, (size_t)cbBuf);
    BOOL result = oWritePrinter(hPrinter, pBuf, cbBuf, pcWritten);

    return result;
}

typedef BOOL(__stdcall *StartDocPrinterW_t)(HANDLE hPrinter, DWORD Level, DOC_INFO_1W * pDocInfo);
StartDocPrinterW_t oStartDocPrinterW;
// E8 ? ? ? ? 41 89 07 call
DWORD __stdcall StartDocPrinterW_HK(HANDLE hPrinter, DWORD Level, DOC_INFO_1W * pDocInfo)
{
    std::wstring a(pDocInfo->pDocName);
    std::string b = std::string(a.begin(), a.end());
    

    spdlog::info("StartDocPrinterW called for doc name {} and level {}", b.c_str(), Level);
    return oStartDocPrinterW(hPrinter, Level, pDocInfo);
}

typedef BOOL(__stdcall *OpenPrinter2W_t)(LPCWSTR pPrinterName,
                                         LPHANDLE phPrinter,
                                         PPRINTER_DEFAULTSW pDefault,
                                         PPRINTER_OPTIONSW pOptions);
OpenPrinter2W_t oOpenPrinter2W;
// E8 ? ? ? ? 8B F0 E9 ? ? ? ? 48 8B 0D ? ? ? ? 4C 8D 2D ? ? ? ? 49 3B CD 74 1E F6 41 call
BOOL __stdcall OpenPrinter2W_HK(
    LPCWSTR pPrinterName,
    LPHANDLE phPrinter,
    PPRINTER_DEFAULTSW pDefault,
    PPRINTER_OPTIONSW pOptions)
{
    std::wstring wstr(pPrinterName);
    std::string str(wstr.begin(), wstr.end());

    spdlog::info("OpenPrinter2W {} ", str.c_str());

    return oOpenPrinter2W(pPrinterName, phPrinter, pDefault, pOptions);
}

typedef DWORD(__stdcall *SplCommitSpoolData_t)(void *hPrinter,
                                               wchar_t *hProcessHandle,
                                               DWORD cbCommit,
                                               DWORD Level,
                                               void *pFileInfo,
                                               DWORD dwSize,
                                               DWORD *dwNeeded);

typedef struct _WINSPOOL_JOB_INFO_2
{
    DWORD JobId;
    WCHAR *pPrinterName;
    WCHAR *pMachineName;
    WCHAR *pUserName;
    WCHAR *pDocument;
    WCHAR *pNotifyName;
    WCHAR *pDatatype;
    WCHAR *pPrintProcessor;
    WCHAR *pParameters;
    WCHAR *pDriverName;
    ULONG_PTR pDevMode;
    WCHAR *pStatus;
    ULONG_PTR pSecurityDescriptor;
    DWORD Status;
    DWORD Priority;
    DWORD Position;
    DWORD StartTime;
    DWORD UntilTime;
    DWORD TotalPages;
    DWORD Size;
    SYSTEMTIME Submitted;
    DWORD Time;
    DWORD PagesPrinted;
} WINSPOOL_JOB_INFO_2;

SplCommitSpoolData_t oSplCommitSpoolData;
// E8 ? ? ? ? 8B F0 85 C0 75 0E 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B D8 B9 ? ? ? ? E8 ? ? ? ? EB 0E 48 FF 15 ? ? ? ? 0F 1F 44 00
DWORD __fastcall SplCommitSpoolData_HK(
    void *hPrinter,
    wchar_t *hProcessHandle,
    DWORD cbCommit,
    DWORD Level,
    void *pFileInfo,
    DWORD dwSize,
    DWORD *dwNeeded)
{
    spdlog::info("called oSplCommitSpoolData Level {} !!!", Level);
    return oSplCommitSpoolData(hPrinter, hProcessHandle, cbCommit, Level, pFileInfo, dwSize, dwNeeded);
}

typedef BOOL(__stdcall *SetJobW_t)(HANDLE hPrinter, DWORD JobId, DWORD Level, JOB_INFO_1 *pJob, DWORD Command);
SetJobW_t oSetJobW;
// E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B 4C 24 60 E8 ? ? ? ? 85 DB 74 04 33 C0 EB 50 call
BOOL __stdcall SetJobW_HK(HANDLE hPrinter, DWORD JobId, DWORD Level, JOB_INFO_1 *pJob, DWORD Command)
{

    spdlog::info("called SetJobW_HK with jobid  {} and command {} and level {}", JobId, Command, Level);
    if (Level == 1 && pJob)
    {
        
        spdlog::info("Created job id {}", pJob->JobId);
    }
    else if (Level == 2  && pJob){
        JOB_INFO_2* job2 = (JOB_INFO_2*)pJob;
        spdlog::info("mearsa si la level 2 !!!");
    }
    return oSetJobW(hPrinter, JobId, Level, pJob, Command);
}

typedef BOOL(__stdcall *AddJobW_t)(HANDLE hPrinter, DWORD Level, PBYTE pData, DWORD cbBuf, PDWORD pcbNeeded);
AddJobW_t oAddJobW;

//this also updates tray icon ;)
// E8 ? ? ? ? 44 8B E0 44 8B 44 24 ?  calll
BOOL __stdcall AddJobW_HK(HANDLE hPrinter, DWORD Level, PBYTE pData, DWORD cbBuf, PDWORD pcbNeeded)
{
    BOOL res =  oAddJobW(hPrinter, Level, pData, cbBuf, pcbNeeded);


  JOB_INFO_1W* pji1w = (JOB_INFO_1W*)pData;
 
        // Replace relative offset addresses in the output by absolute pointers.
      //  MarshallUpStructure(cbBuf, pData, AddJobInfo1Marshalling.pInfo, AddJobInfo1Marshalling.cbStructureSize, TRUE);
    spdlog::info("Add job called pData {}", fmt::ptr(pData));
    return res;
}

bool CSpoolSVHooks::EnableAll()
{

    {
        auto target = hook::pattern("48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60").count(1).get(0).get<void>();

        if (MH_CreateHook(target, &WritePrinter_HK, (void **)&oWritePrinter) != MH_OK)
        {
            spdlog::critical("Failed to enable write printer hookk {}");
        }
    }
    {
        auto target_call = hook::pattern("E8 ? ? ? ? 41 89 07").count(1).get(0).get<void>();
        auto target = hook::get_call(target_call);
        if (MH_CreateHook(target, &StartDocPrinterW_HK, (void **)&oStartDocPrinterW) != MH_OK)
        {
            spdlog::critical("Failed to enable StartDocPrinterW hookk {}");
        }
    }
    {
        auto target_call = hook::pattern("E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B 4C 24 60 E8 ? ? ? ? 85 DB 74 04 33 C0 EB 50").count(1).get(0).get<void>();
        auto target = hook::get_call(target_call);
        if (MH_CreateHook(target, &SetJobW_HK, (void **)&oSetJobW) != MH_OK)
        {
            spdlog::critical("Failed to enable SetJobW_HK hookk {}");
        }
    }
    {
        auto target_call = hook::pattern("E8 ? ? ? ? 44 8B E0 44 8B 44 24 ?").count(1).get(0).get<void>();
        auto target = hook::get_call(target_call);
        if (MH_CreateHook(target, &AddJobW_HK, (void **)&oAddJobW) != MH_OK)
        {
            spdlog::critical("Failed to enable AddJobW_HK hookk {}");
        }
    }
    // {
    //     auto target_call = hook::pattern("E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B 4C 24 60 E8 ? ? ? ? 85 DB 74 04 33 C0 EB 50").count(1).get(0).get<void>();
    //     auto target = hook::get_call(target_call);
    //      if (MH_CreateHook(target, &SplCommitSpoolData_HK, (void **)&oSplCommitSpoolData) != MH_OK)
    //     {
    //         spdlog::critical("Failed to enable SplCommitSpoolData hookk {}");
    //     }
    // }
    // {
    //     {
    //         auto target_call = hook::pattern("E8 ? ? ? ? 8B F0 85 C0 75 0E 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B D8 B9 ? ? ? ? E8 ? ? ? ? EB 0E 48 FF 15 ? ? ? ? 0F 1F 44 00").count(2).get(0).get<void>();
    //         auto target = hook::get_call(target_call);
    //         if (MH_CreateHook(target, &OpenPrinter2W_HK, (void **)&oOpenPrinter2W) != MH_OK)
    //         {
    //             spdlog::critical("Failed to enable OpenPrinter2W hookk {}");
    //         }
    //     }
    // }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        spdlog::critical("Failed to enable hooks!");
        return false;
    }

    spdlog::info("Hooked succefsully!");
    return true;
}