#include "CSpoolSVHooks.hpp"
#include "Hooking/Hooking.Patterns.h"
#include <MinHook.h>

#include <spdlog/spdlog.h>
#include <fstream>
#include <Windows.h>
#include <Sddl.h>
#include "marshaling.h"
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <memory>
#include "inc.hpp"
#include "CJobService.hpp"
#include "CPrintJob.hpp"

//
#define JOB_CONTROL_PAUSE 1
#define JOB_CONTROL_RESUME 2
#define JOB_CONTROL_CANCEL 3
#define JOB_CONTROL_RESTART 4
#define JOB_CONTROL_DELETE 5
#define JOB_CONTROL_SENT_TO_PRINTER 6
#define JOB_CONTROL_LAST_PAGE_EJECTED 7

//
#define JOB_STATUS_PAUSED 0x00000001
#define JOB_STATUS_ERROR 0x00000002
#define JOB_STATUS_DELETING 0x00000004
#define JOB_STATUS_SPOOLING 0x00000008
#define JOB_STATUS_PRINTING 0x00000010
#define JOB_STATUS_OFFLINE 0x00000020
#define JOB_STATUS_PAPEROUT 0x00000040
#define JOB_STATUS_PRINTED 0x00000080
#define JOB_STATUS_DELETED 0x00000100
#define JOB_STATUS_BLOCKED_DEVQ 0x00000200
#define JOB_STATUS_USER_INTERVENTION 0x00000400
#define JOB_STATUS_RESTART 0x00000800
#define JOB_STATUS_COMPLETE 0x00001000

typedef struct _SPOOL
{
    DWORD signature;
    HANDLE hPrinter;
    DWORD Status;
    LONG cThreads;  // InterlockedDecrement/Increment variable for thread synch
    HANDLE hModule; // Driver UM DLL Module Handle
    FARPROC pfnWrite;
    FARPROC pfnStartDoc;
    FARPROC pfnEndDoc;
    FARPROC pfnClose;
    FARPROC pfnStartPage;
    FARPROC pfnEndPage;
    FARPROC pfnAbort;
    HANDLE hDriver; // supplied to us by driver UI dll
    DWORD JobId;
} SPOOL;

typedef NTSTATUS(WINAPI *RtlGetVersionFunc)(PRTL_OSVERSIONINFOW lpVersionInformation);
static RTL_OSVERSIONINFOW osVersion;
BOOL __stdcall SetJobW_HK(HANDLE hPrinter, DWORD JobId, DWORD Level, LPBYTE pJob, DWORD Command);

DWORD currentJobId = 0;
void GetOsVersion()
{
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod != nullptr)
    {
        RtlGetVersionFunc pRtlGetVersion = (RtlGetVersionFunc)GetProcAddress(hMod, "RtlGetVersion");
        if (pRtlGetVersion != nullptr)
        {
            osVersion = {0};
            osVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

            if (pRtlGetVersion(&osVersion) == 0)
            {
                spdlog::info("Windows version: minor {} major {}.", osVersion.dwMinorVersion, osVersion.dwMajorVersion);
            }
            else
            {
                spdlog::info("Error getting Windows version.");
            }
        }
        else
        {
            spdlog::info("Error finding RtlGetVersion function.");
        }
    }
}
void *CALL(std::string pattern, int expected, int get, std::function<bool(int, int)> func)
{
    if (!func(osVersion.dwMajorVersion, osVersion.dwMinorVersion))
        return nullptr;

    auto target_call = hook::pattern(pattern).count(expected).get(get).get<void>();
    if (!target_call)
        return nullptr;

    auto target = hook::get_call(target_call);

    return target;
}
void *FUNC(std::string pattern, int expected, int get, std::function<bool(int, int)> func)
{
    if (!func(osVersion.dwMajorVersion, osVersion.dwMinorVersion))
        return nullptr;

    auto target = hook::pattern(pattern).count(expected).get(get).get<void>();

    return target;
}

template <typename... Args>
void Hook(std::string hookName, void *detour, void **original, void *ptr, const Args &...pointers)
{
    // Process the first argument
    std::cout << ptr << std::endl;

    if (ptr)
    {
        // LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal
        if (MH_CreateHook(ptr, detour, original) != MH_OK)
        {
            spdlog::error("Failed to hook {}", hookName.c_str());
        }
        else
        {
            spdlog::info("hooked {} succesfuly!", hookName.c_str());
        }
    }

    // Recursively process the rest of the arguments
    if constexpr (sizeof...(pointers) > 0)
    {
        Hook(hookName, detour, original, pointers...);
    }
}

void PrintCallStack(std::string funcName, void *retAddr)
{

    auto moduleAddress = GetModuleHandle(nullptr);

    const int maxStackTraceSize = 64;
    void *stackTrace[maxStackTraceSize];

    // Capture the stack trace
    USHORT frames = CaptureStackBackTrace(0, maxStackTraceSize, stackTrace, nullptr);

    // Print the stack trace
    spdlog::info("[CALLSTACK TRACE FOR {}]", funcName.c_str());
    for (USHORT i = frames; i > 0; i--)
    {
        std::uintptr_t offset = (std::uintptr_t)stackTrace[i] - (std::uintptr_t)moduleAddress;

        if (stackTrace[i] == retAddr)
            spdlog::info("[CURRENT FRAME] at {} offset({})", fmt::ptr(stackTrace[i]), offset);
        else
            spdlog::info("[FRAME] at {} offset({})", fmt::ptr(stackTrace[i]), offset);
    }
}

// Structures
/*
 * Describes a handle returned by AddPrinterW or OpenPrinterW.
 */
typedef DWORD(__stdcall *YGetJob_t)(void *handle,
                                    DWORD JobId,
                                    DWORD Level,
                                    void *buffer,
                                    DWORD cbBuf,
                                    DWORD *a6,
                                    unsigned int restoreMarshall);
YGetJob_t pYGetJob;

typedef BOOL(__stdcall *GetJobAttributesEx_t)(LPWSTR pPrinterName,
                                              LPDEVMODEW pDevmode,
                                              DWORD dwLevel,
                                              LPBYTE pAttributeInfo,
                                              DWORD nSize,
                                              DWORD dwFlags);

typedef struct _SPOOLER_HANDLE
{
    DWORD_PTR Sig;
    BOOL bStartedDoc : 1;
    BOOL bJob : 1;
    BOOL bAnsi : 1;
    BOOL bDocEvent : 1;
    BOOL bTrayIcon : 1;
    BOOL bNoColorProfile : 1;
    BOOL bShared : 1;
    BOOL bClosed : 1;
    DWORD dwJobID;
    HANDLE hPrinter;
    HANDLE hSPLFile;
    DWORD cCount;
    HANDLE hSpoolFileHandle;
    DWORD dwOptions;
} SPOOLER_HANDLE, *PSPOOLER_HANDLE;

bool bInCreatingPrintingJob = false;

__int64 __fastcall RpcGetJob_HK(PSPOOLER_HANDLE handle, DWORD JobId, DWORD Level, void *buff, DWORD cbBuf, DWORD *neededSize);

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

typedef BOOL(__stdcall *WritePrinter_t)(void *hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten);
WritePrinter_t oWritePrinter;
// thanks reactos
//  48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60

std::wstring GetSecurityId()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return std::wstring(L"invalid");
    }

    // Get the size needed for the SID
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);

    // Allocate memory for the TOKEN_USER structure
    TOKEN_USER *pTokenUser = reinterpret_cast<TOKEN_USER *>(new char[dwLength]);

    // Get the user's SID
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength))
    {
        std::cerr << "GetTokenInformation failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        delete[] reinterpret_cast<char *>(pTokenUser);
        return std::wstring(L"invalid");
    }

    // Convert the SID to a string representation
    LPWSTR pStringSid = nullptr;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pStringSid))
    {
        std::cerr << "ConvertSidToStringSid failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        delete[] reinterpret_cast<char *>(pTokenUser);
        return std::wstring(L"invalid");
    }

    return std::wstring((LPCWSTR)pStringSid);
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/ccc2a501-794e-4d2b-b312-f69c75131c2e
/*
 if (settings_->dpi_horizontal() > 0) {
      dev_mode->dmPrintQuality = settings_->dpi_horizontal();
      dev_mode->dmFields |= DM_PRINTQUALITY;
    }
    if (settings_->dpi_vertical() > 0) {
      dev_mode->dmYResolution = settings_->dpi_vertical();
      dev_mode->dmFields |= DM_YRESOLUTION;
    }
*/

void GetPrintJobInfo(void *hPrinter, int jobID)
{

    DWORD bytes_needed = 0;
    /* The above code appears to be a function or method declaration in C++. The name of the function
    is "GetJobW_HK". However, without the actual implementation of the function, it is not possible
    to determine what the code is doing. */
    CSpoolSVHooks::GetJobW_HK(hPrinter, jobID, 2, NULL, 0, &bytes_needed);
    if (bytes_needed == 0)
    {
        spdlog::error("Unable to get bytes needed for job info");
        return;
    }
    std::vector<BYTE> buffer;
    buffer.resize(bytes_needed);

    if (!CSpoolSVHooks::GetJobW_HK(hPrinter,
                                   jobID,
                                   2,
                                   (LPBYTE)(buffer.data()),
                                   buffer.size(),
                                   &bytes_needed))
    {
        spdlog::error("Unable to get job info.");
        return;
    }
    JOB_INFO_2W *job_info = reinterpret_cast<JOB_INFO_2W *>(buffer.data());

    spdlog::info("MEARSA CRUCEA MATIII");

    spdlog::info("job_info {} ", fmt::ptr(job_info));
    spdlog::info("ceva legej  monmentan idu {}", job_info->JobId);

    spdlog::info("job status {}", job_info->Status);
}
BOOL __stdcall WritePrinter_HK(PSPOOLER_HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten)
{

    spdlog::info("Called WritePrinter hook");

    if (currentJobId != -1)
    {
        auto job = CJobService::GetJobById(currentJobId);
        if (job.has_value())
        {
            job.value()->AppendRawSPLData((void *)pBuf, cbBuf);
        }
    }

    BOOL result = oWritePrinter(hPrinter, pBuf, cbBuf, pcWritten);
    spdlog::info("Called WritePrinter hook");

    return TRUE;
}

typedef BOOL(__stdcall *StartDocPrinterW_t)(HANDLE hPrinter, DWORD Level, DOC_INFO_1W *pDocInfo);
StartDocPrinterW_t oStartDocPrinterW;
// E8 ? ? ? ? 41 89 07 call
DWORD __stdcall StartDocPrinterW_HK(HANDLE hPrinter, DWORD Level, DOC_INFO_1W *pDocInfo)
{
    std::wstring a(pDocInfo->pDocName);
    std::string b = std::string(a.begin(), a.end());

    SPOOL *pSpool = (SPOOL *)hPrinter;
    spdlog::info(" pSpool->Status-> {}", pSpool->Status);

    auto jobId = oStartDocPrinterW(hPrinter, Level, pDocInfo);

    if (jobId == 0)
    {
        spdlog::critical("StartDocPrinterW failed error {}", GetLastError());

        return 0;
    }
    spdlog::info("StartDocPrinterW called so createdjob id {} for doc name {} and level {}", jobId, b.c_str(), Level);
    spdlog::info(" sa vedem cdaca merge");

    spdlog::info("hPrinter {}", fmt::ptr(hPrinter));

    PSPOOLER_HANDLE spoolHandle = (PSPOOLER_HANDLE)hPrinter;
    spdlog::info("spoolHandle->hPrinter {}", fmt::ptr(spoolHandle->hPrinter));

    currentJobId = jobId;

    if (!CJobService::DoesJobExist(jobId))
    {
        CJobService::InsertJob(hPrinter, jobId);
    }

    bInCreatingPrintingJob = true;
    return jobId;
}

typedef BOOL(__stdcall *EndDocPrinter_t)(HANDLE hPrinter);
// 48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 48 85 C9 74 70 -> windows 11
// 48 89 5C 24 ? 57 48 83 EC ? 48 8B D9 48 85 C9 0F 84 ? ? ? ? 81 39 ? ? ? ? 0F 85 ? ? ? ? 48 8B 41 -> windows 10 server
EndDocPrinter_t oEndDocPrinter;
BOOL __stdcall EndDocPrinter_HK(HANDLE hPrinter)
{
    spdlog::info("EndDocPrinter_HK ");
    if (currentJobId != -1)
    {
        spdlog::info("mark as sent");
        /*SetJobW_HK(hPrinter,
                     currentJobId,
                     0,
                     NULL,
                     JOB_CONTROL_SENT_TO_PRINTER);
  */
        auto job = CJobService::GetJobById(currentJobId);
        if (job.has_value())
        {
            spdlog::info("EndDocPrinter job id {}", currentJobId);
            job.value()->SafeJobToFile();
            {
                // DWORD bytes_needed=  0;
                // CSpoolSVHooks::GetJobW_HK(hPrinter, jobID, 2, NULL, 0, &bytes_needed);
                // if (bytes_needed == 0)
                // {
                //     spdlog::error("Unable to get bytes needed for job info");
                //     return oEndDocPrinter(hPrinter);;
                // }
                // std::vector<BYTE> buffer;
                // buffer.resize(bytes_needed);

                // if (!CSpoolSVHooks::GetJobW_HK(hPrinter,
                //                                jobID,
                //                                2,
                //                                (LPBYTE)(buffer.data()),
                //                                buffer.size(),
                //                                &bytes_needed))
                // {
                //     spdlog::error("Unable to get job info.");
                //     return oEndDocPrinter(hPrinter);;
                // }
                // JOB_INFO_2W *job_info = reinterpret_cast<JOB_INFO_2W *>(buffer.data());
                // if (job_info)
                //     SetJobW(hPrinter, currentJobId, 2, (LPBYTE)job_info, 6); // delete from queue
            }
        }
    }

    spdlog::info("called EndDocPrinter_HK {}", currentJobId);
    currentJobId = -1;
    return oEndDocPrinter(hPrinter);
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
    auto res = oOpenPrinter2W(pPrinterName, phPrinter, pDefault, pOptions);

    spdlog::info("mearsa secundele");
    if (pPrinterName)
        spdlog::info(L"OpenPrinter2W called for printer {} ", pPrinterName);
    spdlog::info("OpenPrinter2W_HK handle is  {} ", res == TRUE ? "true" : "false");

    if (pDefault)
    {
        spdlog::info("pDefault->pDevMode ", fmt::ptr(pDefault->pDevMode));
    }

    return TRUE;
}

typedef DWORD(__stdcall *SplCommitSpoolData_t)(void *hPrinter,
                                               wchar_t *hProcessHandle,
                                               DWORD cbCommit,
                                               DWORD Level,
                                               void *pFileInfo,
                                               DWORD dwSize,
                                               DWORD *dwNeeded);

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

/*

from tcpmon.dll

__int64 __fastcall CTcpJob::SetStatus(CTcpJob *this, unsigned int a2)
{
  DWORD v4; // edx
  void *v5; // rcx
  DWORD cbBuf; // ebp
  BYTE *v7; // rdi
  DWORD v8; // edx
  void *v9; // rcx
  DWORD Command; // [rsp+48h] [rbp+10h] BYREF
  // this should be written bits not command lol

  if ( WPP_GLOBAL_Control != (TBidiServer *)&WPP_GLOBAL_Control && (*((_BYTE *)WPP_GLOBAL_Control + 28) & 1) != 0 )
    WPP_SF_d(*((_QWORD *)WPP_GLOBAL_Control + 2), 13i64, &WPP_af0c50b75bdb3e6c058c0c07f30fa3e4_Traceguids, a2);
  Command = 0;
  if ( *((_DWORD *)this + 272) != a2 )
  {
    CDeviceStatus::TriggerStatusTimer((CDeviceStatus *)&qword_18003A640);
    v4 = *((_DWORD *)this + 5);
    v5 = (void *)*((_QWORD *)this + 134);
    *((_DWORD *)this + 272) = a2;
    GetJobW(v5, v4, 1u, 0i64, 0, &Command);
    cbBuf = Command;
    v7 = (BYTE *)malloc(Command);
    if ( v7 )
    {
      if ( GetJobW(*((HANDLE *)this + 0x86), *((_DWORD *)this + 5), 1u, v7, cbBuf, &Command) )
      {
        *((_DWORD *)v7 + 16) = 0;
        v8 = *((_DWORD *)this + 5);
        v9 = (void *)*((_QWORD *)this + 134);
        *((_DWORD *)v7 + 14) = a2;
        SetJobW(v9, v8, 1u, v7, 0);
      }
      free(v7);
    }
  }
  return 0i64;
}

*/

typedef DWORD(__stdcall *YGetJobHK_t)(void *handle,
                                      DWORD JobId,
                                      DWORD Level,
                                      JOB_INFO_2W *buff,
                                      DWORD cbBuf,
                                      LPDWORD neededSize,
                                      unsigned int revertMarshling);
YGetJobHK_t oYGetJobHK;
DWORD __fastcall YGetJob_HK(
    void *handle,
    DWORD JobId,
    DWORD Level,
    JOB_INFO_2W *buff,
    DWORD cbBuf,
    LPDWORD neededSize,
    unsigned int revertMarshling)
{

    // Level = 2;

    PrintCallStack("YGetJob_HK", _ReturnAddress());

    auto res = oYGetJobHK(handle, JobId, Level, buff, cbBuf, neededSize, revertMarshling);
    spdlog::info("called YGetJob_HK for jobId {} and marshaling {}", JobId, revertMarshling);

    spdlog::info("func result {}", res);

    // if (buff != nullptr)
    // {
    //     spdlog::info("cristos id {}", buff->JobId);
    //     spdlog::info("buff->pDevMode {}", fmt::ptr(buff->pDevMode));
    //     DEVMODEW* pDevMode = (buff->pDevMode);

    //     auto mata = (DWORD*)(buff->pDevMode);

    //     auto addr = *mata;

    //     spdlog::info("dmBitsPerPel {}", addr);
    // }

    //  JOB_INFO_2W* cristos = (JOB_INFO_2W*)(buff);
    // spdlog::info("cristos id {}", cristos->JobId);

    return res;
}

typedef BOOL(__stdcall *SetJobW_t)(HANDLE hPrinter, DWORD JobId, DWORD Level, LPBYTE pJob, DWORD Command);
SetJobW_t oSetJobW;
// E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B 4C 24 60 E8 ? ? ? ? 85 DB 74 04 33 C0 EB 50 call
BOOL __stdcall SetJobW_HK(HANDLE hPrinter, DWORD JobId, DWORD Level, LPBYTE pJob, DWORD Command)
{

    spdlog::info("called SetJobW_HK with jobid  {} and command {} and level {}", JobId, Command, Level);

    /*
        // Set the new job information.
    if (!SetJobW((HANDLE)pHandle, pAddJobInfo1->JobId, 1, (PBYTE)pJobInfo1, 0))
    {
        dwErrorCode = GetLastError();
        ERR("SetJobW failed with error %lu!\n", dwErrorCode);
        goto Cleanup;
    }

    :REACTOS REFERENCE
    https://doxygen.reactos.org/d7/d4f/base_2winspool_2printers_8c_source.html#l00065

    */

    // if (Level == 1 && pJob)
    // {

    //     DWORD rSize = 0;
    //     auto result = pYGetJob(hPrinter, JobId, 1u, 0, 0, &rSize, 1);
    //     spdlog::info("first call result {} needed Size {}", result, rSize);

    //     auto bufferData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, rSize);
    //     auto cbBuf = rSize;

    //     if (pYGetJob(hPrinter, JobId, 1u, bufferData, cbBuf, &rSize, 1))
    //     {
    //         spdlog::info("mearsa secundele in altar");
    //     }
    //     else
    //     {
    //         spdlog::error("pula si caciula");
    //     }
    // }

    return oSetJobW(hPrinter, JobId, Level, pJob, Command);
}

typedef BOOL(__fastcall *SetPortW_t)(LPWSTR pName, LPWSTR pPortName, DWORD dwLevel, LPBYTE pPortInfo);
SetPortW_t oSetPortW;
BOOL __fastcall SetPortW_HK(LPWSTR pName, LPWSTR pPortName, DWORD dwLevel, LPBYTE pPortInfo)
{
    spdlog::info("oSetPortW called");
    return oSetPortW(pName, pPortName, dwLevel, pPortInfo);
}
typedef __int64(__fastcall *RpcGetJob_t)(PSPOOLER_HANDLE handle, DWORD JobId, DWORD Level, void *buff, DWORD cbBuf, DWORD *neededSize);
RpcGetJob_t oRpcGetJob;
__int64 __fastcall RpcGetJob_HK(PSPOOLER_HANDLE handle, DWORD JobId, DWORD Level, void *buff, DWORD cbBuf, DWORD *neededSize)
{

    //   Level = 2;
    // PrintCallStack("RpcGetJob ", _ReturnAddress());

    auto res = oRpcGetJob(handle, JobId, Level, buff, cbBuf, neededSize);

    spdlog::info("RpcGetJob_HK called with handle {} and and childhandle {} for jobId {} and buffsize {} and level {} and buff {} funcret {}", fmt::ptr(handle), fmt::ptr(handle->hPrinter), JobId, cbBuf, Level, fmt::ptr(buff), res);

    // if (Level == 2 && cbBuf > 0)
    // {

    //     JOB_INFO_2W *job_info = reinterpret_cast<JOB_INFO_2W *>(buff);
    //     spdlog::info("job_info {}", fmt::ptr(job_info));
    //     spdlog::info("testare jobinfo {}", job_info->JobId);

    //     spdlog::info("job_info->pDevMode {}", fmt::ptr(job_info->pDevMode));

    //     auto ver = job_info->pDevMode->dmDriverVersion;
    //     spdlog::info("ver is {}").
    // }

    return res;
}

typedef BOOL(__stdcall *AddJobW_t)(HANDLE hPrinter, DWORD Level, PBYTE pData, DWORD cbBuf, PDWORD pcbNeeded);
AddJobW_t oAddJobW;

// this also updates tray icon ;)
//  E8 ? ? ? ? 44 8B E0 44 8B 44 24 ?  calll
//  BOOL __stdcall AddJobW_HK(HANDLE hPrinter, DWORD Level, PBYTE pData, DWORD cbBuf, PDWORD pcbNeeded)
//  {

// BOOL res =  oAddJobW(hPrinter, Level, pData, cbBuf, pcbNeeded);
//      JOB_INFO_1W* pji1w = (JOB_INFO_1W*)pData;

//         // Replace relative offset addresses in the output by absolute pointers.
//     MarshallUpStructure(cbBuf, pData, AddJobInfo1Marshalling.pInfo, AddJobInfo1Marshalling.cbStructureSize, TRUE);

//    // spdlog::info("Add job called with ID MEARSA {}", pji1w->JobId);

//     return res;
// }

// E8 ? ? ? ? 8B 8C 24 ? ? ? ? 44 8B F8 E8 ? ? ? ? 45 85 FF 74 24 39 9C 24 ? ? ? ? 74 70 44 8B 8C 24 ? ? ? ? 4C 8B C7 48 8B D5 49 8B CE call

BOOL __stdcall CSpoolSVHooks::GetJobW_HK(void *hPrinter, unsigned long JobId, unsigned long Level, void *pJob, unsigned long cbBuf, unsigned long *pcbNeeded)
{
    spdlog::info("called GetJobW_HK for jobId {} and level {}", JobId, Level);
    spdlog::info("GetJobW handle {}", fmt::ptr(hPrinter));

    auto result = CSpoolSVHooks::oGetJobW(hPrinter, JobId, Level, pJob, cbBuf, pcbNeeded);

    if (Level == 1 && cbBuf > 0)
    {
        JOB_INFO_1W *pInfo = (JOB_INFO_1W *)(pJob);

        if (pInfo)
        {
            spdlog::info("Get job status1 is {}", pInfo->Status);

            //  spdlog::info(L"print wstr status {}",   pInfo->pStatus);
            pInfo->Status = 8208;
            SetJobW_HK(hPrinter, JobId, Level, (LPBYTE)pJob, 0);
        }
    }
    if (Level == 2 && cbBuf > 0)
    {
        JOB_INFO_2W *pInfo = (JOB_INFO_2W *)(pJob);

        if (pInfo)
        {
            spdlog::info("Get job status2 is {}", pInfo->Status);
            //  spdlog::info(L"print wstr status {}",   pInfo->pStatus);
            pInfo->Status = 8208;
            SetJobW_HK(hPrinter, JobId, Level, (LPBYTE)pJob, 0);
        }
    }
    return result;
}
/*void GetAvailablePrinters() {
    PRINTER_INFO_2* pPrinterInfo = nullptr;
    DWORD dwNeeded, dwReturned;

    // First, get the required buffer size
    if (!EnumPrinters(PRINTER_ENUM_LOCAL, nullptr, 2, nullptr, 0, &dwNeeded, &dwReturned)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pPrinterInfo = (PRINTER_INFO_2*)malloc(dwNeeded);

            // Now, retrieve the printer information
            if (pPrinterInfo && EnumPrinters(PRINTER_ENUM_LOCAL, nullptr, 2, (LPBYTE)pPrinterInfo, dwNeeded, &dwNeeded, &dwReturned)) {
                for (DWORD i = 0; i < dwReturned; ++i) {
                    std::wcout << "Printer Name: " << pPrinterInfo[i].pPrinterName << std::endl;
                    // You can access other information from PRINTER_INFO_2 structure as needed
                }
            }
            else {
                std::cerr << "Error enumerating printers: " << GetLastError() << std::endl;
            }

            free(pPrinterInfo);
        }
        else {
            std::cerr << "Error getting printer information: " << GetLastError() << std::endl;
        }
    }
}
*/
// chromium printer backend for win
/*
/mojom::ResultCode PrintBackendWin::EnumeratePrinters(
    PrinterList& printer_list) {
  DCHECK(printer_list.empty());
  DWORD bytes_needed = 0;
  DWORD count_returned = 0;
  constexpr DWORD kFlags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
  const DWORD kLevel = 4;
  EnumPrinters(kFlags, nullptr, kLevel, nullptr, 0, &bytes_needed,
               &count_returned);
  logging::SystemErrorCode code = logging::GetLastSystemErrorCode();
  if (code == ERROR_SUCCESS) {
    // If EnumPrinters() succeeded, that means there are no printer drivers
    // installed because 0 bytes was sufficient.
    DCHECK_EQ(bytes_needed, 0u);
    VLOG(1) << "Found no printers";
    return mojom::ResultCode::kSuccess;
  }

  if (code != ERROR_INSUFFICIENT_BUFFER) {
    LOG(ERROR) << "Error enumerating printers: "
               << logging::SystemErrorCodeToString(code);
    return GetResultCodeFromSystemErrorCode(code);
  }

  auto printer_info_buffer = std::make_unique<BYTE[]>(bytes_needed);
  if (!EnumPrinters(kFlags, nullptr, kLevel, printer_info_buffer.get(),
                    bytes_needed, &bytes_needed, &count_returned)) {
    NOTREACHED();
    return GetResultCodeFromSystemErrorCode(logging::GetLastSystemErrorCode());
  }

  // No need to worry about a query failure for `GetDefaultPrinterName()` here,
  // that would mean we can just treat it as there being no default printer.
  std::string default_printer;
  GetDefaultPrinterName(default_printer);

  PRINTER_INFO_4* printer_info =
      reinterpret_cast<PRINTER_INFO_4*>(printer_info_buffer.get());
  for (DWORD index = 0; index < count_returned; index++) {
    ScopedPrinterHandle printer;
    PrinterBasicInfo info;
    if (printer.OpenPrinterWithName(printer_info[index].pPrinterName) &&
        InitBasicPrinterInfo(printer.Get(), &info)) {
      info.is_default = (info.printer_name == default_printer);
      printer_list.push_back(info);
    }
  }

  VLOG(1) << "Found " << count_returned << " printers";
  return mojom::ResultCode::kSuccess;
}
*/
typedef BOOL(__stdcall *EnumPrintersW_t)(DWORD Flags,
                                         LPWSTR Name,
                                         DWORD dwLevel,
                                         LPBYTE lpPrinterEnum,
                                         DWORD cbBuf,
                                         LPDWORD pcbNeeded,
                                         LPDWORD pcReturned);

EnumPrintersW_t oEnumPrintersW;
/*
 LPWSTR  pPrinterName;
    LPWSTR  pServerName;
    DWORD   Attributes;
*/
#define WORD_ALIGN_DOWN(addr) ((LPBYTE)(((DWORD)addr) &= ~1))
#define DWORD_ALIGN_UP(sizeAAA) ((sizeAAA + 3) & ~3)
DWORD PrinterInfo1Strings[] = {offsetof(PRINTER_INFO_1A, pDescription),
                               offsetof(PRINTER_INFO_1A, pName),
                               offsetof(PRINTER_INFO_1A, pComment),
                               0xFFFFFFFF};
DWORD PrinterInfo4Strings[] = {offsetof(PRINTER_INFO_4A, pPrinterName),
                               offsetof(PRINTER_INFO_4A, pServerName),
                               0xFFFFFFFF};

typedef LPBYTE(__stdcall *PackStrings_t)(LPWSTR *pSource,
                                         LPBYTE pDest,
                                         DWORD *DestOffsets,
                                         LPBYTE pEnd);

//
/*
e sfant codul acesta

*/
LPBYTE
CopyPrinterNameToPrinterInfo4(
    LPWSTR pServerName,
    LPWSTR pPrinterName,
    LPBYTE pPrinter,
    LPBYTE pEnd)
{
    static PackStrings_t fnPackStrings = (PackStrings_t)GetProcAddress(GetModuleHandle("spoolss.dll"), "PackStrings");

    LPWSTR SourceStrings[sizeof(PRINTER_INFO_4) / sizeof(LPWSTR)];
    LPWSTR *pSourceStrings = SourceStrings;
    LPPRINTER_INFO_4 pPrinterInfo = (LPPRINTER_INFO_4)pPrinter;
    DWORD *pOffsets;

    pOffsets = PrinterInfo4Strings;

    *pSourceStrings++ = pPrinterName;
    *pSourceStrings++ = pServerName;

    pEnd = fnPackStrings(SourceStrings,
                         (LPBYTE)pPrinterInfo,
                         pOffsets,
                         pEnd);

    pPrinterInfo->Attributes = 2624;

    return pEnd;
}
//__int64 __fastcall PackStrings(_QWORD, _QWORD, _QWORD, _QWORD)

BOOL __stdcall EnumPrintersW_HK(
    DWORD Flags,
    LPWSTR Name,
    DWORD dwLevel,
    LPBYTE lpPrinterEnum,
    DWORD cbBuf,
    LPDWORD pcbNeeded,
    LPDWORD pcReturned)
{
    spdlog::info("called enumprinterw with level {}, cbBuf {}", dwLevel, cbBuf);
    return oEnumPrintersW(Flags, Name, dwLevel, lpPrinterEnum, cbBuf, pcbNeeded, pcReturned);
    if (dwLevel == 1)
    {
        return oEnumPrintersW(Flags, Name, dwLevel, lpPrinterEnum, cbBuf, pcbNeeded, pcReturned);
        auto pPrinter = (PRINTER_INFO_1W *)(lpPrinterEnum);

        static PackStrings_t fnPackStrings = (PackStrings_t)GetProcAddress(GetModuleHandle("spoolss.dll"), "PackStrings");

        DWORD i, NoReturned, Total;
        DWORD cb;
        LPBYTE pEnd;
        LPWSTR SourceStrings[sizeof(PRINTER_INFO_1) / sizeof(LPWSTR)];
        WCHAR string[MAX_PATH];

        //   DBGMSG(DBG_TRACE, ("EnumerateDomains pPrinter %x cbBuf %d pcbNeeded %x pcReturned %x pEnd %x\n",
        //                    pPrinter, cbBuf, pcbNeeded, pcReturned, pEnd));

        *pcReturned = 0;
        *pcbNeeded = 0;

        static wchar_t cel_mai_Tare_sv[] = L"ceauder";
        static wchar_t szLoggedOnDomain[] = L"AXE";

        pEnd = (LPBYTE)pPrinter + cbBuf - *pcbNeeded;

        for (i = 0; i < NoReturned; i++)
        {

            wcscpy(string, L"dada");
            wcscat(string, L"!");
            wcscat(string, cel_mai_Tare_sv);

            cb = wcslen(cel_mai_Tare_sv) * sizeof(WCHAR) + sizeof(WCHAR) +
                 wcslen(string) * sizeof(WCHAR) + sizeof(WCHAR) +
                 wcslen(szLoggedOnDomain) * sizeof(WCHAR) + sizeof(WCHAR) +
                 sizeof(PRINTER_INFO_1);

            (*pcbNeeded) += cb;

            if (cbBuf >= *pcbNeeded)
            {

                (*pcReturned)++;

                pPrinter->Flags = PRINTER_ENUM_LOCAL;

                /* Set the PRINTER_ENUM_EXPAND flag for the user's logon domain
                 */

                SourceStrings[0] = cel_mai_Tare_sv;
                SourceStrings[1] = string;
                SourceStrings[2] = szLoggedOnDomain;

                pEnd = fnPackStrings(SourceStrings, (LPBYTE)pPrinter,
                                     PrinterInfo1Strings, pEnd);

                pPrinter++;
            }
        }

        if (cbBuf < *pcbNeeded)
        {

            //   DBGMSG(DBG_TRACE, ("EnumerateDomains returns ERROR_INSUFFICIENT_BUFFER\n"));
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }

        return TRUE;
    }
    else if (dwLevel == 4)
    {
        WCHAR PrinterName[] = L"AnyPrint";
        WCHAR ServerName[] = L"topor";
        spdlog::info("attempt to add spoofed printer level 4");

        auto res = oEnumPrintersW(Flags, Name, dwLevel, lpPrinterEnum, cbBuf, pcbNeeded, pcReturned);

        if (res == TRUE)
        {
            auto sizeSim = sizeof(PRINTER_INFO_4) +
                           wcslen(PrinterName) * sizeof(WCHAR) + sizeof(WCHAR) +
                           wcslen(ServerName) * sizeof(WCHAR) + sizeof(WCHAR);

            LPBYTE pPrinter = (LPBYTE)(lpPrinterEnum + (*pcReturned) * sizeof(PRINTER_INFO_4));

            cbBuf = (cbBuf - sizeSim);

            spdlog::info("sizeSim is {}", sizeSim);
            spdlog::info("cbbuf is {}", cbBuf);

            LPBYTE pEnd = pPrinter + sizeSim;

            pEnd = CopyPrinterNameToPrinterInfo4(ServerName,
                                                 PrinterName,
                                                 pPrinter,
                                                 pEnd);

            (*pcReturned)++;
            spdlog::info("*pcReturned e {}", *pcReturned);

            cbBuf -= *pcbNeeded;
            return TRUE;
        }
        else
        {
            *pcReturned++;
            *pcbNeeded += sizeof(PRINTER_INFO_4) +
                          wcslen(PrinterName) * sizeof(WCHAR) + sizeof(WCHAR) +
                          wcslen(ServerName) * sizeof(WCHAR) + sizeof(WCHAR);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            spdlog::info("alocating mem stage req size is {}", *pcbNeeded);
            return FALSE;
        }
    }

    // Unsupported level
    // SetLastError(ERROR_INVALID_LEVEL);
    // return oEnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcCountReturned);
}

typedef BOOL(__stdcall *GetPrinterW_t)(HANDLE hPrinter, DWORD Level, LPBYTE pPrinter, DWORD cbBuf, LPDWORD pcbNeeded);
// E8 ? ? ? ? 48 8D 15 ? ? ? ? 49 8B CE
GetPrinterW_t oGetPrinterW;
BOOL __stdcall GetPrinterW_HK(HANDLE hPrinter, DWORD Level, LPBYTE pPrinter, DWORD cbBuf, LPDWORD pcbNeeded)
{

    auto ret = oGetPrinterW(hPrinter, Level, pPrinter, cbBuf, pcbNeeded);
    if (Level == 2)
    {
        PRINTER_INFO_2W *printerInfo = (PRINTER_INFO_2W *)(pPrinter);
        if (printerInfo)
        {
            if (printerInfo->Attributes & PRINTER_ATTRIBUTE_WORK_OFFLINE)
                printerInfo->Attributes &= ~(PRINTER_ATTRIBUTE_WORK_OFFLINE);

            //      spdlog::info("[LEVEL 2] printer info status is {}", printerInfo->Status);
            //      spdlog::info("[LEVEL 2] printer info printerInfo->Attributes) is {}", printerInfo->Attributes);
            //       spdlog::info("printerInfo->Attributes & PRINTER_ATTRIBUTE_WORK_OFFLINE {}", printerInfo->Attributes & PRINTER_ATTRIBUTE_WORK_OFFLINE ? "yes" : "no");
        }
    }
    if (Level == 4)
    {
        PRINTER_INFO_4W *printerInfo = (PRINTER_INFO_4W *)(pPrinter);

        if (printerInfo)
        {
            if (printerInfo->Attributes & PRINTER_ATTRIBUTE_WORK_OFFLINE)
            {

                printerInfo->Attributes &= ~(PRINTER_ATTRIBUTE_WORK_OFFLINE);
            }
        }
    }
    if (Level == 6)
    {
        PRINTER_INFO_6 *printerInfo = (PRINTER_INFO_6 *)(pPrinter);
        if (printerInfo)
        {
            printerInfo->dwStatus = 0x00002000;
            //    spdlog::info(L"[LEVEL 1] printer name  {}", printerInfo->pName);
            //       spdlog::info("[level 1]  printerInfo->Flags {}", printerInfo->Flags);
        }
    }
    // BOOL result = oGetPrinterW(hPrinter, Level, pPrinter, cbBuf, pcbNeeded);
    return ret;
}

// 4C 8B DC 49 89 5B 18 49 89 73 20 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89
// winprint.dll
typedef __int64(__stdcall *PrintEMFJob_t)(void *a1, uint16_t *a2);
PrintEMFJob_t oPrintEMFJob;

__int64 __fastcall PrintEMFJob_HK(void *a1, uint16_t *a2)
{
    spdlog::info("Called PrintEMFJob_HK");
    return oPrintEMFJob(a1, a2);
}
typedef void *(__fastcall *FindSpooler_t)(LPCWSTR lpString1, int a2);
FindSpooler_t oFindSpooler;
void *__fastcall FindSpooler_HK(LPCWSTR lpString1, int a2)
{
    spdlog::info(L"Called FindSpooler_HK with param {}", lpString1);
    return oFindSpooler(lpString1, a2);
}

typedef BOOL(__stdcall *StartPagePrinter_t)(HANDLE hPrinter);
StartPagePrinter_t oStartPagePrinter;
BOOL __stdcall StartPagePrinter_HK(HANDLE hPrinter)
{

    // auto res = oStartPagePrinter(hPrinter);
    // GetPrintJobInfo(hPrinter, currentJobId);
    spdlog::info("Called StartPagePrinter_HK spoofed to TRUE");

    return TRUE;
}

typedef DWORD(__fastcall *YOpenPrinterEx_t)(void *a1,
                                            void **a2,
                                            WCHAR *a3,
                                            void *a4,
                                            void *a5,
                                            void *a6,
                                            void *a7);
YOpenPrinterEx_t oYOpenPrinterEx;
DWORD __fastcall YOpenPrinterEx_HK(
    void *a1,
    void **a2,
    WCHAR *a3,
    void *a4,
    void *a5,
    void *a6,
    void *a7)
{
    spdlog::info(L"called RpcSplOpenPrinter_HK printerName {}", a3);
    return oYOpenPrinterEx(a1, a2, a3, a4, a5, a6, a7);
}

typedef __int64(__fastcall *OpenPrinterExW_t)(void *a1, void **a2, void *a3, unsigned __int8 **a4);
OpenPrinterExW_t oOpenPrinterExW;
__int64 __fastcall OpenPrinterExW_HK(void *a1, void **a2, void *a3, unsigned __int8 **a4)
{
    spdlog::info("MORTII MATII CALLED OpenPrinterExW");
    return oOpenPrinterExW(a1, a2, a3, a4);
}
/*

 HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod != nullptr) {
        RtlGetVersionFunc pRtlGetVersion = (RtlGetVersionFunc)GetProcAddress(hMod, "RtlGetVersion");
        if (pRtlGetVersion != nullptr) {
            RTL_OSVERSIONINFOW rovi = { 0 };
            rovi.dwOSVersionInfoSize = sizeof(rovi);

            if (pRtlGetVersion(&rovi) == 0) {
                std::wcout << L"Windows Version: " << rovi.dwMajorVersion << L"." << rovi.dwMinorVersion << L"." << rovi.dwBuildNumber << std::endl;
            } else {
                std::cerr << "Error getting Windows version." << std::endl;
            }
        } else {
            std::cerr << "Error finding RtlGetVersion function." << std::endl;
        }
    } else {
        std::cerr << "Error getting module handle for ntdll.dll." << std::endl;
    }
*/
bool CSpoolSVHooks::EnableAll()
{

    GetOsVersion();

    {
        /* Hook("WritePrinter_HK", &WritePrinter_HK, (void **)&oWritePrinter,
              FUNC("48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60", 1, 0, [](int majorVersion, int minorVersion)
                   { return true; }));*/
        auto target = hook::pattern("48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60").count(1).get(0).get<void>();

        if (MH_CreateHook(target, &WritePrinter_HK, (void **)&oWritePrinter) != MH_OK)
        {
            spdlog::critical("Failed to enable WritePrinterW hookk {}");
        }
    }

    {
        auto target = hook::pattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 33 F6").count(1).get(0).get<void>();

        if (MH_CreateHook(target, &StartDocPrinterW_HK, (void **)&oStartDocPrinterW) != MH_OK)
        {
            spdlog::critical("Failed to enable StartDocPrinterW hookk {}");
        }
    }

    { // SetJobW(hPrinter, currentJobId, 2, (LPBYTE)job_info, 6);
        auto target = hook::pattern("40 53 48 83 EC ? 4C 8B D9 48 85 C9 74 ? 81 39 ? ? ? ? 75 ? 8B 5C 24 ? 4D 85 C9 75 ? 85 DB 74").count(1).get(0).get<void>();
        //   auto target = hook::get_call(target_call);
        if (MH_CreateHook(target, &CSpoolSVHooks::GetJobW_HK, (void **)&CSpoolSVHooks::oGetJobW) != MH_OK)
        {
            spdlog::critical("Failed to enable GetJobW_HK hookk {}");
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
    // {
    //     auto target = hook::module_pattern(GetModuleHandle("winprint.dll"), "4C 8B DC 49 89 5B 18 49 89 73 20 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89").count(1).get(0).get<void>();
    //      if (MH_CreateHook(target, &PrintEMFJob_HK, (void **)&oPrintEMFJob) != MH_OK)
    //     {
    //         spdlog::critical("Failed to enable PrintEMFJob hookk {}");
    //     }
    // }

    // {
    //     auto target = hook::pattern("48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 50 4C 8B F1 49 8B F9 48 8D 48 E8 41 8B F0 8B EA 33 DB 48 FF 15 ? ? ? ?").count(2).get(0).get<void>();
    //     if (MH_CreateHook(target, &RpcGetJob_HK, (void **)&oRpcGetJob) != MH_OK)
    //     {
    //         spdlog::critical("Failed to enable RpcGetJob_HK hookk {}");
    //     }
    // }
    {
        {
            auto target = hook::pattern("4C 8B DC 49 89 5B ? 49 89 6B ? 49 89 73 ? 49 89 7B ? 41 56 48 81 EC").count(1).get(0).get<void>();

            if (MH_CreateHook(target, &OpenPrinter2W_HK, (void **)&oOpenPrinter2W) != MH_OK)
            {
                spdlog::critical("Failed to enable oOpenPrinter2W hookk {}");
            }
        }
    }

    Hook("GetPrinterW", &GetPrinterW_HK, (void **)&oGetPrinterW,
         CALL("E8 ? ? ? ? 48 8D 15 ? ? ? ? 49 8B CE", 1, 0, [](int major, int minor)
              { return major >= 11; }),
         FUNC("40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 33 DB", 1, 0, [](int major, int minor)
              { return major >= 10; }));

    Hook("SetPortW", &SetPortW_HK, (void **)&oSetPortW,
         FUNC("48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 48 89 78 ? 41 56 48 83 EC ? 49 8B F9 41 8B F0", 1, 0, [](int major, int minor)
              { return major >= 10; }));

    // 48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 48 85 C9 74 70 -> windows 11
    // 48 89 5C 24 ? 57 48 83 EC ? 48 8B D9 48 85 C9 0F 84 ? ? ? ? 81 39 ? ? ? ? 0F 85 ? ? ? ? 48 8B 41 -> windows 10 server
    {
        {

            Hook("EndDocPrinter", &EndDocPrinter_HK, (void **)&oEndDocPrinter,
                 FUNC("48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 48 85 C9 74 70", 1, 0, [](int major, int minor)
                      { return major >= 11; }),
                 FUNC("48 89 5C 24 ? 57 48 83 EC ? 48 8B D9 48 85 C9 0F 84 ? ? ? ? 81 39 ? ? ? ? 0F 85 ? ? ? ? 48 8B 41", 1, 0, [](int major, int minor)
                      { return major >= 10; }));
        }
    }
    /*  {
          {
              auto target_call = hook::pattern("E8 ? ? ? ? 8B 6C 24 70").count(1).get(0).get<void>();
              auto target = hook::get_call(target_call);
              if (MH_CreateHook(target, &EnumPrintersW_HK, (void **)&oEnumPrintersW) != MH_OK)
              {
                  spdlog::critical("Failed to enable EnumPrintersW_HK hookk {}");
              }
              spdlog::info("hooked EnumPrintersW_HK");
          }
      }*/
    {
        auto target = hook::pattern("48 83 EC ? 48 85 C9 0F 84 ? ? ? ? 81 39 ? ? ? ? 0F 85 ? ? ? ? 48 8B 41 ? 49 BA ? ? ? ? ? ? ? ? 48 8B 49 ? 48 8B 80 ? ? ? ? 48 83 C4 ? 48 FF 25 ? ? ? ? CC CC CC CC CC CC CC CC").count(1).get(0).get<void>();

        if (MH_CreateHook(target, &StartPagePrinter_HK, (void **)&oStartPagePrinter) != MH_OK)
        {
            spdlog::critical("Failed to enable StartPagePrinter hookk {}");
        }
    }
    //
    // {
    //     {
    //         auto target = hook::pattern("48 8B C4 48 89 58 20 44 89 40 18 48 89 50 10 89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 40").count(1).get(0).get<void>();

    //         if (MH_CreateHook(target, &YEnumPrinters_HK, (void **)&oYEnumPrinters) != MH_OK)
    //         {
    //             spdlog::critical("Failed to enable YEnumPrinters hookk {}");
    //         }
    //         spdlog::info("hooked YEnumPrinters_HK");
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