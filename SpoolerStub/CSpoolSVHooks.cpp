#include "CSpoolSVHooks.hpp"
#include "Hooking/Hooking.Patterns.h"
#include <MinHook.h>

#include <spdlog/spdlog.h>
#include <fstream>
#include <Windows.h>
#include "marshaling.h"
#include <map>

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
BOOL __stdcall GetJobW_HK(PSPOOLER_HANDLE hPrinter, DWORD JobId, DWORD Level, LPBYTE pJob, DWORD cbBuf, LPDWORD pcbNeeded);
bool bInCreatingPrintingJob = false;
static DWORD currentJobId = -1;
static const MARSHALLING AddJobInfo1Marshalling = {
    sizeof(ADDJOB_INFO_1W),
    {{FIELD_OFFSET(ADDJOB_INFO_1W, Path), RTL_FIELD_SIZE(ADDJOB_INFO_1W, Path), RTL_FIELD_SIZE(ADDJOB_INFO_1W, Path), TRUE},
     {FIELD_OFFSET(ADDJOB_INFO_1W, JobId), RTL_FIELD_SIZE(ADDJOB_INFO_1W, JobId), RTL_FIELD_SIZE(ADDJOB_INFO_1W, JobId), FALSE},
     {MAXDWORD, 0, 0, FALSE}}};

static const MARSHALLING JobInfo1Marshalling = {
    sizeof(JOB_INFO_1W),
    {{FIELD_OFFSET(JOB_INFO_1W, JobId), RTL_FIELD_SIZE(JOB_INFO_1W, JobId), RTL_FIELD_SIZE(JOB_INFO_1W, JobId), FALSE},
     {FIELD_OFFSET(JOB_INFO_1W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_1W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_1W, pPrinterName), TRUE},
     {FIELD_OFFSET(JOB_INFO_1W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_1W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_1W, pMachineName), TRUE},
     {FIELD_OFFSET(JOB_INFO_1W, pUserName), RTL_FIELD_SIZE(JOB_INFO_1W, pUserName), RTL_FIELD_SIZE(JOB_INFO_1W, pUserName), TRUE},
     {FIELD_OFFSET(JOB_INFO_1W, pDocument), RTL_FIELD_SIZE(JOB_INFO_1W, pDocument), RTL_FIELD_SIZE(JOB_INFO_1W, pDocument), TRUE},
     {FIELD_OFFSET(JOB_INFO_1W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_1W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_1W, pDatatype), TRUE},
     {FIELD_OFFSET(JOB_INFO_1W, pStatus), RTL_FIELD_SIZE(JOB_INFO_1W, pStatus), RTL_FIELD_SIZE(JOB_INFO_1W, pStatus), TRUE},
     {FIELD_OFFSET(JOB_INFO_1W, Status), RTL_FIELD_SIZE(JOB_INFO_1W, Status), RTL_FIELD_SIZE(JOB_INFO_1W, Status), FALSE},
     {FIELD_OFFSET(JOB_INFO_1W, Priority), RTL_FIELD_SIZE(JOB_INFO_1W, Priority), RTL_FIELD_SIZE(JOB_INFO_1W, Priority), FALSE},
     {FIELD_OFFSET(JOB_INFO_1W, Position), RTL_FIELD_SIZE(JOB_INFO_1W, Position), RTL_FIELD_SIZE(JOB_INFO_1W, Position), FALSE},
     {FIELD_OFFSET(JOB_INFO_1W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_1W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_1W, TotalPages), FALSE},
     {FIELD_OFFSET(JOB_INFO_1W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_1W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_1W, PagesPrinted), FALSE},
     {FIELD_OFFSET(JOB_INFO_1W, Submitted), RTL_FIELD_SIZE(JOB_INFO_1W, Submitted), sizeof(WORD), FALSE},
     {MAXDWORD, 0, 0, FALSE}}};

static const MARSHALLING JobInfo2Marshalling = {
    sizeof(JOB_INFO_2W),
    {{FIELD_OFFSET(JOB_INFO_2W, JobId), RTL_FIELD_SIZE(JOB_INFO_2W, JobId), RTL_FIELD_SIZE(JOB_INFO_2W, JobId), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_2W, pPrinterName), RTL_FIELD_SIZE(JOB_INFO_2W, pPrinterName), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_2W, pMachineName), RTL_FIELD_SIZE(JOB_INFO_2W, pMachineName), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pUserName), RTL_FIELD_SIZE(JOB_INFO_2W, pUserName), RTL_FIELD_SIZE(JOB_INFO_2W, pUserName), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pDocument), RTL_FIELD_SIZE(JOB_INFO_2W, pDocument), RTL_FIELD_SIZE(JOB_INFO_2W, pDocument), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pNotifyName), RTL_FIELD_SIZE(JOB_INFO_2W, pNotifyName), RTL_FIELD_SIZE(JOB_INFO_2W, pNotifyName), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_2W, pDatatype), RTL_FIELD_SIZE(JOB_INFO_2W, pDatatype), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pPrintProcessor), RTL_FIELD_SIZE(JOB_INFO_2W, pPrintProcessor), RTL_FIELD_SIZE(JOB_INFO_2W, pPrintProcessor), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pParameters), RTL_FIELD_SIZE(JOB_INFO_2W, pParameters), RTL_FIELD_SIZE(JOB_INFO_2W, pParameters), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pDriverName), RTL_FIELD_SIZE(JOB_INFO_2W, pDriverName), RTL_FIELD_SIZE(JOB_INFO_2W, pDriverName), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pDevMode), RTL_FIELD_SIZE(JOB_INFO_2W, pDevMode), RTL_FIELD_SIZE(JOB_INFO_2W, pDevMode), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pStatus), RTL_FIELD_SIZE(JOB_INFO_2W, pStatus), RTL_FIELD_SIZE(JOB_INFO_2W, pStatus), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, pSecurityDescriptor), RTL_FIELD_SIZE(JOB_INFO_2W, pSecurityDescriptor), RTL_FIELD_SIZE(JOB_INFO_2W, pSecurityDescriptor), TRUE},
     {FIELD_OFFSET(JOB_INFO_2W, Status), RTL_FIELD_SIZE(JOB_INFO_2W, Status), RTL_FIELD_SIZE(JOB_INFO_2W, Status), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, Priority), RTL_FIELD_SIZE(JOB_INFO_2W, Priority), RTL_FIELD_SIZE(JOB_INFO_2W, Priority), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, Position), RTL_FIELD_SIZE(JOB_INFO_2W, Position), RTL_FIELD_SIZE(JOB_INFO_2W, Position), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, StartTime), RTL_FIELD_SIZE(JOB_INFO_2W, StartTime), RTL_FIELD_SIZE(JOB_INFO_2W, StartTime), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, UntilTime), RTL_FIELD_SIZE(JOB_INFO_2W, UntilTime), RTL_FIELD_SIZE(JOB_INFO_2W, UntilTime), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_2W, TotalPages), RTL_FIELD_SIZE(JOB_INFO_2W, TotalPages), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, Size), RTL_FIELD_SIZE(JOB_INFO_2W, Size), RTL_FIELD_SIZE(JOB_INFO_2W, Size), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, Submitted), RTL_FIELD_SIZE(JOB_INFO_2W, Submitted), sizeof(WORD), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, Time), RTL_FIELD_SIZE(JOB_INFO_2W, Time), RTL_FIELD_SIZE(JOB_INFO_2W, Time), FALSE},
     {FIELD_OFFSET(JOB_INFO_2W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_2W, PagesPrinted), RTL_FIELD_SIZE(JOB_INFO_2W, PagesPrinted), FALSE},
     {MAXDWORD, 0, 0, FALSE}}};

static const MARSHALLING *pJobInfoMarshalling[] = {
    NULL,
    &JobInfo1Marshalling,
    &JobInfo2Marshalling};
__int64 __fastcall RpcGetJob_HK(PSPOOLER_HANDLE handle, DWORD JobId, DWORD Level, void *buff, DWORD cbBuf, DWORD *neededSize);
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

typedef BOOL(__stdcall *WritePrinter_t)(PSPOOLER_HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten);
WritePrinter_t oWritePrinter;
// thanks reactos
//  48 89 5C 24 ? 57 48 83 EC 30 48 8B D9 48 85 C9 74 46 81 39 ? ? ? ? 75 3E 48 83 79 ? ? 75 37 48 8B 41 08 49 BA ? ? ? ? ? ? ? ? 48 8B 49 10 48 8B 80 ? ? ? ? FF 15 ? ? ? ? 8B F8 85 C0 74 0E 48 8B 4B 60

void GetPrintJobInfo(PSPOOLER_HANDLE hPrinter, int jobID)
{

    DWORD bytes_needed = 0;
    /* The above code appears to be a function or method declaration in C++. The name of the function
    is "GetJobW_HK". However, without the actual implementation of the function, it is not possible
    to determine what the code is doing. */
    GetJobW_HK(hPrinter, jobID, 2, NULL, 0, &bytes_needed);
    if (bytes_needed == 0)
    {
        spdlog::error("Unable to get bytes needed for job info");
        return;
    }
    std::vector<BYTE> buffer;
    buffer.resize(bytes_needed);

    if (!GetJobW_HK(hPrinter,
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

     auto ver = job_info->pDevMode->dmDriverVersion;

    spdlog::info("SATANA IN PERSOANA {}", ver);
    spdlog::info(L"dmDeviceName {} ", job_info->pDevMode->dmDeviceName);
}
BOOL __stdcall WritePrinter_HK(PSPOOLER_HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten)
{
    DWORD sig = 999; //*(DWORD*)(hPrinter->Sig);

    spdlog::info("Called WritePrniter hook");

    std::string res = std::string(hPrinter->bStartedDoc ? "started doc yes" : "started doc no");

    appendBufferToFile("A:\\repos\\SpoolSvHook\\build\\print_data\\print_data.bin", pBuf, (size_t)cbBuf);

    spdlog::info("currentJobId is {}", currentJobId);
    spdlog::info("hPrinter->hPrinter {}", hPrinter->hPrinter);

    //GetPrintJobInfo(hPrinter->hPrinter, 2);

    BOOL result = oWritePrinter(hPrinter, pBuf, cbBuf, pcWritten);

    return result;
}

typedef BOOL(__stdcall *StartDocPrinterW_t)(HANDLE hPrinter, DWORD Level, DOC_INFO_1W *pDocInfo);
StartDocPrinterW_t oStartDocPrinterW;
// E8 ? ? ? ? 41 89 07 call
DWORD __stdcall StartDocPrinterW_HK(HANDLE hPrinter, DWORD Level, DOC_INFO_1W *pDocInfo)
{
    std::wstring a(pDocInfo->pDocName);
    std::string b = std::string(a.begin(), a.end());

    auto jobId = oStartDocPrinterW(hPrinter, Level, pDocInfo);
    spdlog::info("StartDocPrinterW called so createdjob id {} for doc name {} and level {}", jobId, b.c_str(), Level);
    spdlog::info(" sa vedem cdaca merge");

    spdlog::info("hPrinter {}", fmt::ptr(hPrinter));

    PSPOOLER_HANDLE spoolHandle = (PSPOOLER_HANDLE)hPrinter;
  spdlog::info("spoolHandle->hPrinter {}", fmt::ptr(spoolHandle->hPrinter));

    GetPrintJobInfo(spoolHandle, jobId);
    
    bInCreatingPrintingJob = true;
    return jobId;
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

    spdlog::info("OpenPrinter2W called ");
    spdlog::info("pDefault {} ", fmt::ptr(pDefault));

    if (pDefault)
    {
        spdlog::info("pDefault->pDevMode ", fmt::ptr(pDefault->pDevMode));
    }

    return res;
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

typedef BOOL(__stdcall *SetJobW_t)(HANDLE hPrinter, DWORD JobId, DWORD Level, JOB_INFO_1 *pJob, DWORD Command);
SetJobW_t oSetJobW;
// E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B 4C 24 60 E8 ? ? ? ? 85 DB 74 04 33 C0 EB 50 call
BOOL __stdcall SetJobW_HK(HANDLE hPrinter, DWORD JobId, DWORD Level, JOB_INFO_1 *pJob, DWORD Command)
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

typedef BOOL(__stdcall *GetJobW_t)(PSPOOLER_HANDLE hPrinter, DWORD JobId, DWORD Level, LPBYTE pJob, DWORD cbBuf, LPDWORD pcbNeeded);
GetJobW_t oGetJobW;
BOOL __stdcall GetJobW_HK(PSPOOLER_HANDLE hPrinter, DWORD JobId, DWORD Level, LPBYTE pJob, DWORD cbBuf, LPDWORD pcbNeeded)
{
    spdlog::info("called GetJobW_HK for jobId {} and level {}", JobId, Level);
    spdlog::info("GetJobW handle {}", fmt::ptr(hPrinter));

    return oGetJobW(hPrinter, JobId, Level, pJob, cbBuf, pcbNeeded);
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
    // {
    //     auto target_call = hook::pattern("E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B 4C 24 60 E8 ? ? ? ? 85 DB 74 04 33 C0 EB 50").count(1).get(0).get<void>();
    //     auto target = hook::get_call(target_call);
    //     if (MH_CreateHook(target, &SetJobW_HK, (void **)&oSetJobW) != MH_OK)
    //     {
    //         spdlog::critical("Failed to enable SetJobW_HK hookk {}");
    //     }
    // }
    {
        auto target_call = hook::pattern("E8 ? ? ? ? 8B 0D ? ? ? ? 33 D2 8B D8 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 8B C3 48 8B 5C 24 ? 48 8B 6C 24 ? 48 8B 74 24 ? 48 8B 7C 24 ? 48 83 C4 50 41 5E C3 CC CC CC CC CC CC CC 71 81").count(1).get(0).get<void>();
        pYGetJob = (YGetJob_t)(hook::get_call(target_call));

        //     if (MH_CreateHook(pYGetJob, &YGetJob_HK, (void **)&oYGetJobHK) != MH_OK)
        //     {
        //         spdlog::critical("Failed to enable YGetJob_HK hookk {}");
        //     }
        spdlog::info("pYGetJob {} ", fmt::ptr(pYGetJob));
    }
    {
        auto target_call = hook::pattern("E8 ? ? ? ? 8B 8C 24 ? ? ? ? 44 8B F8 E8 ? ? ? ? 45 85 FF 74 24 39 9C 24 ? ? ? ? 74 70 44 8B 8C 24 ? ? ? ? 4C 8B C7 48 8B D5 49 8B CE").count(1).get(0).get<void>();
        auto target = hook::get_call(target_call);
         if (MH_CreateHook(target, &GetJobW_HK, (void **)&oGetJobW) != MH_OK)
        {
            spdlog::critical("Failed to enable GetJobW_HK hookk {}");
        }
    }
    // {
    //     auto target = hook::module_pattern(GetModuleHandle("winprint.dll"), "4C 8B DC 49 89 5B 18 49 89 73 20 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89").count(1).get(0).get<void>();
    //      if (MH_CreateHook(target, &PrintEMFJob_HK, (void **)&oPrintEMFJob) != MH_OK)
    //     {
    //         spdlog::critical("Failed to enable PrintEMFJob hookk {}");
    //     }
    // }

    {
        auto target = hook::pattern("48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 50 4C 8B F1 49 8B F9 48 8D 48 E8 41 8B F0 8B EA 33 DB 48 FF 15 ? ? ? ?").count(2).get(0).get<void>();
        if (MH_CreateHook(target, &RpcGetJob_HK, (void **)&oRpcGetJob) != MH_OK)
        {
            spdlog::critical("Failed to enable RpcGetJob_HK hookk {}");
        }
    }
    {
        {
            auto target_call = hook::pattern("E8 ? ? ? ? 8B F0 E9 ? ? ? ? 48 8B 0D ? ? ? ? 4C 8D 2D ? ? ? ? 49 3B CD 74 1E F6 41").count(1).get(0).get<void>();
            auto target = hook::get_call(target_call);

            if (MH_CreateHook(target, &OpenPrinter2W_HK, (void **)&oOpenPrinter2W) != MH_OK)
            {
                spdlog::critical("Failed to enable oOpenPrinter2W hookk {}");
            }
        }
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        spdlog::critical("Failed to enable hooks!");
        return false;
    }

    spdlog::info("Hooked succefsully!");
    return true;
}