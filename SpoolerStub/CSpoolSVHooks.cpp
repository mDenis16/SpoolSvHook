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

#include "CJobService.hpp"
#include "CPrintJob.hpp"


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

DWORD currentJobId = 0;



std::optional<UUID> GenerateUUID(){
     HMODULE hRpcrt4 = LoadLibrary("rpcrt4.dll");

    if (hRpcrt4 != NULL) {
        typedef RPC_STATUS(__stdcall *UuidCreate_t)(UUID *Uuid);

        UuidCreate_t func = (UuidCreate_t)GetProcAddress(hRpcrt4, "UuidCreate");
        UUID ret;
        if (func)
        {
            auto rpc_result = func(&ret);
            if (rpc_result == RPC_S_OK)
                 return ret;
        }
    } else {
       spdlog::error("RPCRT4.dll is not present in spooler.");
    }

    return {};
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

typedef BOOL(__stdcall *WritePrinter_t)(void* hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten);
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

std::string WideStringToString(WCHAR *wideptr)
{
    std::wstring wstr(wideptr);
    return std::string(wstr.begin(), wstr.end());
}
const char* DuplexToString(short dmDuplex){
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
//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/ccc2a501-794e-4d2b-b312-f69c75131c2e
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
nlohmann::json constructJsonPrinterMeta(JOB_INFO_2W *jobInfo)
{

    auto dev = jobInfo->pDevMode;

    nlohmann::json j;
    j["Bin"] = 0; // unnknown atm,
    j["BinName"] = "null";
    j["Collate"] = dev->dmCollate;
    j["Color"] = dev->dmColor == 2 ? "Color" : "Monochrome";
    j["Duplex"] = DuplexToString(dev->dmDuplex);
    j["HorizontalResolution"] = dev->dmPrintQuality;
    j["JobID"] = jobInfo->JobId;
    j["MachineName"] = WideStringToString(jobInfo->pMachineName);
    j["Name"] = jobInfo->pDocument;
    j["Orientation"] = dev->dmOrientation == 1 ? "Portrait" : "Landscape";
    j["Pages"] = jobInfo->TotalPages;
    j["PagesPerSheet"] = 1; // still unk
    j["PaperLength"] = dev->dmPaperLength;
    j["PaperSize"] = dev->dmPaperSize;
    j["PaperSizeName"] = WideStringToString(dev->dmFormName);
    j["PaperWidth"] = dev->dmPaperWidth;
    j["SecurityID"] = WideStringToString(GetSecurityId().data());
    j["Staple"] = "None"; // unknown
    j["Status"] = jobInfo->Status;
    j["Username"] = WideStringToString(jobInfo->pUserName);
    j["VerticalResolution"] = dev->dmYResolution;

/*
0,1,2

DMDUP_HORIZONTAL
Print double-sided, using short edge binding.

DMDUP_SIMPLEX
Print single-sided.

DMDUP_VERTICAL

*/
    return j;
}
void GetPrintJobInfo(void* hPrinter, int jobID)
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

    auto ver = job_info->pDevMode->dmDriverVersion;

    spdlog::info("SATANA IN PERSOANA {}", ver);
    spdlog::info(L"dmDeviceName {} ", job_info->pDevMode->dmDeviceName);

    auto json = constructJsonPrinterMeta(job_info);

    auto jsonStr = json.dump();

    appendBufferToFile("A:\\repos\\SpoolSvHook\\build\\print_data\\print_data_meta.json", jsonStr.data(), jsonStr.size());

    spdlog::info(L"print status {}", job_info->Status);
    spdlog::info(L" dev->dmFormName {}", job_info->pDevMode->dmFormName);
}
BOOL __stdcall WritePrinter_HK(PSPOOLER_HANDLE hPrinter, LPVOID pBuf, DWORD cbBuf, LPDWORD pcWritten)
{
   

    spdlog::info("Called WritePrniter hook");

    std::string res = std::string(hPrinter->bStartedDoc ? "started doc yes" : "started doc no");

    appendBufferToFile("A:\\repos\\SpoolSvHook\\build\\print_jobs\\print_data.bin", pBuf, (size_t)cbBuf);

    
    
    // GetPrintJobInfo(hPrinter->hPrinter, 2);

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

    if (!CJobService::DoesJobExist(jobId)){
        CJobService::InsertJob(hPrinter, jobId);
    }

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


BOOL __stdcall CSpoolSVHooks::GetJobW_HK(void *hPrinter, unsigned long JobId,  unsigned long Level, void* pJob, unsigned long cbBuf, unsigned long*  pcbNeeded)
{
    spdlog::info("called GetJobW_HK for jobId {} and level {}", JobId, Level);
    spdlog::info("GetJobW handle {}", fmt::ptr(hPrinter));

    auto result = CSpoolSVHooks::oGetJobW(hPrinter, JobId, Level, pJob, cbBuf, pcbNeeded);
    if (Level == 1 && cbBuf > 0)
    {
        JOB_INFO_1W *pInfo = (JOB_INFO_1W *)(pJob);

        if (pInfo)
        {
            spdlog::info("Job got updated status {}", pInfo->Status);
            spdlog::info("spoofing jobstatus to 16");
            pInfo->Status |= JOB_STATUS_PRINTING;
        }
    }
    return result;
}

typedef BOOL(__stdcall *GetPrinterW_t)(HANDLE hPrinter, DWORD Level, LPBYTE pPrinter, DWORD cbBuf, LPDWORD pcbNeeded);
//E8 ? ? ? ? 48 8D 15 ? ? ? ? 49 8B CE
GetPrinterW_t oGetPrinterW;
BOOL __stdcall GetPrinterW_HK(HANDLE hPrinter, DWORD Level, LPBYTE pPrinter, DWORD cbBuf, LPDWORD pcbNeeded){
    spdlog::info("GetPrinterW_HK at level {} ", Level);

    BOOL result = oGetPrinterW(hPrinter, Level, pPrinter, cbBuf, pcbNeeded);


    return result;
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
        if (MH_CreateHook(target, &CSpoolSVHooks::GetJobW_HK, (void **)&CSpoolSVHooks::oGetJobW) != MH_OK)
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

    {
        {
            auto target_call = hook::pattern("E8 ? ? ? ? 48 8D 15 ? ? ? ? 49 8B CE").count(1).get(0).get<void>();
            auto target = hook::get_call(target_call);

            if (MH_CreateHook(target, &GetPrinterW_HK, (void **)&oGetPrinterW) != MH_OK)
            {
                spdlog::critical("Failed to enable GetPrinterW hookk {}");
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