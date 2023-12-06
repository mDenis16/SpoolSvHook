#pragma once

enum class InjectionResult : int {
    SUCESFULLY,
    INVALID_PROC_HANDLE,
    INVALID_RIGHTS,
    FAILED_DUE_INVALID_SECTIONS
};

class ALPCInjector {
public:
    InjectionResult Inject(DWORD PID, std::vector<unsigned char> buffer);

public:

    //void *address, PTP_CALLBACK_OBJECT tco, std::vector<unsigned char> buffer
    bool ExecutePayload(void *address, PTP_CALLBACK_OBJECT tco, std::vector<unsigned char> buffer );
    void IterateSections(const std::function<bool(MEMORY_BASIC_INFORMATION)>& function);
    std::optional<std::pair<void*, PTP_CALLBACK_OBJECT>> FindCallback(MEMORY_BASIC_INFORMATION mbi);
    bool IsValidTCO(PTP_CALLBACK_OBJECT tco);
    HANDLE hProcess;
};