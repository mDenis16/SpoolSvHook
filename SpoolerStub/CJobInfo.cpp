#include <Windows.h>

#include "inc.hpp"

#include "CSpoolSVHooks.hpp"
#include "CJobInfo.hpp"
#include <spdlog/spdlog.h>




CJobInfo::CJobInfo(void* _hPrinter, int _JobId, int _Level)
    : hPrinter(_hPrinter), JobId(_JobId), Level(_Level) {
 
    /* The above code appears to be a function or method declaration in C++. The name of the function
    is "GetJobW_HK". However, without the actual implementation of the function, it is not possible
    to determine what the code is doing. */
    CSpoolSVHooks::GetJobW_HK(hPrinter, JobId, Level, NULL, 0, &buffSize);
    if (buffSize == 0)
    {
        spdlog::error("Unable to get bytes needed for job info");
        return ;
    }

    buff = new unsigned char[buffSize];

    unsigned long unsued;
    if (!CSpoolSVHooks::GetJobW_HK(hPrinter,
                                   JobId,
                                   Level,
                                   buff,
                                   buffSize,
                                   &unsued))
    {
        spdlog::error("Unable to get job info.");
        return ;
    }

}

// Destructor definition
CJobInfo::~CJobInfo() {
   delete[] buff;
}



   