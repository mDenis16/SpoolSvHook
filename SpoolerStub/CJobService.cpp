#include <Windows.h>
#include <vector>
#include <memory>

#include <algorithm>
#include <spdlog/spdlog.h>
#include "CJobService.hpp"
#include "CPrintJob.hpp"
#include "CJobInfo.hpp"

#include "CSpoolSVHooks.hpp"
void CJobService::InsertJob(HANDLE SpoolerHPrinter, DWORD jobId)
{
    spdlog::info("[CJobService] Inserted new job id {}", jobId);
    
    auto job = std::make_shared<CPrintJob>(SpoolerHPrinter, jobId);
}

bool CJobService::DoesJobExist(DWORD jobId)
{
    auto itx = std::find_if(m_Jobs.begin(), m_Jobs.end(), [jobId]( std::shared_ptr<CPrintJob> &job)
            { 
                return job->Id == jobId; 
            });
    return itx != m_Jobs.end();
}


bool CJobService::GetJobInfoFromSpooler(HANDLE hPrinter, DWORD Id, DWORD level, std::vector<BYTE>& buffer ){
  DWORD bytes_needed = 0;
    /* The above code appears to be a function or method declaration in C++. The name of the function
    is "GetJobW_HK". However, without the actual implementation of the function, it is not possible
    to determine what the code is doing. */
    CSpoolSVHooks::GetJobW_HK(hPrinter, Id, level, NULL, 0, &bytes_needed);
    if (bytes_needed == 0)
    {
        spdlog::error("Unable to get bytes needed for job info");
        return false;
    }
   
    buffer.resize(bytes_needed);

    if (!CSpoolSVHooks::GetJobW_HK(hPrinter,
                    Id,
                    level,
                    (LPBYTE)(buffer.data()),
                    buffer.size(),
                    &bytes_needed))
    {
        spdlog::error("Unable to get job info.");
        return false;
    }
    

}