#include <Windows.h>
#include "inc.hpp"

#include "CJobService.hpp"
#include "CPrintJob.hpp"
#include "CJobInfo.hpp"

#include "CSpoolSVHooks.hpp"
#include <rpcdce.h>

void CJobService::InsertJob(HANDLE SpoolerHPrinter, DWORD jobId)
{
    spdlog::info("[CJobService] Inserted new job id {}", jobId);

    auto job = std::make_shared<CPrintJob>(SpoolerHPrinter, jobId);

    m_Jobs.push_back(job);
}

bool CJobService::DoesJobExist(DWORD jobId)
{
    auto itx = std::find_if(m_Jobs.begin(), m_Jobs.end(), [jobId](std::shared_ptr<CPrintJob> &job)
                            { return job->Id == jobId; });

    spdlog::info("Checking if DoesJobExist {} m_Jobs count size {}", jobId, m_Jobs.size());

    return itx != m_Jobs.end();
}

//
std::optional<std::shared_ptr<CPrintJob>> CJobService::GetJobById(unsigned long dwjobID)
{
    auto itx = std::find_if(m_Jobs.begin(), m_Jobs.end(), [dwjobID](std::shared_ptr<CPrintJob> &job)
                            { return job->Id == dwjobID; });
    if (itx == m_Jobs.end())
        return {};

    return *itx;
}

