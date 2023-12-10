#pragma once

class CPrintJob;
#include <optional>



class CJobService
{
public:

    static void InsertJob(HANDLE SpoolerHPrinter, DWORD jobId);
    static bool DoesJobExist(DWORD jobId);


    inline static std::vector<std::shared_ptr<CPrintJob>> m_Jobs;

    static std::optional<std::shared_ptr<CPrintJob>> GetJobById(unsigned long dwjobID);


};