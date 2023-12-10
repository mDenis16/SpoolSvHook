#pragma once

class CPrintJob;

class CJobService
{
public:

    static void InsertJob(HANDLE SpoolerHPrinter, DWORD jobId);
    static bool DoesJobExist(DWORD jobId);

    inline static std::vector<std::shared_ptr<CPrintJob>> m_Jobs;

    //JOB_INFO_2W *job_info = reinterpret_cast<JOB_INFO_2W *>(buffer.data());
    bool GetJobInfoFromSpooler(HANDLE hPrinter, DWORD Id, DWORD level, std::vector<BYTE>& buffer);
};