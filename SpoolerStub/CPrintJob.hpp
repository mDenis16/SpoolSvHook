#pragma once

class CJobInfo;

class CPrintJob
{
public:
    int Id;
    CPrintJob(HANDLE _hPrinter, int _Id);
    ~CPrintJob();
    HANDLE hPrinter;
  
    std::shared_ptr<CJobInfo> m_JobInfo;
};