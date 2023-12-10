#pragma once

class CJobInfo;

class CPrintJob
{
public:
    int Id;
    CPrintJob(HANDLE _hPrinter, int _Id);
    ~CPrintJob();
    HANDLE hPrinter;


    std::string m_UniqueIdentifier;
  
    std::shared_ptr<CJobInfo> m_JobInfo;

    std::vector<unsigned char> m_RawPrintBuffer;

    void AppendRawSPLData(void* buff, size_t size);


    void SafeJobToFile();

    std::string GetJobMetaData();
};