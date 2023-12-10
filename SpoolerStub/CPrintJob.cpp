#include <Windows.h>
#include <iostream>
#include <vector>
#include "CJobInfo.hpp"
#include "CPrintJob.hpp"
#include <memory>

CPrintJob::CPrintJob(HANDLE _hPrinter, int _Id) : hPrinter(_hPrinter), Id(_Id)
{
    m_JobInfo = std::make_shared<CJobInfo>(_hPrinter, _Id, 2);
}

CPrintJob::~CPrintJob()
{
}