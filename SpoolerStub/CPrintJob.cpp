#include <Windows.h>
#include "inc.hpp"

#include "CJobInfo.hpp"
#include "CPrintJob.hpp"
#include "Utilities.hpp"
#include <nlohmann/json.hpp>



CPrintJob::CPrintJob(HANDLE _hPrinter, int _Id) : hPrinter(_hPrinter), Id(_Id)
{
    m_JobInfo = std::make_shared<CJobInfo>(_hPrinter, _Id, 2);
    m_UniqueIdentifier = Utilities::GenerateUniqueIdentifier().value();
}

CPrintJob::~CPrintJob()
{
}

void CPrintJob::AppendRawSPLData(void *buff, size_t size)
{
    m_RawPrintBuffer.insert(m_RawPrintBuffer.end(), static_cast<unsigned char *>(buff), static_cast<unsigned char *>(buff) + size);
}

void CPrintJob::SafeJobToFile()
{

    std::string jobRoot = fmt::format("A:\\repos\\SpoolSvHook\\build\\printjobs\\{}", m_UniqueIdentifier);

    BOOL result = CreateDirectoryA(jobRoot.c_str(), NULL);

    if (result)
    {
        auto meta = GetJobMetaData();
    }
}

std::string CPrintJob::GetJobMetaData()
{
    auto jobInfo = m_JobInfo->CastData<JOB_INFO_2W>();
    auto dev = jobInfo->pDevMode;

    nlohmann::json j;
    j["Bin"] = 0; // unnknown atm,
    j["BinName"] = "null";
    j["Collate"] = dev->dmCollate;
    j["Color"] = dev->dmColor == 2 ? "Color" : "Monochrome";
    j["Duplex"] = Utilities::DuplexToString(dev->dmDuplex);
    j["HorizontalResolution"] = dev->dmPrintQuality;
    j["JobID"] = jobInfo->JobId;
    j["MachineName"] = Utilities::WideStringToString(jobInfo->pMachineName);
    j["Name"] = jobInfo->pDocument;
    j["Orientation"] = dev->dmOrientation == 1 ? "Portrait" : "Landscape";
    j["Pages"] = jobInfo->TotalPages;
    j["PagesPerSheet"] = 1; // still unk
    j["PaperLength"] = dev->dmPaperLength;
    j["PaperSize"] = dev->dmPaperSize;
    j["PaperSizeName"] = Utilities::WideStringToString(dev->dmFormName);
    j["PaperWidth"] = dev->dmPaperWidth;
    j["SecurityID"] = "null";
    j["Staple"] = "None"; // unknown
    j["Status"] = jobInfo->Status;
    j["Username"] = Utilities::WideStringToString(jobInfo->pUserName);
    j["VerticalResolution"] = dev->dmYResolution;
}