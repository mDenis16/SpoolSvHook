#pragma once
namespace Utilities
{
    std::optional<std::string> GenerateUniqueIdentifier();
    std::string WideStringToString(WCHAR *wideptr);
    const char *DuplexToString(short dmDuplex);

}