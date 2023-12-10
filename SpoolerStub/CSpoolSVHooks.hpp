#pragma once

  typedef int(__stdcall *GetJobW_t)(void *hPrinter, unsigned long JobId,  unsigned long Level, void* pJob, unsigned long cbBuf, unsigned long* pcbNeeded);

namespace CSpoolSVHooks
{

    bool EnableAll();

  
    inline static GetJobW_t oGetJobW;
    int __stdcall GetJobW_HK(void *hPrinter, unsigned long JobId,  unsigned long Level, void* pJob, unsigned long cbBuf, unsigned long*  pcbNeeded);
};
