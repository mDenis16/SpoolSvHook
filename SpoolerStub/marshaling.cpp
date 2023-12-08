#define WIN32_NO_STATUS
#include <Windows.h>
 
#include "marshaling.h"

BOOL WINAPI
MarshallDownStructure(PVOID pStructure, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean)
{
    // Sanity checks
    if (!pStructure || !pInfo)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
 
    // Loop until we reach an element with offset set to MAXDWORD.
    while (pInfo->dwOffset != MAXDWORD)
    {
        PULONG_PTR pCurrentField = (PULONG_PTR)((PBYTE)pStructure + pInfo->dwOffset);
 
        if (pInfo->bAdjustAddress && *pCurrentField)
        {
            // Make a relative offset out of the absolute pointer address.
            *pCurrentField -= (ULONG_PTR)pStructure;
        }
 
        // Advance to the next field description.
        pInfo++;
    }
 
    return TRUE;
}
 
BOOL WINAPI
MarshallDownStructuresArray(PVOID pStructuresArray, DWORD cElements, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean)
{
    PBYTE pCurrentElement = (PBYTE)pStructuresArray;
 
    // Call MarshallDownStructure on all array elements given by cElements of cbStructureSize.
    while (cElements--)
    {
        if (!MarshallDownStructure(pCurrentElement, pInfo, cbStructureSize, bSomeBoolean))
            return FALSE;
 
        // Advance to the next array element.
        pCurrentElement += cbStructureSize;
    }
 
    return TRUE;
}
 
BOOL WINAPI
MarshallUpStructure(DWORD cbSize, PVOID pStructure, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean)
{
    // Sanity checks
    if (!pStructure || !pInfo)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
 
    // Loop until we reach an element with offset set to MAXDWORD.
    while (pInfo->dwOffset != MAXDWORD)
    {
        PULONG_PTR pCurrentField = (PULONG_PTR)((PBYTE)pStructure + pInfo->dwOffset);
 
        if (pInfo->bAdjustAddress && *pCurrentField)
        {
            // Verify that the offset in the current field is within the bounds given by cbSize.
            if (cbSize <= *pCurrentField)
            {
                SetLastError(ERROR_INVALID_DATA);
                return FALSE;
            }
 
            // Make an absolute pointer address out of the relative offset.
            *pCurrentField += (ULONG_PTR)pStructure;
        }
 
        // Advance to the next field description.
        pInfo++;
    }
 
    return TRUE;
}
 
BOOL WINAPI
MarshallUpStructuresArray(DWORD cbSize, PVOID pStructuresArray, DWORD cElements, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean)
{
    PBYTE pCurrentElement = (PBYTE)pStructuresArray;
 
    // Call MarshallUpStructure on all array elements given by cElements of cbStructureSize.
    while (cElements--)
    {
        if (!MarshallUpStructure(cbSize, pCurrentElement, pInfo, cbStructureSize, bSomeBoolean))
            return FALSE;
 
        // Advance to the next array element.
        pCurrentElement += cbStructureSize;
    }
 
    return TRUE;
}
