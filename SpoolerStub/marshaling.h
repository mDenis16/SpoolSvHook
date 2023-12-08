/*
 * PROJECT:     ReactOS Printing Stack Marshalling Functions
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Marshalling definitions
 * COPYRIGHT:   Copyright 2015-2018 Colin Finck (colin@reactos.org)
 */
 
 
#ifndef _MARSHALLING_H
#define _MARSHALLING_H
 
typedef struct _MARSHALLING_INFO
{
    DWORD dwOffset;             
    DWORD cbSize;               
    DWORD cbPerElementSize;     
    BOOL bAdjustAddress;        
}
MARSHALLING_INFO;
 
typedef struct _MARSHALLING
{
    DWORD cbStructureSize;
    MARSHALLING_INFO pInfo[];
}
MARSHALLING;
 
BOOL WINAPI MarshallDownStructure(PVOID pStructure, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean);
BOOL WINAPI MarshallDownStructuresArray(PVOID pStructuresArray, DWORD cElements, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean);
BOOL WINAPI MarshallUpStructure(DWORD cbSize, PVOID pStructure, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean);
BOOL WINAPI MarshallUpStructuresArray(DWORD cbSize, PVOID pStructuresArray, DWORD cElements, const MARSHALLING_INFO* pInfo, DWORD cbStructureSize, BOOL bSomeBoolean);
 
#endif