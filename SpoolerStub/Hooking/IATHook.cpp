#include <Windows.h>
#include <iostream>
#include "IATHook.h"


namespace Hooking {
	void IAT_Hook(std::string function, DWORD_PTR hk) {
		LPVOID imageBase = GetModuleHandleA(NULL);
		PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
		IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
		LPCSTR libraryName = NULL;
		HMODULE library = NULL;
		PIMAGE_IMPORT_BY_NAME functionName = NULL;

		while (importDescriptor->Name != NULL)
		{
			libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
			library = LoadLibraryA(libraryName);

			if (library)
			{
				PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
				originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
				firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

				while (originalFirstThunk->u1.AddressOfData != NULL)
				{
					functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

					if (std::string(functionName->Name).compare(function) == 0)
					{
						SIZE_T bytesWritten = 0;
						DWORD oldProtect = 0;
						VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
						firstThunk->u1.Function = hk;
					}
					++originalFirstThunk;
					++firstThunk;
				}
			}

			importDescriptor++;
		}
	}
}