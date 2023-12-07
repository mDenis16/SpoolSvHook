/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 */

#include <Windows.h>
#include <iostream>
#include "Hooking.h"

namespace hook
{
	static uintptr_t g_currentStub = 0;
	const uint64_t MEMORY_BLOCK_SIZE = 0x1000;

	// Max range for seeking a memory block. (= 1024MB)
	const uint64_t MAX_MEMORY_RANGE = 0x40000000;
	static LPVOID FindPrevFreeRegion(LPVOID pAddress,
		LPVOID pMinAddr,
		DWORD dwAllocationGranularity) {
		ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

		// Round down to the next allocation granularity.
		tryAddr -= tryAddr % dwAllocationGranularity;

		// Start from the previous allocation granularity multiply.
		tryAddr -= dwAllocationGranularity;

		while (tryAddr >= (ULONG_PTR)pMinAddr) {
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) ==
				0)
				break;

			if (mbi.State == MEM_FREE)
				return (LPVOID)tryAddr;

			if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
				break;

			tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
		}

		return NULL;
	}
	void* AllocateFunctionStubImpl(void* function, int type)
	{
	
		void* origin = (void*)GetModuleHandle(NULL);


		if (!g_currentStub) {
			ULONG_PTR minAddr;
			ULONG_PTR maxAddr;

			SYSTEM_INFO si;
			GetSystemInfo(&si);
			minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
			maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

			if ((ULONG_PTR)origin > MAX_MEMORY_RANGE &&
				minAddr < (ULONG_PTR)origin - MAX_MEMORY_RANGE)
				minAddr = (ULONG_PTR)origin - MAX_MEMORY_RANGE;

			if (maxAddr > (ULONG_PTR)origin + MAX_MEMORY_RANGE)
				maxAddr = (ULONG_PTR)origin + MAX_MEMORY_RANGE;

			LPVOID pAlloc = origin;

			while ((ULONG_PTR)pAlloc >= minAddr) {
				pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr,
					si.dwAllocationGranularity);
				if (pAlloc == NULL)
					break;

				g_currentStub =
					(std::uintptr_t)VirtualAlloc(pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE,
						PAGE_EXECUTE_READWRITE);
				if (g_currentStub != NULL)
					break;
			}
		}
		if (!g_currentStub)
			return nullptr;

		char* code = (char*)g_currentStub;

		DWORD oldProtect;
		VirtualProtect(code, 15, PAGE_EXECUTE_READWRITE, &oldProtect);

		*(uint8_t*)code = 0x48;
		*(uint8_t*)(code + 1) = 0xb8 | type;

		*(uint64_t*)(code + 2) = (uint64_t)function;

		*(uint16_t*)(code + 10) = 0xE0FF | (type << 8);

		*(uint64_t*)(code + 12) = 0xCCCCCCCCCCCCCCCC;

		g_currentStub += 20;

		return code;
	}
	void* AllocateStubMemoryImpl(size_t size)
	{
		void* origin = (void*)GetModuleHandle(NULL);


		if (!g_currentStub) {
			ULONG_PTR minAddr;
			ULONG_PTR maxAddr;

			SYSTEM_INFO si;
			GetSystemInfo(&si);
			minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
			maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

			if ((ULONG_PTR)origin > MAX_MEMORY_RANGE &&
				minAddr < (ULONG_PTR)origin - MAX_MEMORY_RANGE)
				minAddr = (ULONG_PTR)origin - MAX_MEMORY_RANGE;

			if (maxAddr > (ULONG_PTR)origin + MAX_MEMORY_RANGE)
				maxAddr = (ULONG_PTR)origin + MAX_MEMORY_RANGE;

			LPVOID pAlloc = origin;

			while ((ULONG_PTR)pAlloc >= minAddr) {
				pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr,
					si.dwAllocationGranularity);
				if (pAlloc == NULL)
					break;

				g_currentStub =
					(std::uintptr_t)VirtualAlloc(pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE,
						PAGE_EXECUTE_READWRITE);
				if (g_currentStub != NULL)
					break;
			}
		}
		if (!g_currentStub)
			return nullptr;
		char* code = (char*)g_currentStub;

		DWORD oldProtect;
		VirtualProtect(code, size, PAGE_EXECUTE_READWRITE, &oldProtect);

		g_currentStub += size;

		return code;
	}
#ifndef _M_AMD64
	void inject_hook::inject()
	{
		inject_hook_frontend fe(this);
		m_assembly = std::make_shared<FunctionAssembly>(fe);

		put<uint8_t>(m_address, 0xE9);
		put<int>(m_address + 1, (uintptr_t)m_assembly->GetCode() - (uintptr_t)get_adjusted(m_address) - 5);
	}

	void inject_hook::injectCall()
	{
		inject_hook_frontend fe(this);
		m_assembly = std::make_shared<FunctionAssembly>(fe);

		put<uint8_t>(m_address, 0xE8);
		put<int>(m_address + 1, (uintptr_t)m_assembly->GetCode() - (uintptr_t)get_adjusted(m_address) - 5);
	}
#else
	void* AllocateFunctionStub(void* ptr, int type)
	{
#if defined(GTA_FIVE) || defined(IS_RDR3)
		

		return AllocateFunctionStubImpl(ptr, type);
#else
		return ptr;
#endif
	}

	void* AllocateStubMemory(size_t size)
	{
#if defined(GTA_FIVE) || defined(IS_RDR3)
		

		return AllocateStubMemoryImpl(size);
#else
		return nullptr;
#endif
	}
#endif

	ptrdiff_t baseAddressDifference;
}


