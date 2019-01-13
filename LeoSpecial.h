#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>

#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif



class LeoHook {
public:
	static bool Hook(uintptr_t og_fun, uintptr_t hk_fun);
	static bool Unhook();

private:
	static uintptr_t og_fun;
	static uintptr_t hk_fun;
	static PVOID VEH_Handle;
	static DWORD oldProtection;

	static bool AreInSamePage(const uint8_t* Addr1, const uint8_t* Addr2);
	static LONG WINAPI LeoHandler(EXCEPTION_POINTERS *pExceptionInfo);
};

uintptr_t LeoHook::og_fun = 0;
uintptr_t LeoHook::hk_fun = 0;
PVOID LeoHook::VEH_Handle = nullptr;
DWORD LeoHook::oldProtection = 0;

bool LeoHook::Hook(uintptr_t original_fun, uintptr_t hooked_fun)
{
	og_fun = original_fun;
	LeoHook::hk_fun = hooked_fun;

	if (AreInSamePage((const uint8_t*)og_fun, (const uint8_t*)hk_fun))
		return false;

	VEH_Handle = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)LeoHandler);

	if(VEH_Handle && VirtualProtect((LPVOID)og_fun, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection))
		return true;
	
	return false;
}

bool LeoHook::Unhook()
{
	DWORD old;
	if (VEH_Handle &&
		VirtualProtect((LPVOID)og_fun, 1, oldProtection, &old) &&
		RemoveVectoredExceptionHandler(VEH_Handle))
		return true;

	return false;
}

LONG WINAPI LeoHook::LeoHandler(EXCEPTION_POINTERS *pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		if (pExceptionInfo->ContextRecord->XIP == (uintptr_t)og_fun)
		{
			pExceptionInfo->ContextRecord->XIP = (uintptr_t)hk_fun;
		}

		pExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		DWORD dwOld;
		VirtualProtect((LPVOID)og_fun, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


bool LeoHook::AreInSamePage(const uint8_t* Addr1, const uint8_t* Addr2)
{
	MEMORY_BASIC_INFORMATION mbi1;
	if (!VirtualQuery(Addr1, &mbi1, sizeof(mbi1)))
		return true;

	MEMORY_BASIC_INFORMATION mbi2;
	if (!VirtualQuery(Addr2, &mbi2, sizeof(mbi2)))
		return true;

	if (mbi1.BaseAddress == mbi2.BaseAddress)
		return true;

	return false;
}