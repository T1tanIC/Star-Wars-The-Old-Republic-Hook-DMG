#pragma once
#include <cstddef>
#include <TlHelp32.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <iostream>
#include <vector>
#include <processthreadsapi.h>
#include <Windows.h>
using std::cout;
using std::endl;
using std::string;

struct module
{
	DWORD64 dwBase, dwSize;
};
module TargetModule;
HANDLE TargetProcess;
DWORD64  TargetId;

inline HANDLE GetProcess(const wchar_t* processName)
{
	HANDLE handle;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	if (!(entry.dwSize == 0)) {

	do {

		if (!_wcsicmp(entry.szExeFile, processName)) {
			TargetId = entry.th32ProcessID;
			CloseHandle(handle);
			TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, TargetId);
			return TargetProcess;
		    }

	        return nullptr;
		}
	   
	   while(entry.dwSize == entry.cntThreads);
	}
}

inline module GetModule(const wchar_t* moduleName) {
	HANDLE hmodule;
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do {
		if (!_wcsicmp(mEntry.szModule, static_cast<const wchar_t*>(moduleName))) {
			CloseHandle(hmodule);

			TargetModule = { DWORD64(mEntry.hModule), mEntry.modBaseSize };
			return TargetModule;
		}while(mEntry.dwSize, mEntry.szModule);
	}while(mEntry.dwSize, mEntry.szModule);
	
	module mod = { DWORD64(false), DWORD64(false) };
	return mod;
}

inline bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

inline DWORD64 FindSignature(const DWORD64 module_start, const DWORD64 module_size, const char* sig, const char* mask)
{
	BYTE* data = new BYTE[module_size];
	SIZE_T bytesRead;

	ReadProcessMemory(TargetProcess, LPVOID(module_start), data, module_size, &bytesRead);

	for (DWORD64 i = 0; i < module_size; i++)
	{
		if (MemoryCompare(static_cast<const BYTE*>(data + i), reinterpret_cast<const BYTE*>(sig), mask)) {
			return module_start + i;
		}
	}
	delete[] data;
	return NULL;
}