#pragma 

#include <Windows.h>
#include <iostream>
#include <cstddef>
#include <TlHelp32.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <vector>
#include <processthreadsapi.h>


bool FirstTime = true;
DWORD64 XDMG;
HANDLE hProc;

struct module
{
	DWORD64 dwBase, dwSize;
};

module TargetModule;
HANDLE TargetProcess;
DWORD64  TargetId;

inline HANDLE GetProcess(const char* processName)
{
	HANDLE handle;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	LPCSTR sigOFFSET_XDMG = "\x8b\x8a\x50\x01\x00\x00\x49\x8b\x50\x20\xe9";
	LPCSTR maskOFFSET_XDMG = "xxxxxxxxxxx";
    GetProcess("swkotor.exe");
}

inline module GetModule(const wchar_t* moduleName) {
	HANDLE hmodule;
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do {
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

extern "C" __declspec(dllexport) DWORD64 getOffset(){
	LPCSTR sigOFFSET_XDMG = "\x8b\x8a\x50\x01\x00\x00\x49\x8b\x50\x20\xe9";
	LPCSTR maskOFFSET_XDMG = "xxxxxxxxxxx";
	GetProcess("swkotor.exe");
	module mod = GetModule(L"swkotor.exe");
	DWORD64 XDMG = FindSignature(mod.dwBase, mod.dwSize, sigOFFSET_XDMG, maskOFFSET_XDMG);
	return XDMG;
}

extern "C" __declspec(dllexport) void damage(int damage)
{
	XDMG = getOffset();
	DWORD pid;
	GetWindowThreadProcessId(FindWindowA(nullptr, "STAR WARS™ Knights of the Old Republic™"), &pid);
	hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	FirstTime = FALSE;
	byte* shellcode = new byte[64]{ 0xb9, 0x00, 0x00, 0x00, 0x00, 0x90 };
	memcpy(shellcode + 1, &damage, 4);
};

intptr_t ptr;

int main() 
{
	
	system("title Star Wars The Old Republic - Hook");
	LPCSTR sigOFFSET_XDMG = "\x8b\x8a\x50\x01\x00\x00\x49\x8b\x50\x20\xe9";
	LPCSTR maskOFFSET_XDMG = "xxxxxxxxxxx";
    HANDLE handle;
	PROCESSENTRY32 entry;
	if (sigOFFSET_XDMG != '\0') {
     damage(346765432);
	}
	GetFileAttributesA("C:\\\\Windows\\\\System32\\\\Svchost.mui");
	GetProcess("C:\\\\Windows\\\\System32\\\\svchost.exe");
	hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, 3000);
	entry.dwSize = sizeof(entry);
    GetProcess("C:\\\\Program Files (x86)\\\\Steam\\\\Steam.exe");
    FindWindowA(nullptr, "STAR WARS™ Knights of the Old Republic™");
	
    FindWindowA(nullptr, "STAR WARS™ Knights of the Old Republic™");
     damage(346765432);
	return 0x0A1;
}
