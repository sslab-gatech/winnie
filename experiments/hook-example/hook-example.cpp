#include "pch.h"
#include <Psapi.h>
#include <stdio.h>
#include <conio.h>

#include "../forkserver-proto.h"

#define FATAL(f, ...) {printf(f ": %d\n", ##__VA_ARGS__##, GetLastError()); getc(stdin); ExitProcess(GetLastError()); }

#define dank_perror(msg) { \
	LPCSTR _errorText = NULL; \
	FormatMessageA( \
		FORMAT_MESSAGE_FROM_SYSTEM \
		| FORMAT_MESSAGE_ALLOCATE_BUFFER \
		| FORMAT_MESSAGE_IGNORE_INSERTS, \
		NULL, \
		GetLastError(), \
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), \
		(LPSTR)&_errorText, \
		0, \
		NULL); \
	if (_errorText) \
	{ \
		FATAL(msg " failed: %s", _errorText); \
		LocalFree((HLOCAL) _errorText); \
		_errorText = NULL; \
	} \
	else \
	{ \
		FATAL(msg " failed"); \
	} \
}

HMODULE FindModule(HANDLE hProcess, const char* szModuleName)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		dank_perror("EnumProcessModules");
		return NULL;
	}
	for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
	{
		char szModName[MAX_PATH];
		if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
		{
			if (!_stricmp(szModuleName, szModName))
			{
				return hMods[i];
			}
		}
	}
	return NULL;
}

PIMAGE_NT_HEADERS map_pe_file(LPCSTR szPath, LPVOID* lpBase, HANDLE* hMapping, HANDLE* hFile)
{
	BY_HANDLE_FILE_INFORMATION bhfi;
	*hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (*hFile == INVALID_HANDLE_VALUE) {
		FATAL("Invalid handle when map PE file");
		return NULL;
	}

	*hMapping = CreateFileMappingA(*hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);

	if (!*hMapping) {
		FATAL("Cannot make file mapping");
		return NULL;
	}

	*lpBase = (char *)MapViewOfFile(*hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!*lpBase) {
		FATAL("Cannot make MapViewOfFile");
		return NULL;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)*lpBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		FATAL("IMAGE_DOS_SIGNATURE not matched");
		return NULL;
	}

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)*lpBase + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		FATAL("IMAGE_NT_SIGNATURE not matched");
		return NULL;
	}

	return ntHeader;
}

DWORD get_entry_point(LPCSTR szPath)
{
	DWORD dwEntryPoint = NULL;
	HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
	BYTE* lpBase = NULL;
	PIMAGE_NT_HEADERS ntHeader = map_pe_file(szPath, (LPVOID*)&lpBase, &hMapping, &hFile);
	if (ntHeader)
	{
		dwEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
	}
	else {
		FATAL("Cannot parse the PEfile!");
	}

	if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
	if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return dwEntryPoint;
}

// GetProcAddress that works on another process
DWORD get_proc_offset(char *data, char *name) {
	DWORD pe_offset;
	pe_offset = *((DWORD *)(data + 0x3C));
	char *pe = data + pe_offset;
	DWORD signature = *((DWORD *)pe);
	if (signature != 0x00004550) {
		return 0;
	}
	pe = pe + 0x18;
	WORD magic = *((WORD *)pe);
	DWORD exporttableoffset;
	if (magic == 0x10b) {
		exporttableoffset = *(DWORD *)(pe + 96);
	}
	else if (magic == 0x20b) {
		exporttableoffset = *(DWORD *)(pe + 112);
	}
	else {
		return 0;
	}

	if (!exporttableoffset) return 0;
	char *exporttable = data + exporttableoffset;

	DWORD numentries = *(DWORD *)(exporttable + 24);
	DWORD addresstableoffset = *(DWORD *)(exporttable + 28);
	DWORD nameptrtableoffset = *(DWORD *)(exporttable + 32);
	DWORD ordinaltableoffset = *(DWORD *)(exporttable + 36);
	DWORD *nameptrtable = (DWORD *)(data + nameptrtableoffset);
	WORD *ordinaltable = (WORD *)(data + ordinaltableoffset);
	DWORD *addresstable = (DWORD *)(data + addresstableoffset);

	DWORD i;
	for (i = 0; i < numentries; i++) {
		char *nameptr = data + nameptrtable[i];
		if (strcmp(name, nameptr) == 0) break;
	}

	if (i == numentries) return 0;

	WORD oridnal = ordinaltable[i];
	DWORD offset = addresstable[oridnal];

	return offset;
}

HMODULE InjectDll(HANDLE hProcess, LPCSTR szDllFilename)
{
	LPVOID pMem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem)
	{
		dank_perror("VirtualAllocEx");
		return NULL;
	}
	printf("pMem = 0x%p\n", pMem);

	BOOL bSuccess = WriteProcessMemory(hProcess, pMem, szDllFilename, strlen(szDllFilename) + 1, NULL);
	if (!bSuccess)
	{
		dank_perror("WriteProcessMemory");
		return NULL;
	}
	printf("Wrote %s\n", szDllFilename);

	LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
	printf("LoadLibraryA = 0x%p\n", pLoadLibraryA);
	DWORD dwThreadId;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryA, pMem, 0, &dwThreadId);
	if (!hThread)
	{
		dank_perror("CreateRemoteThread");
		return NULL;
	}
	printf("Thread created, ID = %d\n", dwThreadId);

	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
	{
		dank_perror("WaitForSingleObject");
		return NULL;
	}
	Sleep(100);
	printf("Success\n");

	return FindModule(hProcess, szDllFilename);
}

#define HARNESS_DLL "forkserver.dll"
#define DRYRUN_DLL "dryrun.dll"
#define SYNC_EVENT_NAME "Global\\harness-sync"

int main()
{
	// The process to start and inject into
	char* targetProgram = "toy_example\\math3.exe";
	char* argvs = "toy_example\\math3.exe toy_example\\in\\input";
	BOOL dryrun = FALSE;

	printf("Spawning the forkserver.\n");
	
	// Spawn the process suspended. We can't inject immediately, however. Need to let the program initialize itself before we can load a library.
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	RtlZeroMemory(&pi, sizeof(pi));
	RtlZeroMemory(&si, sizeof(si));
	BOOL success = CreateProcessA(NULL, argvs, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);
	if (!success)
	{
		dank_perror("CreateProcessA");
		return 1;
	}

	// Derive entrypoint address from PEB and PE header
	CONTEXT context;
	context.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi.hThread, &context);
	uintptr_t pebAddr, dwBaseAddr = 0;
#ifdef _WIN64
	pebAddr = context.Rdx;
	ReadProcessMemory(pi.hProcess, (PVOID)(pebAddr + 0x10), &dwBaseAddr, sizeof(dwBaseAddr), NULL);
#else
	pebAddr = context.Ebx;
	ReadProcessMemory(pi.hProcess, (PVOID)(pebAddr + 8), &dwBaseAddr, sizeof(dwBaseAddr), NULL);
#endif
	printf("peb=%p, base address=%p\n", pebAddr, dwBaseAddr);

	uintptr_t oep = get_entry_point(targetProgram);
	printf("oep=%x\n", oep);
	uintptr_t pEntryPoint = oep + dwBaseAddr;
	if (!pEntryPoint)
	{
		dank_perror("GetEntryPoint");
		return 1;
	}
	printf("entrypoint = %p\n", pEntryPoint);

	// assemble infinite loop at entrypoint
	DWORD dwOldProtect;
	VirtualProtectEx(pi.hProcess, (PVOID)pEntryPoint, 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	BYTE oepBytes[2];
	ReadProcessMemory(pi.hProcess, (PVOID)pEntryPoint, oepBytes, 2, NULL);
	WriteProcessMemory(pi.hProcess, (PVOID)pEntryPoint, "\xEB\xFE", 2, NULL);
	ResumeThread(pi.hThread);

	// Poll the instruction pointer until it reached the entrypoint, or time out.
#ifdef _WIN64
	for (int i = 0; context.Rip != pEntryPoint; Sleep(100))
#else
	for (int i = 0; context.Eip != pEntryPoint; Sleep(100))
#endif
	{
		if (++i > 50)
		{
			TerminateProcess(pi.hProcess, -1);
			perror("entrypoint trap trimed out\n");
		}
		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(pi.hThread, &context);
	}
	printf("entrypoint trap hit, injecting the dll now!\n");
	SuspendThread(pi.hThread);

	// Event for synchronizing with the harness.
	HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, SYNC_EVENT_NAME);
	
	// Actually inject the dll now.
	char* injectedDll = dryrun ? DRYRUN_DLL : HARNESS_DLL;
	char szDllFilename[MAX_PATH];
	GetCurrentDirectoryA(sizeof(szDllFilename) - 1, szDllFilename);
	strncat(szDllFilename, "\\", max(0, MAX_PATH - strlen(szDllFilename) - 1));
	strncat(szDllFilename, injectedDll, max(0, MAX_PATH - strlen(szDllFilename) - 1));
	printf("injecting %s\n", szDllFilename);
	HMODULE hModule = InjectDll(pi.hProcess, szDllFilename);
	if (!hModule)
	{
		perror("InjectDll");
		return 1;
	}
	printf("harness dll injected, base address = %p\n", hModule);

	// Write coverage info
	HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
	BYTE* lpBase = NULL;
	PIMAGE_NT_HEADERS ntHeader = map_pe_file(injectedDll, (LPVOID*)&lpBase, &hMapping, &hFile);
	if (!ntHeader)
		FATAL("Failed to parse export table of %s", injectedDll);
	
	DWORD off_num_basicblocks = get_proc_offset((char*)lpBase, "num_basicblocks");
	DWORD off_arr_basicblocks = get_proc_offset((char*)lpBase, "arr_basicblocks");

	if (!off_num_basicblocks || !off_arr_basicblocks)
		FATAL("Fail to find num_basicblocks and arr_basicblocks in injected dll\n");
	printf("num_basicblocks offset = %08x, arr_basicblocks offset = %08x\n", off_num_basicblocks, off_arr_basicblocks);
	
	LPVOID pNum_basicblocks = (LPVOID)((uintptr_t)hModule + off_num_basicblocks);
	LPVOID pArr_basicblocks = (LPVOID)((uintptr_t)hModule + off_arr_basicblocks);
	printf("num_basicblocks = %p, arr_basicblocks = %p\n", pNum_basicblocks, pArr_basicblocks);

	// dummy data
	LPVOID some_array[] = { (LPVOID)(dwBaseAddr+0x1105) };
	size_t numberofbasicblocks = ARRAYSIZE(some_array);
	
	LPVOID* basicblock_addresses = some_array;
	if (!WriteProcessMemory(pi.hProcess, pNum_basicblocks, &numberofbasicblocks, sizeof(size_t), NULL))
	{
		dank_perror("Failed to write number of basic blocks into child");
	}			
	size_t arr_size = sizeof(LPVOID) * numberofbasicblocks;
	LPVOID pMem = VirtualAllocEx(pi.hProcess, NULL, arr_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem)
	{
		dank_perror("Failed to allocate basic blocks list into child");
	}
	if (!WriteProcessMemory(pi.hProcess, pMem, some_array, arr_size, NULL))
	{
		dank_perror("Failed to write basic blocks list into child");
	}

	if (!WriteProcessMemory(pi.hProcess, pArr_basicblocks, &pMem, sizeof(LPVOID*), NULL))
	{
		dank_perror("Failed to write number of basic blocks into child");
	}
	
	if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
	if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	// Signal to harness that coverage info is written
	SetEvent(hEvent);

	// Wait for harness to setup hooks before we resume the main thread.
	if (WaitForSingleObject(hEvent, INFINITE) == WAIT_FAILED)
	{
		perror("WaitForSingleObject");
		return 1;
	}
	printf("Ok, the harness is ready. Resuming the main thread now.\n");

	// a possible problem is if the injected harness overwrites pEntryPoint before we restore oepBytes.
	// to deal with that just check that nothing edited that code before we restore it.
	WriteProcessMemory(pi.hProcess, (PVOID)pEntryPoint, oepBytes, 2, NULL);
	DWORD trash;
	VirtualProtectEx(pi.hProcess, (PVOID)pEntryPoint, 2, dwOldProtect, &trash);
	ResumeThread(pi.hThread);

	printf("Connecting to forkserver...\n");
	HANDLE hPipeForkserver;
	do
	{
		hPipeForkserver = CreateFileA(AFL_FORKSERVER_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipeForkserver == INVALID_HANDLE_VALUE)
		{
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				Sleep(10);
				continue;
			}
			dank_perror("CreateFileA");
		}
	} while (hPipeForkserver == INVALID_HANDLE_VALUE);
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	if (!SetNamedPipeHandleState(hPipeForkserver, &dwMode, NULL, NULL))
	{
		dank_perror("SetNamedPipeHandleState");
	}
		
	for (int i = 0 ; i < 3; i++)
	{
		printf("Iteration %d\n", i);		
		AFL_FORKSERVER_REQUEST forkserverRequest;
		forkserverRequest.Operation = AFL_CREATE_NEW_CHILD;
		DWORD nWritten;
		if (!WriteFile(hPipeForkserver, &forkserverRequest, sizeof(forkserverRequest), &nWritten, NULL) || nWritten != sizeof(forkserverRequest))
		{
			FATAL("Broken forkserver pipe, WriteFile");
		}

		AFL_FORKSERVER_RESULT forkserverResult;
		do
		{
			if (!ReadFile(hPipeForkserver, &forkserverResult, sizeof(forkserverResult), &nWritten, NULL) || nWritten != sizeof(forkserverResult))
			{
				FATAL("Broken forkserver pipe, ReadFile (main)");
			}
			if (forkserverResult.StatusCode == AFL_CHILD_COVERAGE)
			{
				printf("Got coverage: %s+%p\n", forkserverResult.CoverageInfo.ModuleName, forkserverResult.CoverageInfo.Rva);
			}
		} while (forkserverResult.StatusCode == AFL_CHILD_COVERAGE);
		printf("Result from forkserver: %d\n", forkserverResult.StatusCode);
	}
	
	printf("Done.\n");
	return 0;
}
