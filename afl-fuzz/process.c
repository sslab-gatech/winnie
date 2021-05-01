// Child process manager
//
// This file provides utilities for interacting with the child process through debug Win32 APIs.

#include <Windows.h>
#include <tlhelp32.h>
#include <conio.h>
#include <psapi.h>
#include <dbghelp.h>

#include <stdbool.h>

#include "debug.h"
#include "process.h"

// returns an array of handles for all modules loaded in the target process
DWORD get_all_modules(HANDLE child_handle, HMODULE **modules) {	
    DWORD module_handle_storage_size = 1024 * sizeof(HMODULE);
    HMODULE *module_handles = (HMODULE *)malloc(module_handle_storage_size);
    DWORD hmodules_size;
    while (true) {
        if (!EnumProcessModulesEx(child_handle, module_handles, module_handle_storage_size, &hmodules_size, LIST_MODULES_ALL)) {
            FATAL("EnumProcessModules failed, %x\n", GetLastError());
        }
        if (hmodules_size <= module_handle_storage_size) break;
        module_handle_storage_size *= 2;
        module_handles = (HMODULE *)realloc(module_handles, module_handle_storage_size);
    }
    *modules = module_handles;
	//SAYF("Get all modules:%d\n", hmodules_size / sizeof(HMODULE));
    return hmodules_size / sizeof(HMODULE);
}

HMODULE FindModule(HANDLE hProcess, const char* szModuleName)
{
	HMODULE* hMods;
	size_t nModules = get_all_modules(hProcess, &hMods);
	HMODULE result = NULL;
	for (unsigned int i = 0; i < nModules; i++)
	{
		char szModName[MAX_PATH];
		if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
		{
			if (!_stricmp(szModuleName, szModName))
			{
				result = hMods[i];
				break;
			}
		}
	}
	free(hMods);
	return result;
}

HMODULE InjectDll(HANDLE hProcess, LPCSTR szDllFilename)
{
	LPVOID pMem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem)
	{
		dank_perror("VirtualAllocEx");
		return NULL;
	}
	//trace_printf("pMem = 0x%p\n", pMem);

	BOOL bSuccess = WriteProcessMemory(hProcess, pMem, szDllFilename, strlen(szDllFilename) + 1, NULL);
	if (!bSuccess)
	{
		dank_perror("WriteProcessMemory");
		return NULL;
	}
	//trace_printf("Wrote %s\n", szDllFilename);

	LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
	trace_printf("LoadLibraryA = 0x%p\n", pLoadLibraryA);
	DWORD dwThreadId;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryA, pMem, 0, &dwThreadId);
	if (!hThread)
	{
		dank_perror("CreateRemoteThread");
		return NULL;
	}
	//trace_printf("Thread created, ID = %d\n", dwThreadId);	

	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
	{
		dank_perror("WaitForSingleObject");
		return NULL;
	}
	Sleep(100);
	//trace_printf("Success\n");
	CloseHandle(hThread);

	return FindModule(hProcess, szDllFilename);
}

// parses PE headers and gets the module entypoint
void *get_entrypoint(HANDLE child_handle, void *base_address) {
    unsigned char headers[4096];
    size_t num_read = 0;
    if (!ReadProcessMemory(child_handle, base_address, headers, 4096, &num_read) || (num_read != 4096)) {
        FATAL("Error reading target memory\n");
    }
	IMAGE_DOS_HEADER* dos_header = headers;
	DWORD pe_offset = dos_header->e_lfanew;
    IMAGE_NT_HEADERS* nt_header = headers + pe_offset;
	DWORD signature = nt_header->Signature;
    if (signature != IMAGE_NT_SIGNATURE) {
        FATAL("PE signature error\n");
    }
	IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;
	WORD magic = optional_header->Magic;
    if ((magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
        FATAL("Unknown PE magic value\n");
    } 
	DWORD entrypoint_offset = optional_header->AddressOfEntryPoint;
    if (entrypoint_offset == 0) return NULL;
    return (char *)base_address + entrypoint_offset;
}

// GetProcAddress that works on another process (via parsing PE header)
DWORD get_proc_offset(char* data, char *name) {
	IMAGE_DOS_HEADER* dos_header = data;
	DWORD pe_offset = dos_header->e_lfanew;
    IMAGE_NT_HEADERS* nt_header = data + pe_offset;
	DWORD signature = nt_header->Signature;
    if (signature != IMAGE_NT_SIGNATURE) {
        FATAL("PE signature error\n");
    }
	IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;
	// Note: DataDirectory offset varies by PE32/PE64, so only native architecture is supported
	if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		FATAL("Wrong PE magic value\n");
	}

	IMAGE_EXPORT_DIRECTORY* export_table = data + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD numentries = export_table->NumberOfNames;
	DWORD addresstableoffset = export_table->AddressOfFunctions;
	DWORD nameptrtableoffset = export_table->AddressOfNames;
    DWORD ordinaltableoffset = export_table->AddressOfNameOrdinals;
    DWORD *nameptrtable = (DWORD *)(data + nameptrtableoffset);
    WORD *ordinaltable = (WORD *)(data + ordinaltableoffset);
    DWORD *addresstable = (DWORD *)(data + addresstableoffset);

    DWORD i;
    for (i = 0; i < numentries; i++) {
        char *nameptr = data + nameptrtable[i];
        if (strcmp(name, nameptr) == 0) break;
    }

    if (i == numentries) return 0;

    WORD ordinal = ordinaltable[i];
    DWORD offset = addresstable[ordinal];

    return offset;
}

PIMAGE_NT_HEADERS map_pe_file(LPCSTR szPath, LPVOID* lpBase, HANDLE* hMapping, HANDLE* hFile)
{
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
	DWORD dwEntryPoint = 0;
	HANDLE hMapping = INVALID_HANDLE_VALUE, hFile = INVALID_HANDLE_VALUE;
	BYTE* lpBase = NULL;
	PIMAGE_NT_HEADERS ntHeader = map_pe_file(szPath, (LPVOID*)&lpBase, &hMapping, &hFile);
	if (ntHeader) {
		dwEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
	} else {
		FATAL("Cannot parse the PEfile!");
	}

	if (lpBase) UnmapViewOfFile((LPCVOID)lpBase);
	if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return dwEntryPoint;
}

DWORD GetModuleBaseAddress(DWORD pid, char* DLLName) {
	HANDLE hSnap;
	MODULEENTRY32 xModule;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	xModule.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &xModule)) {
		while (Module32Next(hSnap, &xModule)) {
			if (strcmp(xModule.szModule, DLLName) == 0) {
				CloseHandle(hSnap);
				return (DWORD)xModule.modBaseAddr;
			}
		}
	}

	CloseHandle(hSnap);
	return 0;
}

HMODULE find_module(HANDLE hProcess, const char* szModuleName)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		FATAL("Failed to enumerate process modules, GLE=%d.\n", GetLastError());
		return NULL;
	}

	for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
	{
		char mod_name[MAX_PATH];
		if (GetModuleBaseNameA(hProcess, hMods[i], mod_name, sizeof(mod_name) / sizeof(char)))
			if (strstr(szModuleName, mod_name) != NULL)
				return hMods[i];
	}
	return NULL;
}
