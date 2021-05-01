#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include <conio.h>
#include <psapi.h>
#include <dbghelp.h>

#include <stdbool.h>

DWORD get_all_modules(HANDLE child_handle, HMODULE **modules);

HMODULE FindModule(HANDLE hProcess, const char* szModuleName);

HMODULE InjectDll(HANDLE hProcess, LPCSTR szDllFilename);

void *get_entrypoint(HANDLE child_handle, void *base_address);

DWORD get_proc_offset(char *data, char *name);

PIMAGE_NT_HEADERS map_pe_file(LPCSTR szPath, LPVOID* lpBase, HANDLE* hMapping, HANDLE* hFile);

DWORD get_entry_point(LPCSTR szPath);

DWORD GetModuleBaseAddress(DWORD pid, char* DLLName);

HMODULE find_module(HANDLE hProcess, const char* szModuleName);
