#include "pch.h"
#pragma warning(disable:4996)
#include <stdint.h>
#include <stdio.h>
#include <tchar.h>
#include <pathcch.h>

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
		printf(msg " failed: %s\n", _errorText); \
		LocalFree((HLOCAL) _errorText); \
		_errorText = NULL; \
	} \
	else \
	{ \
		printf(msg " failed\n"); \
	} \
}

#define SafeCloseHandle(h) {if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }

void handle_exception(DWORD pid, PMINIDUMP_EXCEPTION_STREAM ExceptionInfo, LPVOID pMinidump)
{
	PCONTEXT ContextRecord = (CONTEXT*)(((LPBYTE)pMinidump) + ExceptionInfo->ThreadContext.Rva);

	uint64_t faultAddress = NULL;
	if (ExceptionInfo->ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// ExceptionInformation[0] is 1 for write fault, 0 for read fault.
		faultAddress = ExceptionInfo->ExceptionRecord.ExceptionInformation[1];
	}
	printf("Process %d: Uncaught exception %08x at instruction %llx, referencing %llx\n",
		pid,
		ExceptionInfo->ExceptionRecord.ExceptionCode,
		ExceptionInfo->ExceptionRecord.ExceptionAddress,
		faultAddress
		);
}

// mainly inspired by https://github.com/doo/CrashRpt/blob/master/trunk/processing/crashrptprobe/MinidumpReader.cpp
void parse_minidump(DWORD pid, LPCWSTR filename)
{
	printf("Parsing minidump %ls (pid %d)\n", filename, pid);
	
	HANDLE hFile = NULL, hMapping = NULL;
	LPVOID pMinidump = NULL;
	PMINIDUMP_EXCEPTION_STREAM pExceptionStream;
	
	while ((hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_SHARING_VIOLATION)
		{
			// File busy
			Sleep(10);
			continue;
		}
		dank_perror("CreateFile");
		goto fail;
	}
	printf("hFile = %x\n", hFile);

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapping)
	{
		dank_perror("CreateFileMapping");
		goto fail;
	}
	printf("hMapping = %x\n", hMapping);

	pMinidump = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMinidump)
	{
		dank_perror("MapViewOfFile");
		goto fail;
	}
	printf("Minidump mapped at = %p\n", pMinidump);

	PMINIDUMP_DIRECTORY pmd;
	LPVOID pStream;
	ULONG streamSize;
	if (!MiniDumpReadDumpStream(pMinidump, ExceptionStream, &pmd, &pStream, &streamSize))
	{
		dank_perror("MiniDumpReadDumpStream");
		goto fail;
	}

	pExceptionStream = (MINIDUMP_EXCEPTION_STREAM*)pStream;
	if (!pExceptionStream || streamSize < sizeof(MINIDUMP_EXCEPTION_STREAM))
	{
		printf("Corrupt minidump exception info\n");
		goto fail;
	}

	handle_exception(pid, pExceptionStream, pMinidump);
	
	fail:
	if (pMinidump) UnmapViewOfFile(pMinidump);
	SafeCloseHandle(hMapping);
	SafeCloseHandle(hFile);
}

int parse_minidump_filename_pid(LPCWSTR filename)
{
	WCHAR pid[MAX_PATH];
	int len = wcslen(filename);
	if (wcscmp(filename + len - 4, L".dmp")) return -1;
	int i = len - 4;
	while (i-->0 && filename[i] != L'.');
	if (i < 0) return -1;
	if (i == 0) return -1;
	wcsncpy_s(pid, filename + i + 1, len - 5 - i);
	return _wtoi(pid);
}

int main(int argc, char** argv)
{
	LPCSTR minidump_path = "C:\\sslab\\minidumps";
	if (argc > 1)
	{
		minidump_path = argv[1];
	}

	WCHAR minidump_dir[MAX_PATH];
	mbstowcs(minidump_dir, minidump_path, sizeof(minidump_dir));

	HANDLE hDirectory = CreateFileW(minidump_dir,  FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hDirectory == INVALID_HANDLE_VALUE)
	{
		dank_perror("CreateFile");
		return 1;
	}

	printf("OK, listening for minidumps\n");
#define BUFFER_SIZE 0x400
	BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, BUFFER_SIZE);
	FILE_NOTIFY_INFORMATION* notif = (FILE_NOTIFY_INFORMATION*)buffer;
	while (TRUE)
	{
		DWORD notifSize;
		RtlZeroMemory(buffer, BUFFER_SIZE);
		if (!ReadDirectoryChangesW(hDirectory, buffer, BUFFER_SIZE, FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE, &notifSize, NULL, NULL) || notifSize < sizeof(FILE_NOTIFY_INFORMATION))
		{
			dank_perror("ReadDirectoryChangesW");
			ExitProcess(GetLastError());
		}

		printf("%x %ls\n", notif->Action, notif->FileName);
		if (notif->Action == FILE_ACTION_MODIFIED)
		{
			int pid = parse_minidump_filename_pid(notif->FileName);
			if (pid <= 0)
			{
				printf("Couldn't parse pid from dump filename %ls\n", notif->FileName);
				continue;
			}
			WCHAR path[MAX_PATH];
			PathCchCombine(path, sizeof(path), minidump_dir, notif->FileName);
			parse_minidump(pid, path);
		}
	}
}
