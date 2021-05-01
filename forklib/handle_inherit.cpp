#include "stdafx.h"
#include <TlHelp32.h>
#include <stdlib.h>

#ifndef _DEBUG
#define printf(...)
#define DebugBreak()
#else
#include <stdio.h>
#endif

#include "fork.h"

// This method simply iterates through all of the handles that are opened by the
// current process, and call a callback on each one. This can also be used for
// closing any dangling or leaked file handles to the input binary that we are
// mutating in the fuzzer.
extern "C" BOOL EnumerateProcessHandles(void(*callback)(HANDLE, POBJECT_TYPE_INFORMATION, PUNICODE_STRING)) {
	printf("TEST\n");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle = GetCurrentProcess();
	ULONG i;

	handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(handleInfoSize);

	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size.
	while ((status = NtQuerySystemInformation(
		SystemExtendedHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)realloc(handleInfo, handleInfoSize *= 2);

	// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
	if (!NT_SUCCESS(status)) {
		printf("NtQuerySystemInformation failed!\n");
		DebugBreak();
		return FALSE;
	}

	printf("WOW, %d\n", handleInfo->NumberOfHandles);
	for (i = 0; i < handleInfo->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = handleInfo->Handles[i];
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		ULONG returnLength;
		
		// Check if this handle belongs to the PID the user specified.
		if (handle.UniqueProcessId != GetCurrentProcessId())
			continue;

		// we don't need to duplicate ... these are OUR handles lol
		HANDLE handleValue = (HANDLE)handle.HandleValue;

		// Query the object type.
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			handleValue,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		))) {
			printf("[%#x] Error!\n", handle.HandleValue);
			continue;
		}

		// Query the object name (unless it has an access of
		//   0x0012019f, on which NtQueryObject could hang.
		if (handle.GrantedAccess == 0x0012019f) {
			// We have the type, so display that.
			callback(handleValue, objectTypeInfo, NULL);
			free(objectTypeInfo);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			handleValue,
			ObjectNameInformation,
			objectNameInfo,
			0x1000,
			&returnLength
		))) {
			// Reallocate the buffer and try again.
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(
				handleValue,
				ObjectNameInformation,
				objectNameInfo,
				returnLength,
				NULL
			))) {

				// We have the type name, so just display that.
				callback(handleValue, objectTypeInfo, NULL);

				free(objectTypeInfo);
				free(objectNameInfo);
				continue;
			}
		}

		// Cast our buffer into an UNICODE_STRING.
		callback(handleValue, objectTypeInfo, (PUNICODE_STRING)objectNameInfo);

		free(objectTypeInfo);
		free(objectNameInfo);
	}

	free(handleInfo);

	return 0;
}

// Marks a handle as inheritable by child (as handles are not inherited
// by children by default on Windows), and also mark them as uncloseable
// to prevent the forked child from closing any important handles. We
// don't know what the fuzzing target will do, and we need to make sure
// that we can reuse the same handles over and over again in our forkserver.
void markHandle(HANDLE handle, POBJECT_TYPE_INFORMATION, PUNICODE_STRING)
{
	//SetHandleInformation(handle, HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE);
	SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
}

// Mark all handles inheritble and uncloseable. See markHandle for more info.
// This should be called just before starting the forkserver.
extern "C" BOOL MarkAllHandles() {
	//printf("Markall\n");
	return EnumerateProcessHandles(markHandle);
	//return TRUE;
}

extern "C" BOOL SuspendOtherThreads()
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);
	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return FALSE;
	}
	do
	{
		if (te32.th32OwnerProcessID == GetCurrentProcessId())
		{
			if (te32.th32ThreadID != GetCurrentThreadId())
			{
				printf("Yeet thread %d\n", te32.th32ThreadID);
				HANDLE hYeet = OpenThread(THREAD_TERMINATE|THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
				SuspendThread(hYeet);
				CloseHandle(hYeet);
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));
	printf("Yeeted\n");

	CloseHandle(hThreadSnap);
	return TRUE;
}
