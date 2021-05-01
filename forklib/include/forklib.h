#pragma once

#include <Windows.h>
#include <winternl.h>

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllimport) DWORD fork(_Out_ LPPROCESS_INFORMATION lpProcessInformation);
    __declspec(dllimport) BOOL EnumerateProcessHandles(void(*)(HANDLE, POBJECT_TYPE_INFORMATION, PUNICODE_STRING));
    __declspec(dllimport) BOOL MarkAllHandles();
	__declspec(dllimport) BOOL SuspendOtherThreads();
#ifdef __cplusplus
}
#endif

