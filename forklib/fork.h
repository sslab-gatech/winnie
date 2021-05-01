#pragma once

extern "C"
{
	__declspec(dllexport) DWORD fork(_Out_ LPPROCESS_INFORMATION lpProcessInformation);

	__declspec(dllexport) BOOL EnumerateProcessHandles(void(*callback)(HANDLE, POBJECT_TYPE_INFORMATION, PUNICODE_STRING));

	__declspec(dllexport) BOOL MarkAllHandles();

	__declspec(dllexport) BOOL SuspendOtherThreads();
}
