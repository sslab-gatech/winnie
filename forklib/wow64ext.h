#pragma once

extern "C"
{
	extern __declspec(dllimport) DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
	extern __declspec(dllimport) DWORD64 __cdecl GetModuleHandle64(wchar_t* lpModuleName);
	extern __declspec(dllimport) void __cdecl getMem64(void* dstMem, DWORD64 srcMem, size_t sz);
	extern __declspec(dllimport) void __cdecl setMem64(DWORD64 dstMem, void* srcMem, size_t sz);
}
