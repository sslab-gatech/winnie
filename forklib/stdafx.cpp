#include "stdafx.h"

static HMODULE ntdll = GetModuleHandleA("ntdll.dll");
#define CACHE_PROC(mod, name) name##_t name = (name##_t)GetProcAddress(mod, #name)

CACHE_PROC(ntdll, NtQueryInformationProcess);
CACHE_PROC(ntdll, NtCreateUserProcess);
CACHE_PROC(ntdll, RtlRegisterThreadWithCsrss);
CACHE_PROC(ntdll, NtQuerySystemInformation);
CACHE_PROC(ntdll, NtQueryObject);
