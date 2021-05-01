#include "stdafx.h"
#include "csrss.h"

static HMODULE ntdll = GetModuleHandleA("ntdll.dll");
CsrClientConnectToServer_t CsrClientConnectToServer = (CsrClientConnectToServer_t)GetProcAddress(ntdll, "CsrClientConnectToServer");
CsrClientCallServer_t CsrClientCallServer = (CsrClientCallServer_t)GetProcAddress(ntdll, "CsrClientCallServer");
CsrClientCallServer64_t CsrClientCallServer64 = (CsrClientCallServer64_t)CsrClientCallServer;
