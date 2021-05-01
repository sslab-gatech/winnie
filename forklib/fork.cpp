// todo: investigate why MessageBoxA doesnt work

#include "stdafx.h"
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#include "fork.h"

// Uncodumented headers csrss stuff
#include "csrss.h"

// ReWolf's library to fuck with 64-bit memory from 32-bit WoW64 programs
#ifndef _WIN64
#include "wow64ext.h"
#endif

#define _CRT_SECURE_NO_WARNINGS

#ifndef _DEBUG
#define printf(...)
#define DebugBreak()
#endif

// When a new child process is spawned, the parent must call
// CsrClientCallServer with API number BasepCreateProcess to notify
// the csrss subsystem of the new process. However, this seems to
// be optional as the child process will work without doing this
// call.
BOOL NotifyCsrssParent(HANDLE hProcess, HANDLE hThread)
{
	PROCESS_BASIC_INFORMATION info;
	if (!NT_SUCCESS(NtQueryInformationProcess(hProcess,
		ProcessBasicInformation, &info,
		sizeof(info), 0))) {
		printf("FORKLIB: NtQueryInformationProcess failed!\n");
		return FALSE;
	}

	BOOL bIsWow64;
	if (!IsWow64Process(GetCurrentProcess(), &bIsWow64))
	{
		printf("FORKLIB: IsWow64Process failed!\n");
		return FALSE;
	}

	NTSTATUS result;
	if (bIsWow64)
	{
		CSR_API_MSG64 csrmsg;
		RtlZeroMemory(&csrmsg, sizeof(csrmsg));
		csrmsg.CreateProcessRequest.PebAddressNative = (ULONGLONG)info.PebBaseAddress;
		csrmsg.CreateProcessRequest.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
		csrmsg.CreateProcessRequest.ProcessHandle = (ULONGLONG)hProcess;
		csrmsg.CreateProcessRequest.ThreadHandle = (ULONGLONG)hThread;
		csrmsg.CreateProcessRequest.ClientId.UniqueProcess = GetProcessId(hProcess);
		csrmsg.CreateProcessRequest.ClientId.UniqueThread = GetThreadId(hThread);
		//result = CsrClientCallServer64(&csrmsg, NULL, CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess), sizeof(csrmsg.CreateProcessRequest));
	}
	else
	{
		CSR_API_MSG csrmsg;
		RtlZeroMemory(&csrmsg, sizeof(csrmsg));
		csrmsg.CreateProcessRequest.PebAddressNative = info.PebBaseAddress;
#ifdef _WIN64
		csrmsg.CreateProcessRequest.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#else
		csrmsg.CreateProcessRequest.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif
		csrmsg.CreateProcessRequest.ProcessHandle = hProcess;
		csrmsg.CreateProcessRequest.ThreadHandle = hThread;
		csrmsg.CreateProcessRequest.ClientId.UniqueProcess = (HANDLE)GetProcessId(hProcess);
		csrmsg.CreateProcessRequest.ClientId.UniqueThread = (HANDLE)GetThreadId(hThread);
		//result = CsrClientCallServer(&csrmsg, NULL, CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess), sizeof(csrmsg.CreateProcessRequest));
	}

	/*
	if (!NT_SUCCESS(result))
	{
		printf("CsrClientCallServer(BasepCreateThread) failed!\n");
		return FALSE;
	}
	*/

	printf("FORKLIB: Successfully notified Csr of child!\n");
	return TRUE;
}

// When the a new process is spawned, it must call CsrClientConnectToServer
// and RtlRegisterThreadWithCsrss to connect to the various csrss subsystems
// (such as Windows subsystem, Console subsystem, etc). If this is not done,
// then nearly every function in the Win32 API will lead to segfault. It seems
// that internally the APIs depend on csrss in some way.
//
// j00ru documented csrss on his blog:
// https://j00ru.vexillium.org/2010/07/windows-csrss-write-up-inter-process-communication-part-1/
// https://j00ru.vexillium.org/2010/07/windows-csrss-write-up-inter-process-communication-part-2/
//
// However, our situation is even trickier than usual, since we are a *forked*
// process, meaning that all memory values are cloned from the parent process.
// This is important because CsrClientConnectToServer and RtlRegisterThreadWithCsrss
// seem to initialize some of the global variables in ntdll, and the two functions
// will not work if these variable are already initialized.
// Therefore, it's our responsibility to also *manually de-initialize* these
// global variables by zeroing them before reconnecting with csrss.
//
// Yet *another* complication is WoW64: WoW64 enables the execution of 32-bit
// executeables on 64-bit Windows. The program sees a 32-bit address space and
// the 32-bit version of all system dlls. However, the 32-bit ntdll is really just
// a shim to call the 64-bit version of all of the functions it exposes. In other
// words on WoW64, there are actually *two* copies of ntdll loaded: the 32-bit
// version exposed by WoW64, and the 64-bit version that is loaded into every
// process. Therefore, we need to de-initialize the global variables in *both the
// 64- and 32-bit version of ntdll*. This is accomplished using some tRicKErY
// by jumping to 64-bit code from 32-bit.
//
// This method only supports Windows 10. Somewhere between Windows 7 and Windows 10,
// Microsoft refactored Windows to rely less and less on csrss. Hence the API
// and structures are much simpler on Windows 10 than Windows 7, and as a result
// our job is much easier.
BOOL ConnectCsrChild()
{
	BOOL bIsWow64;
	if (!IsWow64Process(GetCurrentProcess(), &bIsWow64))
	{
		printf("FORKLIB: IsWow64Process failed!\n");
		return FALSE;
	}

	// Zero Csr fields???
	// Required or else Csr calls will crash
	printf("FORKLIB: De-initialize ntdll csr data\n");
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
#ifdef _WIN64
	void* pCsrData = (void*)((uintptr_t)ntdll + csrDataRva_x64); // HARDCODED OFFSET, see csrss_offsets.h
	printf("FORKLIB: Csr data = %p\n", pCsrData);
	memset(pCsrData, 0, csrDataSize_x64);
#else
	void* pCsrData = (void*)((uintptr_t)ntdll + csrDataRva_x86); // HARDCODED OFFSET,  see csrss_offsets.h
	printf("FORKLIB: Csr data = %p\n", pCsrData);
	memset(pCsrData, 0, csrDataSize_x86);

	if (bIsWow64)
	{
		DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
		printf("FORKLIB: ntdll 64 = %llx\n", ntdll64);
		char mem[csrDataSize_wow64];
		memset(mem, 0, sizeof(mem));
		DWORD64 pCsrData64 = ntdll64 + csrDataRva_wow64; // HARDCODED OFFSET, see csrss_offsets.h
		printf("FORKLIB: Csr data 64 = %llx\n", ntdll64);
		setMem64(pCsrData64, mem, sizeof(mem));
	}
#endif

	DWORD session_id;
	wchar_t ObjectDirectory[100];
	ProcessIdToSessionId(GetProcessId(GetCurrentProcess()), &session_id);		
	swprintf(ObjectDirectory, 100, L"\\Sessions\\%d\\Windows", session_id);		
	printf("FORKLIB: Session_id: %d\n", session_id);

	// Not required?
	printf("FORKLIB: Link Console subsystem...\n");
	void* pCtrlRoutine = (void*)GetProcAddress(GetModuleHandleA("kernelbase"), "CtrlRoutine");
	BOOLEAN trash;
	//if (!NT_SUCCESS(CsrClientConnectToServer(L"\\Sessions\\" CSRSS_SESSIONID L"\\Windows", 1, &pCtrlRoutine, 8, &trash)))
	if (!NT_SUCCESS(CsrClientConnectToServer(ObjectDirectory, 1, &pCtrlRoutine, 8, &trash)))
	{
		printf("FORKLIB: CsrClientConnectToServer failed!\n");
		return FALSE;
	}

	printf("FORKLIB: Link Windows subsystem...\n");
	// passing &gfServerProcess is not necessary, actually? passing &trash is okay?
	char buf[0x240]; // this seem to just be all zero everytime?
	memset(buf, 0, sizeof(buf));
	//if (!NT_SUCCESS(CsrClientConnectToServer(L"\\Sessions\\" CSRSS_SESSIONID L"\\Windows", 3, buf, 0x240, &trash)))
	if (!NT_SUCCESS(CsrClientConnectToServer(ObjectDirectory, 3, buf, 0x240, &trash)))
	{
		printf("FORKLIB: CsrClientConnectToServer failed!\n");
		return FALSE;
	}

	printf("FORKLIB: Connect to Csr...\n");
	if (!NT_SUCCESS(RtlRegisterThreadWithCsrss()))
	{
		printf("FORKLIB: RtlRegisterThreadWithCsrss failed!\n");
		return FALSE;
	}

	printf("FORKLIB: Connected to Csr!\n");
	return TRUE;
}

// Fix stdio handles of the child. If this isn't done, the child
// will inherit the stdio of the parent, and operations to those
// file descriptors will just not work.
void ReopenStdioHandles()
{
	freopen_s((FILE**)stdout, "CONOUT$", "w+", stdout);
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	freopen_s((FILE**)stderr, "CONOUT$", "w+", stdout);

	SetStdHandle(STD_INPUT_HANDLE, stdin);
	SetStdHandle(STD_OUTPUT_HANDLE, stdout);
	SetStdHandle(STD_ERROR_HANDLE, stderr);
}

#ifndef _WIN64
LONG WINAPI DiscardException(EXCEPTION_POINTERS *ExceptionInfo)
{
	printf("FORKLIB: Discarding exception %08x to %p, at instruction %08x\n",
		ExceptionInfo->ExceptionRecord->ExceptionCode,
		ExceptionInfo->ExceptionRecord->ExceptionAddress,
		ExceptionInfo->ContextRecord->Eip);
	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif

extern "C" DWORD fork(LPPROCESS_INFORMATION lpProcessInformation) {
	printf("FORKLIB: Before the fork, my pid is %d\n", GetProcessId(GetCurrentProcess()));

	PS_CREATE_INFO procInfo;
	RtlZeroMemory(&procInfo, sizeof(procInfo));
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	procInfo.Size = sizeof(PS_CREATE_INFO);

#ifndef _WIN64
	// WTF???? Discard *BIZARRE* segfault in ntdll from read fs:[0x18] that you can ignore???
	LPTOP_LEVEL_EXCEPTION_FILTER oldFilter = SetUnhandledExceptionFilter(DiscardException);
#endif

	// This is the part that actually does the forking. Everything else is just
	// to clean up after the mess that's created afterwards
	NTSTATUS result = NtCreateUserProcess(
		&hProcess, &hThread,
		MAXIMUM_ALLOWED, MAXIMUM_ALLOWED,
		NULL,
		NULL,
		PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT | PROCESS_CREATE_FLAGS_INHERIT_HANDLES, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
		NULL,
		&procInfo,
		NULL);

#ifndef _WIN64
	// Clear the exception handler installed earlier.
	SetUnhandledExceptionFilter(oldFilter);
#endif

	if (!result)
	{
		// Parent process
		printf("FORKLIB: I'm the parent\n");
		printf("FORKLIB: hThread = %p, hProcess = %p\n", hThread, hProcess);
		printf("FORKLIB: Thread ID = %x\n", GetThreadId(hThread));
		printf("FORKLIB: Result = %d\n", result);

		// Not needed??
		if (!NotifyCsrssParent(hProcess, hThread))
		{
			printf("FORKLIB: NotifyCsrssParent failed\n");
			TerminateProcess(hProcess, 1);
			return -1;
		}

		if (lpProcessInformation)
		{
			lpProcessInformation->hProcess = hProcess;
			lpProcessInformation->hThread = hThread;
			lpProcessInformation->dwProcessId = GetProcessId(hProcess);
			lpProcessInformation->dwThreadId = GetThreadId(hThread);
		}

		ResumeThread(hThread); // allow the child to connect to Csr.
		return GetProcessId(hProcess);
	}
	else
	{
		// Child process
		FreeConsole();
		// Remove these calls to improve performance, at the cost of losing stdio.
#ifdef _DEBUG
		AllocConsole();
		SetStdHandle(STD_INPUT_HANDLE, stdin);
		SetStdHandle(STD_OUTPUT_HANDLE, stdout);
		SetStdHandle(STD_ERROR_HANDLE, stderr);
#endif
		printf("I'm the child\n");

		if (!ConnectCsrChild())
		{
			DebugBreak();
			ExitProcess(1);
		}

#ifdef _DEBUG
		// Not safe to do fopen until after ConnectCsrChild
		ReopenStdioHandles();
#endif
		
		return 0;
	}
}
