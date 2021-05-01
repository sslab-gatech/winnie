//#define WIN32_LEAN_AND_MEAN

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include <stdio.h>
#include <tlhelp32.h>
#include <immintrin.h>
#include <vector>
#include <map>
#include <mutex>

#include <forklib.h>

#include "../forkserver-proto.h"
#include "../harness-api.h"
#include "exports.h"

//#include <winsock2.h>
//#pragma comment(lib, "Ws2_32.lib")

__declspec(noreturn) void bye();
__declspec(noreturn) void suicide();

FILE*fuzzer_stdout, *fuzzer_stdin;

#define fuzzer_printf(...) fprintf(fuzzer_stdout, ##__VA_ARGS__##);

// Print if debug enabled
#define debug_printf(...) {if (fuzzer_settings.debug) fprintf(fuzzer_stdout, ##__VA_ARGS__##); }

// For non-user facing debug messages (for fuzzer developers' eyes)
#if (!_DEBUG)
#define trace_printf(fmt, ...) (0)
#else
#define trace_printf(fmt, ...) fprintf(fuzzer_stdout, "TRACE: " fmt, ##__VA_ARGS__##)
#endif

#define FATAL(f, ...) {fprintf(fuzzer_stdout, f ": %d\n", ##__VA_ARGS__##, GetLastError()); fprintf(fuzzer_stdout, "Press enter to exit\n"); fflush(fuzzer_stdout); getc(fuzzer_stdin); suicide(); }

#ifdef _WIN64
#define INSTRUCTION_POINTER Rip
#define TRAMPOLINE_SIZE 14
#define THUNK_SIZE 16
#else
#define INSTRUCTION_POINTER Eip
#define TRAMPOLINE_SIZE 5
#define THUNK_SIZE 5
#endif

// Global variables
BYTE stolenBytes[TRAMPOLINE_SIZE] = { 0 };
struct breakpoint_t
{
	BYTE stolenByte;
	HMODULE hModule;
};
std::map<LPVOID, breakpoint_t> breakpoints;
std::mutex breakpoints_mutex;
std::map<HMODULE, std::string> module_filenames;
HMODULE hHarness = NULL;
PHARNESS_INFO harness_info = NULL;

LPVOID fuzz_iter_address;
LPVOID pCreateFile = NULL;
LPVOID pTerminateProcess = NULL;
LPVOID pRtlExitUserProcess = NULL;

//network related functions
LPVOID pAccept = NULL;
LPVOID pListen = NULL;
LPVOID pRecv = NULL;
LPVOID pSend = NULL;
LPVOID pBind = NULL;
LPVOID pIoctlsocket = NULL;
LPVOID pSetsockopt = NULL;
LPVOID pSelect = NULL;

BYTE* target_address;
int recv_count = 0;
int accept_count = 0;

HANDLE superEarlyHandler = INVALID_HANDLE_VALUE;

typedef PVOID(NTAPI* fnRtlAddVectoredExceptionHandler)(
	ULONG                       First,
	PVECTORED_EXCEPTION_HANDLER Handler
	);
PVOID pRtlAddVectoredExceptionHandler = NULL;
fnRtlAddVectoredExceptionHandler pOrgRtlAddVectoredExceptionHandler = NULL;

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG  NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);
PVOID pNtProtectVirtualMemory = NULL;
fnNtProtectVirtualMemory pOrgNtProtectVirtualMemory = NULL;

typedef SOCKET(*fnAccept)(
	SOCKET   s,
	sockaddr *addr,
	int      *addrlen
	);
fnAccept pOrgAccept = NULL;

typedef int(*fnListen)(
	SOCKET s,
	int    backlog
	);
fnListen pOrgListen = NULL;

typedef int(*fnBind)(
	SOCKET         s,
	const sockaddr *addr,
	int            namelen
	);
fnBind pOrgBind = NULL;

typedef int(*fnRecv)(
	SOCKET s,
	char   *buf,
	int    len,
	int    flags
	);
fnRecv pOrgRecv = NULL;

typedef int(*fnSend)(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
	);
fnSend pOrgSend = NULL;

typedef int(*fnIoctlsocket)(
	SOCKET s,
	long   cmd,
	u_long *argp
	);
fnIoctlsocket pOrgIoctlsocket = NULL;

typedef int(*fnSetsockopt)(
	SOCKET     s,
	int        level,
	int        optname,
	const char *optval,
	int        optlen
	);
fnSetsockopt pOrgSetsockopt = NULL;

typedef int(*fnSelect)(
	int           nfds,
	fd_set        *readfds,
	fd_set        *writefds,
	fd_set        *exceptfds,
	const timeval *timeout
	);
fnSelect pOrgSelect = NULL;

char afl_pipe[MAX_PATH+1];

HMODULE hLibWs2_32 = NULL;

// Fork mode only
char forkserver_child_pipe [MAX_PATH+1];
DWORD childCpuAffinityMask;

const char* get_module_filename(HMODULE hModule)
{
	if (module_filenames.find(hModule) == module_filenames.end())
	{
		char buf[1000];
		if (!GetModuleFileNameA(hModule, buf, sizeof(buf)))
		{
			FATAL("GetModuleFileNameA");
		}
		char* basename = strrchr(buf, '\\');
		if (basename)
			basename++;
		else
			basename = buf;
		module_filenames.emplace(hModule, basename);
	}
	return module_filenames[hModule].c_str();
}

// This is kinda sketchy because other threads might not be suspended and may end up executing the code as we're patching it.
// Ideally we should suspend all the other threads before doing any code patching, but I feel like that would just cause even more problems.
void PatchCode(LPVOID target, _In_ BYTE* bytes, _In_ size_t len, _Out_opt_ BYTE* stolenBytes)
{
	//trace_printf("Patch %p len %d\n", target, len);
	
	DWORD dwOldProtect;
	if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		FATAL("VirtualProtect failed!! (write) :(\n");
	}

	uintptr_t aligned = ((uintptr_t)target) & ~0xfULL;
	uintptr_t end = ((uintptr_t)target) + len;
	uintptr_t aligned_size = end - aligned;
	
	if (len == 1) // Special case because we use CC int3 a lot
	{
		// We can do it atomically using lock cmpxchg
		BYTE stolenByte = _InterlockedExchange8((volatile CHAR*)target, *bytes);
		if (stolenBytes) *stolenBytes = stolenByte;
	}
#ifdef _WIN64
	else if (aligned_size < 16)
	{
		// We can do it atomically using lock cmpxchg16b. All modern CPUs support
		uintptr_t offset = (uintptr_t) target - aligned;
		BYTE orig_bytes[16];
		BYTE new_bytes[16];
		memcpy(orig_bytes, (LPVOID) aligned, 16);
		memcpy(new_bytes, orig_bytes, 16);
		memcpy(new_bytes + offset, bytes, len);
		char success = _InterlockedCompareExchange128((volatile LONG64*) aligned, *(LONG64*)&new_bytes[8], *(LONG64*)&new_bytes[0], (LONG64*) orig_bytes);
		if (!success)
		{
			FATAL("Atomic PatchCode failed!");
		}
		if (stolenBytes) memcpy(stolenBytes, orig_bytes + offset, len);
	}
#endif
	else
	{
		// We can't do the write atomically (straddling multiple cache lines) so just resort to plain-old memcpy.
		if (stolenBytes) memcpy(stolenBytes, target, len);
		memcpy(target, bytes, len);
	}
	
	DWORD trash;
	if (!VirtualProtect(target, len, dwOldProtect, &trash))
	{
		FATAL("VirtualProtect failed!! (restore) :(\n");
	}
	FlushInstructionCache(GetCurrentProcess(), target, len);
}

void InstallBreakpoint(HMODULE hModule, uintptr_t rva)
{
	breakpoints_mutex.lock();
	BYTE int3 = 0xcc;
	BYTE stolenByte = NULL;
	PBYTE target = (PBYTE)hModule + rva;
	//trace_printf("install break: %p\n", target);
	if (breakpoints.find(target) != breakpoints.end())
		FATAL("InstallBreakpoint: duplicate breakpoint detected, check bb-file");
	int3 = 0xcc;
	PatchCode(target, &int3, 1, &stolenByte);
	breakpoints[target] = { stolenByte, hModule };
	breakpoints_mutex.unlock();
}

// uninstall breakpoint
breakpoint_t RestoreBreakpoint(LPVOID target)
{
	breakpoints_mutex.lock();
	if (breakpoints.find(target) == breakpoints.end())
		FATAL("RestoreBreakpoint: attempting to restore nonexistent breakpoint");
	breakpoint_t breakpoint = breakpoints[target];
	//trace_printf("The stolen byte was %p\n", stolenByte);
	breakpoints.erase(target);
	PatchCode(target, &breakpoint.stolenByte, 1, NULL);
	breakpoints_mutex.unlock();
	return breakpoint;
}

BOOL DoesBreakpointExists(LPVOID target)
{
	breakpoints_mutex.lock();
	BOOL result = breakpoints.find(target) != breakpoints.end();
	breakpoints_mutex.unlock();
	return result;
}

// Assembles a far jump to dest.
void AssembleTrampoline(BYTE* dst, uintptr_t target, _Out_opt_ BYTE* stolenBytes)
{
#ifdef _WIN64
	BYTE trampoline[TRAMPOLINE_SIZE] = {
		0x68, 0x00, 0x00, 0x00, 0x00, // push qword XXXXXXXX
		0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsp+4], XXXXXXXX
		0xC3 // ret
	};
	DWORD64 jmpTarget = (DWORD64)target;
	*(DWORD*)(trampoline + 1) = (DWORD)(jmpTarget & 0xFFFFFFFF);
	*(DWORD*)(trampoline + 9) = (DWORD)((jmpTarget >> 32) & 0xFFFFFFFF);
#else
	BYTE trampoline[TRAMPOLINE_SIZE] = {
		0xE9, 0x00, 0x00, 0x00, 0x00, // jmp XXXXXXXX
	};
	*(DWORD*)(trampoline + 1) = (DWORD)(target - ((uintptr_t)dst + 5));
#endif  	
	PatchCode(dst, trampoline, TRAMPOLINE_SIZE, stolenBytes);
}

void RestoreHookedBytes()
{
	PatchCode(target_address, stolenBytes, TRAMPOLINE_SIZE, NULL);
}

// stolenCount should align to instruction, and be larger than TRAMPOLINE_SIZE
void InlineHook(PVOID pOrgFn, PVOID pNewFn, PVOID* ppOrgFnCall, int stolenCount)
{
	// Stolen bytes (5) + Jump to the original function
	*ppOrgFnCall = VirtualAlloc(NULL, 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// MUST COME FIRST BECAUSE IT CALLS VirtualProtect
	debug_printf("inlinehook 1\n");
	AssembleTrampoline((PBYTE)*ppOrgFnCall + stolenCount, (uintptr_t)pOrgFn + stolenCount, NULL);
	debug_printf("inlinehook 2\n");

	// Assemble the code BEFORE hooking, lest we suffer reentrancy issues...
	debug_printf("will copy %d bytes\n", stolenCount - TRAMPOLINE_SIZE);
	memcpy((PBYTE)*ppOrgFnCall + TRAMPOLINE_SIZE, (PBYTE)pOrgFn + TRAMPOLINE_SIZE, stolenCount - TRAMPOLINE_SIZE);
	debug_printf("inlinehook 3\n");
	
	AssembleTrampoline((PBYTE)pOrgFn, (uintptr_t)pNewFn, (PBYTE)*ppOrgFnCall);
	
	debug_printf("inlinehook done\n");
}

void InlineUnhook(PVOID pOrgFn, PVOID ppOrgFnCall, int stolenCount)
{
	PatchCode(pOrgFn, (PBYTE)ppOrgFnCall, stolenCount, NULL);
	debug_printf("inlineunhook done\n");
}

// Breakpoint the basicblocks
void install_breakpoints() {
	AFL_COVERAGE_INFO* cov_info = fuzzer_settings.cov_info;
	if (!cov_info)
	{
		fuzzer_printf("No coverage information provided, relying on external tracing. Coverage events will not be reported to the fuzzer.\n");
		return;
	}
	
	if (!cov_info->NumberOfBasicBlocks)
	{
		FATAL("No basic blocks provided by AFL!!!");
	}

	fuzzer_printf("Installing %zu breakpoints, this might take a while...", cov_info->NumberOfBasicBlocks);
	for (unsigned int i = 0; i < cov_info->NumberOfBasicBlocks; i++)
	{
		//trace_printf("mname: %p\n", cov_info->BasicBlocks[i].ModuleName);
		HMODULE hModule = GetModuleHandleA(cov_info->BasicBlocks[i].ModuleName);
		//trace_printf("mname:%s, baseaddr:%p rva: %p\n", cov_info->BasicBlocks[i].ModuleName, hModule, cov_info->BasicBlocks[i].Rva);
		InstallBreakpoint(hModule, cov_info->BasicBlocks[i].Rva);
		if (i % 10000 == 0) fuzzer_printf(".");
	}
	fuzzer_printf("\nInstalled %zu breakpoints\n", cov_info->NumberOfBasicBlocks);
}

void hook_NtCreateFile()
{
	static HMODULE hNtdll = GetModuleHandleA("ntdll");
	InstallBreakpoint(hNtdll, (uintptr_t)pCreateFile - (uintptr_t)hNtdll);
}

void hook_TerminateProcess()
{
	static HMODULE hKernel32 = GetModuleHandleA("kernel32");
	InstallBreakpoint(hKernel32, (uintptr_t)pTerminateProcess - (uintptr_t)hKernel32);
}

// REALLY exit
__declspec(noreturn) void bye()
{
	// just kidding, wait for AFL to let us die instead of killing ourselves.
	// this is for the intel-pt mode so AFL has time to collect coverage
	// before this process suddenly VANISHES like d.b. motherfucking cooper
	// along with the all of the valuable trace data
	Sleep(INFINITE);
}

__declspec(noreturn) void suicide()
{
	debug_printf("check restore\n");
	if (DoesBreakpointExists(pTerminateProcess))
	{
		debug_printf("do restore\n");
		RestoreBreakpoint(pTerminateProcess);
	}
	debug_printf("bye!\n");
	TerminateProcess(GetCurrentProcess(), 0);
}

void hook_RtlExitUserProcess()
{
	static HMODULE hNtdll = GetModuleHandleA("ntdll");
	InstallBreakpoint(hNtdll, (uintptr_t)pRtlExitUserProcess - (uintptr_t)hNtdll);
}


// In the future, this pipe name needs to be renamed per instance of the forkserver...
#define FORKSERVER_CHILD_PIPE "\\\\.\\pipe\\forkserver-children"

// Forkserver parent-child ipc shit
OVERLAPPED oChildPipe;
HANDLE hPipeChild, hPipeAfl;
HANDLE waitHandles[2] = { NULL, NULL };

typedef struct _FORKSERVER_CHILD_MSG
{
	DWORD pid;
	enum CHILD_FATE StatusCode;
	union
	{
		struct
		{
			uint64_t success_info;
		} SuccessInfo;
		struct
		{
			DWORD _exception_code;
			uint64_t ip;
			uint64_t faulting_address;
		} CrashInfo;
		struct
		{
			uint64_t ip;
		} CoverageInfo;
	};
} FORKSERVER_CHILD_MSG;

// Forkserver only
void SetupChildPipe()
{
	HANDLE hConnectEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	RtlZeroMemory(&oChildPipe, sizeof(oChildPipe));
	oChildPipe.hEvent = hConnectEvent;
	hPipeChild = CreateNamedPipeA(forkserver_child_pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
	if (hPipeChild == INVALID_HANDLE_VALUE)
	{
		FATAL("CreateNamedPipe");
	}
	if (ConnectNamedPipe(hPipeChild, &oChildPipe))
	{
		FATAL("ConnectNamedPipe");
	}
	waitHandles[0] = oChildPipe.hEvent;
}

// Communicate child results.
BOOL AcceptPipe(FORKSERVER_CHILD_MSG* msg, DWORD* lpReadSize)
{
	BYTE response[1] = { 0 };
	BOOL success = FALSE;
	
	if (!GetOverlappedResult(hPipeChild, &oChildPipe, lpReadSize, TRUE))
	{
		fuzzer_printf("GetOverlappedResult failed %d\n", GetLastError());
		goto cleanup;
	}
	trace_printf("Pipe connected\n");

	if (!ReadFile(hPipeChild, msg, sizeof(FORKSERVER_CHILD_MSG), NULL, &oChildPipe) && GetLastError() != ERROR_IO_PENDING)
	{
		fuzzer_printf("ReadFile failed: %d\n", GetLastError());
		goto cleanup;
	}
	if (!GetOverlappedResult(hPipeChild, &oChildPipe, lpReadSize, TRUE))
	{
		fuzzer_printf("Read error %d\n", GetLastError());
		goto cleanup;
	}
	trace_printf("Rx done.\n");

	if (!WriteFile(hPipeChild, response, sizeof(response), NULL, &oChildPipe) && GetLastError() != ERROR_IO_PENDING)
	{
		fuzzer_printf("WriteFile failed: %d\n", GetLastError());
		goto cleanup;
	}
	DWORD nWritten;
	if (!GetOverlappedResult(hPipeChild, &oChildPipe, &nWritten, TRUE))
	{
		fuzzer_printf("Write error: %d\n", GetLastError());
		goto cleanup;
	}
	trace_printf("Tx done.\n");
	
	success = TRUE;

	cleanup:
	DisconnectNamedPipe(hPipeChild);
	trace_printf("Disconnected.\n");

	if (ConnectNamedPipe(hPipeChild, &oChildPipe))
	{
		FATAL("ConnectNamedPipe");
	}
	else if (GetLastError() == ERROR_PIPE_CONNECTED)
	{
		// This can happen if client connected already.
		// Need to alert event waiters to accept connection and prevent hang.
		SetEvent(oChildPipe.hEvent);
	}
	else if (GetLastError() != ERROR_IO_PENDING)
	{
		FATAL("ConnectNamedPipe");
	}

	return success;
}

extern "C" {
	void(*report_end)(); // noreturn
}

__declspec(noreturn) void afl_report_end()
{
	//trace_printf("ipc to the forkserver to tell them we finished\n");
	// ipc to the forkserver to tell him we finished.
	AFL_FORKSERVER_RESULT aflResponse;
	aflResponse.StatusCode = AFL_CHILD_SUCCESS;
	DWORD nWritten;
	if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
	{
		FATAL("Broken AFL pipe, WriteFile (report_end)");
	}
	//trace_printf("Okay, goodbye.\n");
	//getc(fuzzer_stdin);
	bye();
}

__declspec(noreturn) void fork_report_end()
{
	// ipc to the forkserver to tell him we finished.
	FORKSERVER_CHILD_MSG message;
	message.StatusCode = CHILD_SUCCESS;
	DWORD nRead;
	BYTE response[1] = {};
	RestoreBreakpoint(pCreateFile); // Unhook NtCreateFile before CallNamedPipe
	BOOL result = CallNamedPipeA(forkserver_child_pipe, &message, sizeof(message), response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
	//trace_printf("Okay, goodbye.\n");
	//getc(fuzzer_stdin);
	bye();
}

__declspec(noreturn) void persistent_report_end()
{
	AFL_PERSISTENT_RESULT aflResponse;
	aflResponse.StatusCode = AFL_CHILD_SUCCESS;
	DWORD nWritten;
	if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
	{
		FATAL("Broken AFL pipe, WriteFile (child_end)");
	}
	debug_printf("Okay, suspending the current thread.\n");
	//getc(fuzzer_stdin);
	SuspendThread(GetCurrentThread());
	FATAL("Resumed without resetting context in persistent_report_end");
}

void(*report_crashed)(DWORD _exception_code, uint64_t ip, uint64_t faulting_address);

void afl_report_crashed(DWORD _exception_code, uint64_t ip, uint64_t faulting_address)
{
	//trace_printf("crash\n");
	AFL_FORKSERVER_RESULT aflResponse;
	aflResponse.StatusCode = AFL_CHILD_CRASHED;
	DWORD nWritten;
	if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
	{
		FATAL("Broken AFL pipe, WriteFile (report_crashed)");
	}
}

void fork_report_crashed(DWORD _exception_code, uint64_t ip, uint64_t faulting_address)
{
	FORKSERVER_CHILD_MSG message;
	message.pid = GetCurrentProcessId();
	message.StatusCode = CHILD_CRASHED;
	message.CrashInfo._exception_code = _exception_code;
	message.CrashInfo.ip = ip;
	message.CrashInfo.faulting_address = faulting_address;
	DWORD nRead;
	BYTE response[1] = {};
	RestoreBreakpoint(pCreateFile); // Unhook NtCreateFile before CallNamedPipe
	BOOL result = CallNamedPipeA(forkserver_child_pipe, &message, sizeof(message), response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
}

void(*report_coverage)(uintptr_t ip, breakpoint_t bp);

void afl_report_coverage(uintptr_t ip, breakpoint_t bp)
{
	DWORD nWritten;
	AFL_FORKSERVER_RESULT aflResponse;
	aflResponse.StatusCode = AFL_CHILD_COVERAGE;
	aflResponse.CoverageInfo.Rva = ip - (uintptr_t)bp.hModule;
	strncpy(aflResponse.CoverageInfo.ModuleName, get_module_filename(bp.hModule), sizeof(aflResponse.CoverageInfo.ModuleName));
	debug_printf("* %s+%p\n", aflResponse.CoverageInfo.ModuleName, aflResponse.CoverageInfo.Rva);
	if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
	{
		FATAL("Broken AFL pipe, WriteFile");
	}
}

void fork_report_coverage(uintptr_t ip, breakpoint_t bp)
{
	FORKSERVER_CHILD_MSG message;
	message.pid = GetCurrentProcessId();
	message.StatusCode = CHILD_COVERAGE;
	message.CoverageInfo.ip = ip;
	DWORD nRead;
	BYTE response[1] = {};
	RestoreBreakpoint(pCreateFile); // Unhook NtCreateFile before CallNamedPipe
	BOOL result = CallNamedPipeA(forkserver_child_pipe, &message, sizeof(message), response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
	hook_NtCreateFile(); // Rehook NtCreateFile
}

// DO NOT PUT ME IN TLS OR I WILL SEGFAULT ON USE IN THE HANDLER!
// 0 = none
// 1 = NtCreateFile
// 2 = TerminateProcess
int singleStep = 0;
LONG handlerReentrancy = 0; // Detect if our breakpoint handler itself is faulty

void CreateFile_hook(EXCEPTION_POINTERS *ExceptionInfo)
{
	const wchar_t* input_name = L".cur_input";
	if (harness_info->input_file)
		input_name = harness_info->input_file;

#ifdef _WIN64
	DWORD64 r8 = ExceptionInfo->ContextRecord->R8;
	// See if the file name contains .cur_input	
	POBJECT_ATTRIBUTES obj = (POBJECT_ATTRIBUTES)r8;
	PUNICODE_STRING testStr = (PUNICODE_STRING)obj->ObjectName;	
	std::wstring wStrBuf(testStr->Buffer, testStr->Length / sizeof(WCHAR));	
	const wchar_t *wStr = wStrBuf.c_str();
	debug_printf("Filename = %ls\n", wStr);	
	if (wcsstr(wStr, input_name))
	{
		// overwrite buffer
		debug_printf("Intercepted NtCreateFile on input file; overwrite share flag\n");
		DWORD shared_flag = FILE_SHARE_READ | FILE_SHARE_WRITE;
		*(DWORD64*)(r8 + (sizeof(DWORD) * 7)) |= shared_flag;

	}
#else
	DWORD esp = ExceptionInfo->ContextRecord->Esp;
	uintptr_t buffer[10];
	memcpy(buffer, (LPVOID)(esp + sizeof(void *)), sizeof(buffer));

	// See if the file name contains .cur_input
	//trace_printf("Current shared flag: %x\n", *(buffer + 6));
	POBJECT_ATTRIBUTES obj = (POBJECT_ATTRIBUTES)*(buffer + 2);
	PUNICODE_STRING testStr = (PUNICODE_STRING)obj->ObjectName;
	std::wstring wStrBuf(testStr->Buffer, testStr->Length / sizeof(WCHAR));
	const wchar_t *wStr = wStrBuf.c_str();
	debug_printf("Filename = %ls\n", wStr);
	if (wcsstr(wStr, input_name))
	{
		// overwrite buffer
		debug_printf("We found NtCreateFile with .cur_input, we will overwrite share flag\n");
		DWORD shared_flag = FILE_SHARE_READ | FILE_SHARE_WRITE;
		*(DWORD*)(esp + (sizeof(DWORD) * 7)) |= shared_flag;
	}
#endif
}

void TerminateProcess_hook(EXCEPTION_POINTERS* ExceptionInfo)
{
#ifdef _WIN64
	HANDLE hProcess = (HANDLE) ExceptionInfo->ContextRecord->Rcx;
#else
	DWORD esp = ExceptionInfo->ContextRecord->Esp;
	HANDLE hProcess = *(HANDLE*)(esp + 4);
#endif
	if (GetCurrentProcess() == hProcess || GetCurrentProcessId() == GetProcessId(hProcess))
	{
		//trace_printf("Exit5 %d\n", handlerReentrancy);
		InterlockedDecrement(&handlerReentrancy);
		if (handlerReentrancy != 0)
			FATAL("Bad re-entry count %d?", handlerReentrancy);
		report_end();
	}
}

LONG WINAPI BreakpointHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
	//trace_printf("Enter %d\n", handlerReentrancy);
	if (InterlockedIncrement(&handlerReentrancy) != 1)
	{
		FATAL("The breakpoint handler itself generated an exeption (code=%08x, IP=%p) !!! Likely the breakpoint handler is faulty!!", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ContextRecord->INSTRUCTION_POINTER);
	}
	
	// single step from ntcreatefile hook
	if (singleStep)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		{
			FATAL("Expecting single step trap but instead received exception %08x!!! Likely the breakpoint handler is faulty!!", ExceptionInfo->ExceptionRecord->ExceptionCode);
		}
		//trace_printf("YEET! Got single step at %p\n", ExceptionInfo->ContextRecord->INSTRUCTION_POINTER);

		// patch the NtCreateFile again
		if (singleStep == 1)
			hook_NtCreateFile();
		else if (singleStep == 2)
			hook_TerminateProcess();

		singleStep = 0;

		//trace_printf("Exit1 %d\n", handlerReentrancy);
		InterlockedDecrement(&handlerReentrancy);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		// It's a breakpoint, no big deal, just restore the stolen byte and continue.
		LPVOID ip = (LPVOID)ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;
		if (DoesBreakpointExists(ip))
		{
			//trace_printf("hit breakpoint at %p\n", ip);
			if (ip == pCreateFile || ip == pTerminateProcess)
			{
				// do single step to restore the breakpoint. we'll receive a 'single step' exception (see above).
				ExceptionInfo->ContextRecord->EFlags |= 0x100;//trap flag
				if (ip == pCreateFile)
				{
					debug_printf("NtCreateFile hit: %p\n", ip);
					CreateFile_hook(ExceptionInfo);
					singleStep = 1;
				}
				else if (ip == pTerminateProcess)
				{
					debug_printf("TerminateProcess hit: %p\n", ip);
					TerminateProcess_hook(ExceptionInfo); // This may lead to report_end(), so we need to remember to decrement the re-entry counter if that is the case.
					singleStep = 2;
				}				
				else
					FATAL("Wrong single step value");

				RestoreBreakpoint(ip);
			}
			else if (ip == pRtlExitUserProcess)
			{
				debug_printf("RtlExitUserProcess basicblock: %p\n", ip);
				report_end();
			}
			else
			{
				debug_printf("Covered basicblock %p\n", ip);
				breakpoint_t bp = RestoreBreakpoint(ip);
				report_coverage((uintptr_t) ip, bp);
				
				// weird case
				if (bp.stolenByte == 0xCC)
				{
					fuzzer_printf("We seem to have placed a breakpoint on top of an existing breakpoint, check bb-file (duplicated breakpoint?)\n");
					// exception will eventually bubble up to ChildCrashHandler.
					//trace_printf("Exit2 %d\n", handlerReentrancy);
					InterlockedDecrement(&handlerReentrancy);
					return EXCEPTION_CONTINUE_SEARCH;
				}
			}
			//trace_printf("Exit3 %d\n", handlerReentrancy);
			InterlockedDecrement(&handlerReentrancy);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else {
			debug_printf("We hit breakpoint but it's not ours?");
		}
	}
	debug_printf("Ignoring exception %08x at %p, referencing %p\n", ExceptionInfo->ExceptionRecord->ExceptionCode, (void*) ExceptionInfo->ContextRecord->INSTRUCTION_POINTER, ExceptionInfo->ExceptionRecord->ExceptionAddress);
	//trace_printf("Exit4 %d\n", handlerReentrancy);
	InterlockedDecrement(&handlerReentrancy);
	return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI ChildCrashHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
	fuzzer_printf("Uncaught exception %08x at instruction %p, referencing %p\n",
		ExceptionInfo->ExceptionRecord->ExceptionCode,
		ExceptionInfo->ContextRecord->INSTRUCTION_POINTER,
		ExceptionInfo->ExceptionRecord->ExceptionAddress);
	report_crashed(ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ContextRecord->INSTRUCTION_POINTER, (uint64_t)ExceptionInfo->ExceptionRecord->ExceptionAddress);
	bye();
	return EXCEPTION_EXECUTE_HANDLER;
}

HANDLE earlyHandler;

void SetupExceptionFilter()
{
	// for our breakpoints
	AddVectoredExceptionHandler(TRUE, BreakpointHandler);

	// remove temporary handler
	RemoveVectoredExceptionHandler(earlyHandler);

	// crash reporting to forkserver parent
	SetUnhandledExceptionFilter(ChildCrashHandler);

	// apparently, this exception handler runs even when the UnhandledExceptionFilter doesn't.
	// it's the ULTIMATE exception handler! preempts WER even!
	//AddVectoredContinueHandler(FALSE, ChildCrashHandler);

	// Don't let other people mess with our exception handler.
#ifdef _WIN64
	uint8_t ret[] = { 0xc3 }; // ret
#else
	uint8_t ret[] = { 0xc2, 0x04, 0x00 }; // ret 4
#endif
	PatchCode(SetUnhandledExceptionFilter, ret, sizeof(ret), NULL);
}

int parse_minidump_filename_pid(LPCSTR filename)
{
	char pid[MAX_PATH+1];
	size_t len = strlen(filename);
	if (strcmp(filename + len - 4, ".dmp")) return -1;
	size_t i = len - 4;
	while (i-- > 0 && filename[i] != '.');
	if (i < 0) return -1;
	if (i == 0) return -1;
	strncpy(pid, filename + i + 1, len - 5 - i);
	return atoi(pid);
}

// HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting
// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps
// TODO: Why aren't we using AddVectoredContinueHandler?
BOOL SearchForMinidump(DWORD pid)
{
	WIN32_FIND_DATAA ffd;
	char search_path[MAX_PATH+1];
	snprintf(search_path, sizeof(search_path), "%s%s", fuzzer_settings.minidump_path, "\\*.exe.*.dmp");
	HANDLE hFind = FindFirstFileA(search_path, &ffd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND) return FALSE;
		FATAL("FindFirstFile");
	}
	do
	{
		int dumpPid = parse_minidump_filename_pid(ffd.cFileName);
		fuzzer_printf("Found dump %ls, pid %d\n", ffd.cFileName, dumpPid);
		if (dumpPid > 0 && (DWORD)dumpPid == pid)
		{
			return TRUE;
		}
	} while (FindNextFileA(hFind, &ffd));

	if (GetLastError() != ERROR_NO_MORE_FILES)
	{
		FATAL("FindNextFile");
	}
	FindClose(hFind);
	return FALSE;
}

void SetupTarget()
{
	SetupExceptionFilter();

	// Patch NtCreateFile
	hook_NtCreateFile();	
	hook_TerminateProcess();
	hook_RtlExitUserProcess();
}

__declspec(noreturn) void do_child()
{
#ifdef _DEBUG
	fuzzer_stdout = fopen("CONOUT$", "w+");
	fuzzer_stdin = fopen("CONIN$", "r");
	setvbuf(fuzzer_stdout, NULL, _IONBF, 0);
	setvbuf(fuzzer_stdin, NULL, _IONBF, 0);
#endif

	//trace_printf("I am the child.\n");
	//trace_printf("target address = %p\n", target_address);
	SuspendThread(GetCurrentThread()); // wait for parent to unsuspend us when AFL gives the message
	SetupTarget();
	call_target(); // does not return
}

PROCESS_INFORMATION do_fork()
{
	// spawn new child with fork
	PROCESS_INFORMATION pi;
	DWORD pid = fork(&pi);
	if (pid == -1)
	{
		FATAL("fork failed\n");
	}
	else if (!pid) // child (pid = 0)
	{
		do_child(); // does not return
	}

	// VERY IMPORTANT for performance.
	if (!SetProcessAffinityMask(GetCurrentProcess(), childCpuAffinityMask)) {
		FATAL("Failed to set process affinity");
	}

	// Parent report child's return status
	debug_printf("Child pid: %d\n", pid);

	return pi;
}

CHILD_FATE do_parent(PROCESS_INFORMATION pi)
{
	waitHandles[1] = pi.hProcess;
	CHILD_FATE childStatus;
	do
	{
		childStatus = CHILD_UNKNOWN;
		switch (WaitForMultipleObjects(ARRAYSIZE(waitHandles), waitHandles, FALSE, fuzzer_settings.timeout))
		{
		case WAIT_OBJECT_0: { // waitHandles[0] = oChildPipe.hEvent;
			trace_printf("Child event is alerted\n");
			FORKSERVER_CHILD_MSG msg;
			DWORD nRead;

			if (!AcceptPipe(&msg, &nRead))
			{
				FATAL("Failed to communicate with child process!\n");
				break;
			}

			if (msg.StatusCode == CHILD_COVERAGE)
			{
				debug_printf("Child has new coverage: %llx\n", msg.CoverageInfo.ip);

				// remove the breakpoint.
				breakpoint_t bp = RestoreBreakpoint((LPVOID)msg.CoverageInfo.ip);

				// report to fuzzer
				afl_report_coverage((uintptr_t)msg.CoverageInfo.ip, bp);
			}
			else
			{
				debug_printf("Child result: %d\n", msg.StatusCode);
			}
			childStatus = msg.StatusCode;
			break;
		}
		case WAIT_OBJECT_0 + 1:  // waitHandles[1] = pi.hProcess;
			debug_printf("Child process died unexpectedly (crash)\n");
			childStatus = CHILD_CRASHED;
			break;
		case WAIT_TIMEOUT:
			debug_printf("Child timed out\n");
			childStatus = CHILD_TIMEOUT;
			TerminateProcess(pi.hProcess, 1);
			break;
		default:
			FATAL("WaitForMultipleObjects failed");
		}
	} while (childStatus == CHILD_COVERAGE);

	if (childStatus == CHILD_UNKNOWN)
	{
		fuzzer_printf("Child status unknown (crash?)\n");
		// If minidump found, the child actually crashed violently (stack BOF, bad IP)
		if (SearchForMinidump(pi.dwProcessId))
		{
			fuzzer_printf("We found a minidump. This is a serious crash.\n");
			childStatus = CHILD_CRASHED;
		}
	}

	debug_printf("Child fate: %d\n", childStatus);
	return childStatus;
}

_declspec(noreturn) void forkserver()
{
	SetupChildPipe();
	
	fuzzer_printf("Okay, spinning up the forkserver now.\n");

	// forkserver
	int forkCount = 0;
	int done = false;
	PROCESS_INFORMATION curChildInfo = {0};
	int childPending = 0;
	while (!done)
	{
		AFL_FORKSERVER_REQUEST aflRequest;
		DWORD nRead;
		if (!ReadFile(hPipeAfl, &aflRequest, sizeof(aflRequest), &nRead, NULL) || nRead != sizeof(aflRequest))
		{
			FATAL("Broken AFL pipe, ReadFile (forkserver)");
		}
		switch (aflRequest.Operation)
		{
		case AFL_CREATE_NEW_CHILD: {
			trace_printf("Fuzzer asked me to create new child\n");
			if (childPending)
			{
				FATAL("Invalid request; a forked child is already standby for execution");
			}
			forkCount++;
			curChildInfo = do_fork();
			AFL_FORKSERVER_RESULT aflResponse;
			aflResponse.StatusCode = AFL_CHILD_CREATED;
			aflResponse.ChildInfo.ProcessId = curChildInfo.dwProcessId;
			aflResponse.ChildInfo.ThreadId = curChildInfo.dwThreadId;
			DWORD nWritten;
			if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
			{
				FATAL("Broken AFL pipe, WriteFile");
			}
			childPending = 1;
			break;
		}
		case AFL_RESUME_CHILD: {
			if (!childPending)
			{
				FATAL("Invalid request; no forked child to resume");
			}
			trace_printf("Fuzzer asked me to resume the child\n");
			// Wait for the forked child to suspend itself, then we will resume it. (In order to synchronize)
			while (1) {
				DWORD exitCode = 0;
				// If the fork fails somehow, the child will unexpectedly die without suspending itself.
				if (!GetExitCodeProcess(curChildInfo.hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
					fuzzer_printf("The forked child died before we resumed it! Exit code: %d\n", exitCode);
					suicide();
				}
				DWORD dwWaitResult = WaitForSingleObject(curChildInfo.hThread, 0);
				if (dwWaitResult == WAIT_OBJECT_0) { // Thread object is signaled -- thread died
					fuzzer_printf("The forked child thread died before we resumed it!\n");
					suicide();
				}
				DWORD dwResult = ResumeThread(curChildInfo.hThread);
				if (dwResult == (DWORD)-1)
					FATAL("Failed to resume the child");
				if (dwResult == 0) { // Hasn't suspended itself yet
					Sleep(1);
					continue;
				}
				else if (dwResult == 1)
					break;
				else
					FATAL("Unexpected suspend count %d", dwResult);
			}
			AFL_FORKSERVER_RESULT aflResponse;
			CHILD_FATE childStatus = do_parent(curChildInfo); // return child's status from parent.
			CloseHandle(curChildInfo.hProcess);
			CloseHandle(curChildInfo.hThread);
			RtlZeroMemory(&curChildInfo, sizeof(curChildInfo));
			switch (childStatus)
			{
			case CHILD_SUCCESS:
				aflResponse.StatusCode = AFL_CHILD_SUCCESS;
				break;
			case CHILD_CRASHED:
				aflResponse.StatusCode = AFL_CHILD_CRASHED;
				break;
			case CHILD_TIMEOUT:
				aflResponse.StatusCode = AFL_CHILD_TIMEOUT;
				break;
			default:
				FATAL("Child exited in an unexpected way?");
			}
			DWORD nWritten;
			if (!WriteFile(hPipeAfl, &aflResponse, sizeof(aflResponse), &nWritten, NULL) || nWritten != sizeof(aflResponse))
			{
				FATAL("Broken AFL pipe, WriteFile");
			}
			childPending = 0;
			break;		
		}
		case AFL_TERMINATE_FORKSERVER:
			debug_printf("Fuzzer asked me to kill the forkserver\n");
			done = true;
			break;
		}
	}

	DisconnectNamedPipe(hPipeChild);
	DisconnectNamedPipe(hPipeAfl);
	CloseHandle(hPipeAfl);
	CloseHandle(hPipeChild);
	fuzzer_printf("Bye.\n");
	suicide();
}

__declspec(noreturn) void persistent_server()
{
	// This is really quite ugly. Do a raw spinlock to wait for AFL to capture our thread context.
	// We can't yield/sleep/etc. because can't have capture a thread context in a stack frame we will return from (and thus destroy).
	debug_printf("Now going to wait fork AFL to capture our thread context\n");
	MemoryBarrier();
	forkserver_state = FORKSERVER_WAITING;
	MemoryBarrier();
	while (forkserver_state == FORKSERVER_WAITING)
	{
		YieldProcessor(); // _mm_pause
	}
	MemoryBarrier();

	trace_printf("Iterating loop\n\n");
	handlerReentrancy = 0;
	MemoryBarrier();
	call_target(); // call one persistent function
}

LONG WINAPI EarlyExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
	LPVOID ip = (LPVOID)ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		if (DoesBreakpointExists(ip))
		{
			fuzzer_printf("Hit breakpoint %p early\n", ip);
			RestoreBreakpoint(ip);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void SetupServer()
{
	if (fuzzer_settings.enableWER) {
		// enable WER (Windows Error Reporting) so we can monitor crash dumps
		SetErrorMode(0);
	} else {
		// disable WER since minidumps are slow
		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	}

	if (!fuzzer_settings.debug) {
		// Kill the target stdio handles
		freopen("nul", "w+", stdout);
		freopen("nul", "w+", stderr);
		freopen("nul", "r", stdin);
		HANDLE devnul_handle = CreateFileA("nul", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if(devnul_handle == INVALID_HANDLE_VALUE) {
			FATAL("Unable to open the nul device.");
		}
		SetStdHandle(STD_INPUT_HANDLE, devnul_handle);
		SetStdHandle(STD_OUTPUT_HANDLE, devnul_handle);
		SetStdHandle(STD_ERROR_HANDLE, devnul_handle);
	}
}

extern "C" _declspec(noreturn) void harness_main()
{
	fuzzer_printf("Target hook reached!\n");
	fuzzer_printf("Unhooking early critical functions...\n");
	InlineUnhook(pNtProtectVirtualMemory, pOrgNtProtectVirtualMemory, THUNK_SIZE);
	InlineUnhook(pRtlAddVectoredExceptionHandler, pOrgRtlAddVectoredExceptionHandler, THUNK_SIZE);
	fuzzer_printf("-> OK!\n");

	// Setup a temporary handler because a breakpoint might get tripped while we are setting up!!!
	RemoveVectoredExceptionHandler(superEarlyHandler);
	superEarlyHandler = INVALID_HANDLE_VALUE;
	earlyHandler = AddVectoredExceptionHandler(TRUE, EarlyExceptionHandler);

	install_breakpoints();
	RestoreHookedBytes();

	SetupServer();
	
	if (harness_info->setup_func) {
		harness_info->setup_func();
	}
	
	if (fuzzer_settings.mode == DRYRUN)
	{
		SetupTarget();
		call_target(); // noreturn
	}
	else if (fuzzer_settings.mode == PERSISTENT)
	{
		SetupTarget();
		persistent_server(); // noreturn
	}
	else if (fuzzer_settings.mode == FORK)
	{
		forkserver(); // noreturn
	}
	else
	{
		FATAL("Invalid fuzzer mode");
	}
}

#ifdef _WIN64
extern "C" {
	CONTEXT savedContext;
	void FuzzingHarness(void);
}

__declspec(noreturn dllexport) void call_target()
{
	savedContext.Rip = (DWORD64)fuzz_iter_address;
	RtlRestoreContext(&savedContext, NULL);
	// the return address SHOULD be report_end
}

#else
uintptr_t savedEsp;
uint32_t savedregsEsp;
#define HARNESS_STACK_SIZE 0x40
__declspec(align(16)) uint8_t harnessStack[HARNESS_STACK_SIZE];
__declspec(align(64)) BYTE xsaveData[4096];

__declspec(noreturn dllexport) void call_target()
{
	_asm {
		// context switch to target.
		xor eax, eax;
		not eax;
		mov edx, eax;
		lea ecx, [xsaveData];
		xrstor[ecx];
		mov esp, [savedregsEsp];
		popfd;
		popad;
		mov esp, [savedEsp];

		// now in target context.
		call [fuzz_iter_address];

		// ANYTHING we do must be inside a new function as we have no longer have a stack frame.
		jmp [report_end];
	}
}

__declspec(naked) void FuzzingHarness(void) {
	_asm {
		// context switch to harness, first saving the context of target
		add esp, 4; // discard return address
		mov[savedEsp], esp;
		lea esp, [harnessStack + HARNESS_STACK_SIZE];
		pushad;
		pushfd;
		mov[savedregsEsp], esp;
		mov esp, [savedEsp]; // Stack pivot fucks up GetModuleHandleA ???
		sub esp, 0x1000; // Let's allocate some space... to just lubricate some things. Makes SetUnhandledExceptionHandler work(?)
		xor eax, eax;
		not eax;
		mov edx, eax;
		lea ecx, [xsaveData];
		xsave[ecx];
		// now we're in the harness context.
		jmp harness_main;
	}
}
#endif

static SYSTEM_INFO systemInfo;

void GuardTargetAddr() {
	DWORD dwOldProtect;
	MEMORY_BASIC_INFORMATION targetPageInfo;
	if (VirtualQuery(target_address, &targetPageInfo, sizeof(targetPageInfo)))
		VirtualProtect(target_address, 1, targetPageInfo.Protect | PAGE_GUARD, &dwOldProtect);
}

LONG WINAPI SuperEarlyExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{	
	if (singleStep)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		{
			fuzzer_printf("Expecting single step trap but instead received exception %08x!!! Likely the breakpoint handler is faulty!!", ExceptionInfo->ExceptionRecord->ExceptionCode);
		}

		debug_printf("single stepped, reapply the guard page\n");
		GuardTargetAddr();

		singleStep = 0;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		debug_printf("WOW!!! GUARD_PAGE!!! %p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

		uintptr_t fault_addr = (uintptr_t)ExceptionInfo->ExceptionRecord->ExceptionAddress;
		uintptr_t page_start = fault_addr - (fault_addr % systemInfo.dwPageSize);
		uintptr_t page_end = page_start + systemInfo.dwPageSize;
		uintptr_t ip = ExceptionInfo->ContextRecord->INSTRUCTION_POINTER;

		// we guess that it's unpacked if we're executing code in the same page as our target address.
		if (page_start <= (uintptr_t)target_address && (uintptr_t)target_address < page_end && page_start <= ip && ip < page_end) {
			debug_printf("unpacked?\n");
			AssembleTrampoline(target_address, (uintptr_t)FuzzingHarness, stolenBytes);
		}
		else {
			debug_printf("not executing target address yet... single step over the access\n");
			ExceptionInfo->ContextRecord->EFlags |= 0x100; // trap flag
			singleStep = 1;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

PVOID __stdcall MyRtlAddVectoredExceptionHandler(
	ULONG                       First,
	PVECTORED_EXCEPTION_HANDLER Handler
) {
	debug_printf("Intercepted call to RtlAddVectoredExceptionHandler(%d, %p)\n", First, Handler);

	// !First : don't care
	// superEarlyHandler == INVALID_HANDLE_VALUE : job done
	if (!First || superEarlyHandler == INVALID_HANDLE_VALUE)
		return pOrgRtlAddVectoredExceptionHandler(First, Handler);

	PVOID ret = pOrgRtlAddVectoredExceptionHandler(First, Handler);
	debug_printf("Added\n");
	RemoveVectoredExceptionHandler(superEarlyHandler);
	debug_printf("Removed Super Early\n");
	superEarlyHandler = pOrgRtlAddVectoredExceptionHandler(TRUE, SuperEarlyExceptionHandler);
	debug_printf("Added Super Early\n");
	return ret;
}

NTSTATUS __stdcall MyNtProtectVirtualMemory(
	HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG  NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
) {
	debug_printf("Intercepted call to NtProtectVirtualMemory(%p, %p, %08x, %08x, %p)\n", ProcessHandle, BaseAddress, *NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

	NTSTATUS ret = pOrgNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

	if (ProcessHandle == GetCurrentProcess()) {
		uintptr_t start = (uintptr_t)BaseAddress & ~(uintptr_t)(systemInfo.dwPageSize - 1);
		uintptr_t end = ((uintptr_t)BaseAddress + *NumberOfBytesToProtect + systemInfo.dwPageSize);
		if (start <= (uintptr_t)target_address && (uintptr_t)target_address <= end) {
			debug_printf("don't tamper my guard page!!!\n");
			GuardTargetAddr();
		}
	}

	return ret;
}

// FIXME: force end at accept() occurs crash
SOCKET __stdcall MyAccept(SOCKET s, sockaddr *addr, int *addrlen) {
	/*
	if (accept_count < 1) {
		trace_printf("reached at accept()\n");
		accept_count++;
		return (SOCKET)(9999);  // fixed number as socket
	}
	else {
		report_end();
	}
	*/
	debug_printf("Intercepted call to accept()\n");
	return (SOCKET)(8888);  // fixed number as socket
}

int __stdcall MyListen(SOCKET s, int backlog) {
	debug_printf("Intercepted call to listen()\n");
	return 0; // indicates no error
}

int __stdcall MyBind(SOCKET s, const sockaddr *addr, int namelen) {
	debug_printf("Intercepted call to bind()\n");
	return 0; // indicates no error
}

int __stdcall MyRecv(SOCKET s, char *buf, int len, int flags) {	
	if (recv_count < 1) {
		debug_printf("Intercepted call to recv(%d)\n", (int)s);
		recv_count++;

		// FIXME: we have to receive the output directory name
		//        now we manually read .cur_input
		FILE *fp;
		fp = fopen("out/.cur_input", "rb");
		if (!fp) {
			FATAL("Error opening pidfile.txt");
		}
		fseek(fp, 0, SEEK_END);
		int filesize = ftell(fp);
		fseek(fp, 0, SEEK_SET);		
		fread(buf, filesize, 1, fp);		
		buf[filesize] = 0;

		//debug
		//trace_printf("buf:%s\n", buf);
		//getc(fuzzer_stdin);
		fclose(fp);		

		return filesize; //FIXME: this will be the length from stdin
	}
	else {
		report_end();
	}
}

int __stdcall MySend(SOCKET s, const char *buf, int len, int flags) {
	debug_printf("Intercepted call to send()\n");
	return len;
}

int __stdcall MyIoctlsocket(SOCKET s, long cmd, u_long *argp) {
	debug_printf("Intercepted call to ioctlsocket()\n");
	return 0;  // indicates no error 
}

int __stdcall MySetsockopt(SOCKET s, int level, int optname, const char *optval, int optlen) {
	debug_printf("Intercepted call to setsockopt()\n");
	return 0;  // indicates no error
}

int __stdcall MySelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const timeval *timeout) {	
	debug_printf("Intercepted call to select()\n");
	//getc(fuzzer_stdin);

	// indicates no error	
	return 1;

	// original function
	//return pOrgSelect(nfds, readfds, writefds, exceptfds, timeout);
}

DWORD CALLBACK cbThreadStart(LPVOID hModule)
{
	// Create a console for printf
	AllocConsole();
	fuzzer_stdout = fopen("CONOUT$", "w+");
	fuzzer_stdin = fopen("CONIN$", "r");
	setvbuf(fuzzer_stdout, NULL, _IONBF, 0);
	setvbuf(fuzzer_stdin, NULL, _IONBF, 0);
	SetConsoleTitleA("Winnie -- Forkserver");

	// Wait for the AFL to signal us, to tell us that it finished writing the memory.
	while (forkserver_state == FORKSERVER_NOT_READY)
		Sleep(10);

	MemoryBarrier();
	
	switch(fuzzer_settings.mode)
	{
	case DRYRUN:
		report_coverage = afl_report_coverage;
		report_crashed = afl_report_crashed;
		report_end = afl_report_end;
		fuzzer_printf("Forkserver loaded - dryrun mode\n");
		break;
	case FORK:
		report_coverage = fork_report_coverage;
		report_crashed = fork_report_crashed;
		report_end = fork_report_end;
		fuzzer_printf("Forkserver loaded - forkserver mode\n");
		break;
	case PERSISTENT:
		report_coverage = afl_report_coverage;
		report_crashed = afl_report_crashed;
		report_end = persistent_report_end;
		fuzzer_printf("Forkserver loaded - persistent mode\n");
		break;
	default:
		FATAL("Invalid fuzzer mode");
	}

	// Get the name of pipe/event
	DWORD pid = GetCurrentProcessId();
	fuzzer_printf("Forkserver PID: %d\n", pid);
	snprintf(afl_pipe, sizeof(afl_pipe), AFL_FORKSERVER_PIPE "-%d", pid);
	debug_printf("afl_pipe: %s\n", afl_pipe);
	
	SYSTEM_INFO sys_info = { 0 };
	GetSystemInfo(&sys_info);
	DWORD cpu_core_count = sys_info.dwNumberOfProcessors;

	if (fuzzer_settings.mode == FORK) {
		snprintf(forkserver_child_pipe, sizeof(forkserver_child_pipe), "\\\\.\\pipe\\forkserver-children-%d", pid);
		childCpuAffinityMask = ~fuzzer_settings.cpuAffinityMask & ((1 << cpu_core_count) - 1);
	}

	fuzzer_printf("Timeout: %dms\n", fuzzer_settings.timeout);
	fuzzer_printf("Minidumps (WER): %s\n", fuzzer_settings.enableWER ? "enabled" : "disabled");
	fuzzer_printf("Processor affinity: 0x%x (%d cores)\n", fuzzer_settings.cpuAffinityMask, cpu_core_count);
	fuzzer_printf("Will look for minidumps in %s\n", fuzzer_settings.minidump_path);

	if (!SetProcessAffinityMask(GetCurrentProcess(), fuzzer_settings.cpuAffinityMask)) {
		FATAL("Failed to set process affinity");
	}
	
	// Load the harness
	fuzzer_printf("Loading harness: %s\n", fuzzer_settings.harness_name);
	hHarness = LoadLibraryA((LPSTR) fuzzer_settings.harness_name);
	if (!hHarness)
	{
		FATAL("Failed to load harness");
	}
	harness_info = (PHARNESS_INFO) GetProcAddress(hHarness, HARNESS_INFO_PROC);
	if (!harness_info)
	{
		FATAL("Missing harness info block!");
	}

	fuzzer_printf("Waiting for the harness...\n");
	// Wait until the harness is ready. This is really ugly, but it is simple.
	while (!(harness_info->ready))
		Sleep(10);

	MemoryBarrier();

	target_address = (BYTE*)harness_info->target_method;
	fuzz_iter_address = harness_info->fuzz_iter_func;
	fuzzer_printf("Target address: 0x%p | Iter address: 0x%p\n", target_address, fuzz_iter_address);

    // Network fuzzing mode
	if (harness_info->network == TRUE) {
		
		fuzzer_printf("We will hook network APIs\n");

		hLibWs2_32 = LoadLibraryA("Ws2_32.dll");
		if (hLibWs2_32 == NULL) {
			FATAL("failed to load library, gle = %d\n", GetLastError());				
		}

		pAccept = (LPVOID)GetProcAddress(hLibWs2_32, "accept");
		pListen = (LPVOID)GetProcAddress(hLibWs2_32, "listen");
		pBind   = (LPVOID)GetProcAddress(hLibWs2_32, "bind");
		pSend   = (LPVOID)GetProcAddress(hLibWs2_32, "send");
		pRecv   = (LPVOID)GetProcAddress(hLibWs2_32, "recv");
		pSelect = (LPVOID)GetProcAddress(hLibWs2_32, "select");
		pIoctlsocket = (LPVOID)GetProcAddress(hLibWs2_32, "ioctlsocket");
		pSetsockopt  = (LPVOID)GetProcAddress(hLibWs2_32, "setsockopt");
		

		InlineHook(pAccept, MyAccept, (PVOID*)& pOrgAccept, THUNK_SIZE);
		InlineHook(pListen, MyListen, (PVOID*)& pOrgListen, THUNK_SIZE);
		InlineHook(pBind,	MyBind,	  (PVOID*)& pOrgBind,	THUNK_SIZE);
		InlineHook(pSend,	MySend,   (PVOID*)& pOrgSend,	THUNK_SIZE);
		InlineHook(pRecv,	MyRecv,   (PVOID*)& pOrgRecv,	THUNK_SIZE);			
		InlineHook(pSetsockopt,  MySetsockopt,  (PVOID*)& pOrgSetsockopt,  THUNK_SIZE);
		InlineHook(pIoctlsocket, MyIoctlsocket, (PVOID*)& pOrgIoctlsocket, THUNK_SIZE);
		InlineHook(pSelect, MySelect, (PVOID*)& pOrgSelect, THUNK_SIZE);
	}

	// Hook the target address via guard page
	MEMORY_BASIC_INFORMATION targetPageInfo;
	DWORD dwOldProtect;
	VirtualQuery(target_address, &targetPageInfo, sizeof(targetPageInfo));
	VirtualProtect(target_address, 1, targetPageInfo.Protect | PAGE_GUARD, &dwOldProtect);

	// get NtCreateFile address
	pCreateFile = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");

	// get TerminateProcess address
	pTerminateProcess = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");
	pRtlExitUserProcess = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlExitUserProcess");

	pNtProtectVirtualMemory = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
	pRtlAddVectoredExceptionHandler = (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddVectoredExceptionHandler");

	GetSystemInfo(&systemInfo); // get the page size
	superEarlyHandler = AddVectoredExceptionHandler(TRUE, SuperEarlyExceptionHandler);

	fuzzer_printf("Early hooking critical functions...\n");
	InlineHook(pNtProtectVirtualMemory, MyNtProtectVirtualMemory, (PVOID*)& pOrgNtProtectVirtualMemory, THUNK_SIZE);
	InlineHook(pRtlAddVectoredExceptionHandler, MyRtlAddVectoredExceptionHandler, (PVOID*)& pOrgRtlAddVectoredExceptionHandler, THUNK_SIZE);
	fuzzer_printf("-> OK!\n");

	hPipeAfl = CreateNamedPipeA(afl_pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
	if (hPipeAfl == INVALID_HANDLE_VALUE)
	{
		FATAL("CreateNamedPipe");
	}

	fuzzer_printf("Connecting to AFL and returning control to main binary!\n");
	fflush(fuzzer_stdout);

	if (!ConnectNamedPipe(hPipeAfl, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) // This will block!
	{
		FATAL("ConnectNamedPipe");
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, cbThreadStart, hModule, NULL, NULL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

