#pragma once

// https://codereview.chromium.org/1456343002/patch/20001/30001
// https://github.com/begoon/stuff/blob/master/windows/ntfork/main.cpp
// https://doxygen.reactos.org/d6/d18/basemsg_8h_source.html
// Size should be 0x108.
// From kernelbase.dll!CreateProcessInternalW: CsrClientCallServer(&v345, v232, 0x10000i64, 0x108i64);
typedef struct _BASE_CREATE_PROCESS {
	HANDLE ProcessHandle;
	HANDLE ThreadHandle;
	CLIENT_ID ClientId;
	ULONG CreationFlags;
	ULONG VdmBinaryType;
	ULONG VdmTask;
	HANDLE hVDM;
	PVOID something_sxs[23];  // Notice how this is one less on windows 10. Undocumented magic lol (24 on Win7)
	PVOID PebAddressNative;
	PVOID unk0;
	USHORT ProcessorArchitecture;
} BASE_CREATE_PROCESS, *PBASE_CREATE_PROCESS;

// No longer used in Win10, judging from basesrv.dll, the dispatch table entry now points to BaseSrvDeadEntry.
typedef struct _BASE_CREATE_THREAD
{
	HANDLE ThreadHandle;
	CLIENT_ID ClientId;
} BASE_CREATE_THREAD, *PBASE_CREATE_THREAD;

// WoW64 -- need to explicitly specify all pointer types as 64-bit, not 32-bit since csrss uses the x64 structs.
typedef struct {
	ULONGLONG ProcessHandle;
	ULONGLONG ThreadHandle;
	CLIENT_ID64 ClientId;
	ULONG CreationFlags;
	ULONG VdmBinaryType;
	ULONG VdmTask;
	ULONGLONG hVDM;
	ULONGLONG something_sxs[23];  // Notice how this is one less on windows 10. Undocumented magic lol (24 on Win7)
	ULONGLONG PebAddressNative;
	ULONGLONG unk0;
	USHORT ProcessorArchitecture;
} BASE_CREATE_PROCESS64, *PBASE_CREATE_PROCESS64;

typedef struct _BASE_CREATE_THREAD64
{
	ULONGLONG ThreadHandle;
	CLIENT_ID64 ClientId;
} BASE_CREATE_THREAD64, *PBASE_CREATE_THREAD64;

// This is documented here:
// http://www.geoffchappell.com/studies/windows/win32/csrsrv/api/apireqst/api_msg.htm
struct CSR_CAPTURE_HEADER;

typedef struct
{
	PORT_MESSAGE h;
	CSR_CAPTURE_HEADER *CaptureBuffer;
	ULONG ApiNumber;
	ULONG ReturnValue;
	ULONG Reserved;

	union
	{
		BASE_CREATE_PROCESS CreateProcessRequest;
		BASE_CREATE_THREAD CreateThreadRequest;
		ULONG_PTR ApiMessageData[0x2E];
	};
} CSR_API_MSG, *PCSR_API_MESSAGE;

// WoW64 version with 64-bit pointer types
typedef struct
{
	PORT_MESSAGE64 h;
	ULONGLONG CaptureBuffer;
	ULONG ApiNumber;
	ULONG ReturnValue;
	ULONG Reserved;
	union
	{
		BASE_CREATE_PROCESS64 CreateProcessRequest;
		BASE_CREATE_THREAD64 CreateThreadRequest;
		ULONG_PTR ApiMessageData[0x2E];
	};
} CSR_API_MSG64, *PCSR_API_MESSAGE64;


// https://github.com/mic101/windows/blob/master/WRK-v1.2/public/sdk/inc/ntcsrmsg.h
typedef ULONG CSR_API_NUMBER;

#define CSR_MAKE_API_NUMBER( DllIndex, ApiIndex ) \
    (CSR_API_NUMBER)(((DllIndex) << 16) | (ApiIndex))

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

// Windows Server 2003 table from http://j00ru.vexillium.org/csrss_list/api_list.html#Windows_2k3
// See basesrv.dll!BaseServerApiDispatchTable
typedef enum _BASESRV_API_NUMBER
{
	BasepCreateProcess = BASESRV_FIRST_API_NUMBER,
	BasepCreateThread, // No longer used in Win10
	// Rest don't matter lol
} BASESRV_API_NUMBER, *PBASESRV_API_NUMBER;;

// High and low words of ApiNumber determine which API routine to call
// NTSTATUS __stdcall CsrClientCallServer(PCSR_API_MESSAGE ApiMessage, PCSR_CAPTURE_BUFFER CaptureBuffer, CSR_API_NUMBER ApiNumber, ULONG DataLength)
typedef NTSTATUS(WINAPI *CsrClientCallServer_t)(PCSR_API_MESSAGE ApiMsg, PVOID CaptureBuffer, ULONG ApiNumber, ULONG ApiMessageDataSize);
typedef NTSTATUS(WINAPI *CsrClientCallServer64_t)(PCSR_API_MESSAGE64 ApiMsg, PVOID CaptureBuffer, ULONG ApiNumber, ULONG ApiMessageDataSize);

typedef NTSTATUS(NTAPI *CsrClientConnectToServer_t)(
	IN PWSTR ObjectDirectory,
	IN ULONG ServerId,
	IN PVOID ConnectionInfo,
	IN ULONG ConnectionInfoSize,
	OUT PBOOLEAN ServerToServerCall
	);

extern CsrClientConnectToServer_t CsrClientConnectToServer;
extern CsrClientCallServer_t CsrClientCallServer;
extern CsrClientCallServer64_t CsrClientCallServer64;

#include "csrss_offsets.h"
