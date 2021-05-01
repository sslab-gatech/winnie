// Forkserver Protocol
//
// This file defines structs and constants shared between the main fuzzer exe and the injected forkserver DLL.

#pragma once

#include <stdint.h>

// These structures are written directly into the forkserver's memory during initialization.
// They hold fuzzer settings that we want to pass to the forkserver.

typedef volatile struct _AFL_COVERAGE_INFO
{
	size_t NumberOfBasicBlocks;
	struct AFL_BASIC_BLOCK
	{
		char* ModuleName;
		uintptr_t Rva;
	} BasicBlocks[];
} AFL_COVERAGE_INFO;

typedef enum _INJECTION_MODE
{
	DRYRUN = 0,
	FORK,
	PERSISTENT,
} INJECTION_MODE;

typedef volatile struct _AFL_SETTINGS
{
	uint32_t timeout;
	INJECTION_MODE mode;
	AFL_COVERAGE_INFO* cov_info; // If NULL, coverage is not reported and external tracing is assumed
	BOOL enableWER; // Enable minidumps
	BOOL debug; // Enable debugging
	DWORD_PTR cpuAffinityMask; // Affinity mask for the forkserver. Never put the children on the same processor!
	char harness_name[MAX_PATH+1];
	char minidump_path[MAX_PATH+1];
} AFL_SETTINGS;

typedef enum _FORKSERVER_STATE
{
	FORKSERVER_NOT_READY,
	FORKSERVER_READY,
	FORKSERVER_WAITING
} FORKSERVER_STATE;

// These structures define the API passed over the named pipe IPC

#define AFL_FORKSERVER_SYNC "Global\\harness-sync"
#define AFL_FORKSERVER_PIPE "\\\\.\\pipe\\afl-forkserver"

enum AFL_FORKSERVER_REQUEST_METHOD
{
	AFL_CREATE_NEW_CHILD = 0, // Please spawn a new child!
	AFL_RESUME_CHILD,         // Please start the suspended child.
	AFL_TERMINATE_FORKSERVER, // Please kill yourself.
};

typedef struct _AFL_FORKSERVER_REQUEST
{
	enum AFL_FORKSERVER_REQUEST_METHOD Operation;  //added enum 
	union
	{
		struct
		{
			BYTE DoNotUseThisField;
		}
		CreateNewChildInfo;

		struct
		{
			BYTE DoNotUseThisField;
		}
		ResumeChildInfo;
	};
} AFL_FORKSERVER_REQUEST;

enum AFL_FORKSERVER_RESULT_STATUS
{
	AFL_CHILD_CREATED = 0,
	AFL_CHILD_SUCCESS,
	AFL_CHILD_CRASHED,
	AFL_CHILD_TIMEOUT,
	AFL_CHILD_COVERAGE, // new coverage event
};

typedef struct _AFL_FORKSERVER_RESULT
{	
	enum AFL_FORKSERVER_RESULT_STATUS StatusCode;
	union
	{
		struct AFL_CHILD_INFO
		{
			DWORD ProcessId;
			DWORD ThreadId;
		} ChildInfo;
		struct
		{
			BYTE DoNotUseThisField;
		} SuccessInfo;
		struct
		{
			BYTE DoNotUseThisField;
		} CrashInfo;
		struct
		{
			BYTE DoNotUseThisField;
		} TimeoutInfo;
		struct AFL_COVERAGE_PACKET
		{
			char ModuleName[MAX_PATH];
			uintptr_t Rva;
		} CoverageInfo;
	};	
} AFL_FORKSERVER_RESULT, AFL_PERSISTENT_RESULT;

enum CHILD_FATE
{
	CHILD_UNKNOWN = -1, // error?
	CHILD_SUCCESS = 0,
	CHILD_CRASHED,
	CHILD_TIMEOUT,
	CHILD_COVERAGE, // new coverage
};
