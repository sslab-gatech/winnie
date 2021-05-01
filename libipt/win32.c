#include <Windows.h>
#include <libipt.h>
#include <ipt.h>

FORCEINLINE
VOID
InitializeIptBuffer(
	_Inout_ PIPT_INPUT_BUFFER pBuffer,
	_In_ IPT_INPUT_TYPE dwInputType
)
{
	//
	// Zero it out and set the version
	//
	ZeroMemory(pBuffer, sizeof(*pBuffer));
	pBuffer->BufferMajorVersion = IPT_BUFFER_MAJOR_VERSION_CURRENT;
	pBuffer->BufferMinorVersion = IPT_BUFFER_MINOR_VERSION_CURRENT;

	//
	// Set the type
	//
	pBuffer->InputType = dwInputType;
}

FORCEINLINE
BOOL
OpenIptDevice(
	_Out_ PHANDLE phFile
)
{
	//
	// Open the handle
	//
	*phFile = CreateFile(L"\\??\\IPT",
		FILE_GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL |
		FILE_FLAG_SEQUENTIAL_SCAN |
		FILE_FLAG_NO_BUFFERING,
		NULL);

	//
	// Return the result
	//
	return (*phFile == INVALID_HANDLE_VALUE) ? FALSE : TRUE;
}

BOOL
GetIptBufferVersion(
	_Out_ PDWORD pdwBufferMajorVersion
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_BUFFER_VERSION outputBuffer;

	//
	// Initialize for failure
	//
	*pdwBufferMajorVersion = 0;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send only the version header of the input request.
		// The type is unused.
		//
		InitializeIptBuffer(&inputBuffer, -1);
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(IPT_BUFFER_VERSION),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		CloseHandle(hIpt);

		//
		// On success, return the buffer version
		//
		if (bRes != FALSE)
		{
			*pdwBufferMajorVersion = outputBuffer.BufferMajorVersion;
		}
	}
	return bRes;
}

BOOL
GetIptTraceVersion(
	_Out_ PWORD pwTraceVersion
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Initialize for failure
	//
	*pwTraceVersion = 0;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to get the trace version
		//
		InitializeIptBuffer(&inputBuffer, IptGetTraceVersion);
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		CloseHandle(hIpt);

		//
		// On success, return the buffer version
		//
		if (bRes != FALSE)
		{
			*pwTraceVersion = outputBuffer.GetTraceVersion.TraceVersion;
		}
	}
	return bRes;
}

BOOL
GetProcessIptTraceSize(
	_In_ HANDLE hProcess,
	_Out_ PDWORD pdwTraceSize
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Initialize for failure
	//
	*pdwTraceSize = 0;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to get the trace size for the process
		//
		InitializeIptBuffer(&inputBuffer, IptGetProcessTraceSize);
		inputBuffer.GetProcessIptTraceSize.TraceVersion = IPT_TRACE_VERSION_CURRENT;
		inputBuffer.GetProcessIptTraceSize.ProcessHandle = (ULONG64)hProcess;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		CloseHandle(hIpt);

		//
		// Check if we got a size back
		//
		if (bRes != FALSE)
		{
			//
			// The IOCTL layer supports > 4GB traces but this doesn't exist yet
			// Otherwise, return the 32-bit trace size.
			//
			if (outputBuffer.GetTraceSize.TraceSize <= ULONG_MAX)
			{
				*pdwTraceSize = (DWORD)outputBuffer.GetTraceSize.TraceSize;
			}
			else
			{
				//
				// Mark this as a failure -- this is the Windows behavior too
				//
				SetLastError(ERROR_IMPLEMENTATION_LIMIT);
				bRes = FALSE;
			}
		}
	}
	return bRes;
}

BOOL
GetProcessIptTrace(
	_In_ HANDLE hProcess,
	_In_ PVOID pTrace,
	_In_ DWORD dwTraceSize
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;

	//
	// The trace comes as part of an output buffer, so that part is required
	//
	bRes = FALSE;
	if (dwTraceSize < UFIELD_OFFSET(IPT_OUTPUT_BUFFER, GetTrace.TraceSize))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return bRes;
	}

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to get the trace for the process
		//
		InitializeIptBuffer(&inputBuffer, IptGetProcessTrace);
		inputBuffer.GetProcessIptTrace.TraceVersion = IPT_TRACE_VERSION_CURRENT;
		inputBuffer.GetProcessIptTrace.ProcessHandle = (ULONG64)hProcess;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_READ_TRACE,
			&inputBuffer,
			sizeof(inputBuffer),
			pTrace,
			dwTraceSize,
			NULL,
			NULL);
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
StartProcessIptTracing(
	_In_ HANDLE hProcess,
	_In_ IPT_OPTIONS ullOptions
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to start tracing for this process
		//
		InitializeIptBuffer(&inputBuffer, IptStartProcessTrace);
		inputBuffer.StartProcessIptTrace.Options = ullOptions;
		inputBuffer.StartProcessIptTrace.ProcessHandle = (ULONG64)hProcess;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
StopProcessIptTracing(
	_In_ HANDLE hProcess
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to stop tracing for this process
		//
		InitializeIptBuffer(&inputBuffer, IptStopProcessTrace);
		inputBuffer.StopProcessIptTrace.ProcessHandle = (ULONG64)hProcess;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
StartCoreIptTracing(
	_In_ IPT_OPTIONS ullOptions,
	_In_ DWORD dwNumberOfTries,
	_In_ DWORD dwTraceDurationInSeconds
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to start tracing for all the processor cores
		//
		InitializeIptBuffer(&inputBuffer, IptStartCoreTracing);
		inputBuffer.StartCoreIptTracing.Options = ullOptions;
		inputBuffer.StartCoreIptTracing.NumberOfTries = dwNumberOfTries;
		inputBuffer.StartCoreIptTracing.TraceDurationInSeconds = dwTraceDurationInSeconds;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
RegisterExtendedImageForIptTracing(
	_In_ PWCHAR pwszImagePath,
	_In_opt_ PWCHAR pwszFilteredPath,
	_In_ IPT_OPTIONS ullOptions,
	_In_ DWORD dwNumberOfTries,
	_In_ DWORD dwTraceDurationInSeconds
)
{
	BOOL bRes;
	WORD wPathLength, wFilterLength;
	DWORD dwInputLength;
	HANDLE hIpt;
	PIPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Compute the size of the image path, and input buffer containing it
		//
		wPathLength = (WORD)(wcslen(pwszImagePath) + 1) * sizeof(WCHAR);
		dwInputLength = wPathLength + sizeof(*inputBuffer);

		//
		// Add the IFEO filter path size if it was passed in
		//
		if (pwszFilteredPath != NULL)
		{
			wFilterLength = (WORD)(wcslen(pwszFilteredPath) + 1) * sizeof(WCHAR);
			dwInputLength += wFilterLength;
		}

		//
		// Allocate the input buffer. Mimic Windows here by not using the heap.
		//
		inputBuffer = VirtualAlloc(NULL,
			dwInputLength,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (inputBuffer != NULL)
		{
			//
			// Initialize a request for registering the given process
			//
			InitializeIptBuffer(inputBuffer, IptRegisterExtendedImageForTracing);
			inputBuffer->RegisterExtendedImageForIptTracing.Options = ullOptions;
			inputBuffer->RegisterExtendedImageForIptTracing.NumberOfTries = dwNumberOfTries;
			inputBuffer->RegisterExtendedImageForIptTracing.TraceDurationInSeconds = dwTraceDurationInSeconds;

			//
			// Copy the image path
			//
			inputBuffer->RegisterExtendedImageForIptTracing.ImagePathLength = wPathLength;
			CopyMemory(inputBuffer->RegisterExtendedImageForIptTracing.ImageName,
				pwszImagePath,
				wPathLength);

			//
			// Copy the filter path if it was present
			//
			if (pwszFilteredPath != NULL)
			{
				inputBuffer->RegisterExtendedImageForIptTracing.FilteredPathLength = wFilterLength;
				CopyMemory((PVOID)((DWORD_PTR)inputBuffer->RegisterExtendedImageForIptTracing.ImageName + wPathLength),
					pwszFilteredPath,
					wFilterLength);
			}
			else
			{
				inputBuffer->RegisterExtendedImageForIptTracing.FilteredPathLength = 0;
			}

			//
			// Send the request
			//
			bRes = DeviceIoControl(hIpt,
				IOCTL_IPT_REQUEST,
				&inputBuffer,
				sizeof(inputBuffer),
				&outputBuffer,
				sizeof(outputBuffer),
				NULL,
				NULL);

			//
			// Free the input buffer
			//
			VirtualFree(inputBuffer, 0, MEM_RELEASE);
		}
		else
		{
			//
			// Set failure since we're out of memory
			//
			bRes = FALSE;
		}
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
PauseThreadIptTracing(
	_In_ HANDLE hThread,
	_In_ PBOOLEAN pbResult
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to pause tracing for the given thread
		//
		InitializeIptBuffer(&inputBuffer, IptPauseThreadTrace);
		inputBuffer.PauseThreadIptTrace.ThreadHandle = (ULONG64)hThread;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		if (bRes != FALSE)
		{
			//
			// Result whether or not the thread was tracing or not
			//
			*pbResult = outputBuffer.PauseTrace.OldState;
		}
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
ResumeThreadIptTracing(
	_In_ HANDLE hThread,
	_In_ PBOOLEAN pbResult
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to resume tracing for the given thread
		//
		InitializeIptBuffer(&inputBuffer, IptResumeThreadTrace);
		inputBuffer.ResumeThreadIptTrace.ThreadHandle = (ULONG64)hThread;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		if (bRes != FALSE)
		{
			//
			// Return whether or not the thread was tracing or not
			//
			*pbResult = outputBuffer.ResumeTrace.OldState;
		}
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
QueryProcessIptTracing(
	_In_ HANDLE hProcess,
	_Out_ PIPT_OPTIONS pullOptions
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to check if the process has any tracing options set
		//
		InitializeIptBuffer(&inputBuffer, IptQueryProcessTrace);
		inputBuffer.QueryProcessIptTrace.ProcessHandle = (ULONG64)hProcess;
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		if (bRes != FALSE)
		{
			//
			// Return the current set of options that are active
			//
			*pullOptions = outputBuffer.QueryProcessTrace.Options;
		}
		CloseHandle(hIpt);
	}
	return bRes;
}

BOOL
QueryCoreIptTracing(
	_Out_ PIPT_OPTIONS pullOptions
)
{
	BOOL bRes;
	HANDLE hIpt;
	IPT_INPUT_BUFFER inputBuffer;
	IPT_OUTPUT_BUFFER outputBuffer;

	//
	// Open the IPT Device
	//
	bRes = OpenIptDevice(&hIpt);
	if (bRes != FALSE)
	{
		//
		// Send a request to check if the processor has any tracing options set
		//
		InitializeIptBuffer(&inputBuffer, IptQueryCoreTrace);
		bRes = DeviceIoControl(hIpt,
			IOCTL_IPT_REQUEST,
			&inputBuffer,
			sizeof(inputBuffer),
			&outputBuffer,
			sizeof(outputBuffer),
			NULL,
			NULL);
		if (bRes != FALSE)
		{
			//
			// Return the current set of options that are active
			//
			*pullOptions = outputBuffer.QueryCoreTrace.Options;
		}
		CloseHandle(hIpt);
	}
	return bRes;
}

