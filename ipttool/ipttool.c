/*
Copyright 2018 Alex Ionescu. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and
   the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
   and the following disclaimer in the documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY ALEX IONESCU ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ALEX IONESCU
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and
should not be interpreted as representing official policies, either expressed or implied, of Alex Ionescu.
*/

#include <Windows.h>
#include <stdio.h>
#include <libipt.h>

#define IPT_TOOL_USE_MTC_TIMING_PACKETS     0x01
#define IPT_TOOL_USE_CYC_TIMING_PACKETS     0x02
#define IPT_TOOL_TRACE_KERNEL_MODE          0x04
#define IPT_TOOL_TRACE_ALL_MODE             0x08

#define IPT_TOOL_VALID_FLAGS                \
    (IPT_TOOL_USE_MTC_TIMING_PACKETS |      \
     IPT_TOOL_USE_CYC_TIMING_PACKETS |      \
     IPT_TOOL_TRACE_KERNEL_MODE |           \
     IPT_TOOL_TRACE_ALL_MODE)

FORCEINLINE
DWORD
ConvertToPASizeToSizeOption(
	_In_ DWORD dwSize
)
{
	DWORD dwIndex;

	//
	// Cap the size to 128MB. Sizes below 4KB will result in 0 anyway.
	//
	if (dwSize > (128 * 1024 * 1024))
	{
		dwSize = 128 * 1024 * 1024;
	}

	//
	// Find the nearest power of two that's set (align down)
	//
	BitScanReverse(&dwIndex, dwSize);

	//
	// The value starts at 4KB
	//
	dwIndex -= 12;
	return dwIndex;
}

BOOL
EnableIpt(
	VOID
)
{
	SC_HANDLE hScm, hSc;
	BOOL bRes;
	bRes = FALSE;

	//
	// Open a handle to the SCM
	//
	hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hScm != NULL)
	{
		//
		// Open a handle to the IPT Service
		//
		hSc = OpenService(hScm, L"Ipt", SERVICE_START);
		if (hSc != NULL)
		{
			//
			// Start it
			//
			bRes = StartService(hSc, 0, NULL);
			if ((bRes == FALSE) &&
				(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING))
			{
				//
				// If it's already started, that's OK
				//
				bRes = TRUE;
			}
			else if (bRes == FALSE)
			{
				wprintf(L"[-] Unable to start IPT Service (err=%d)\n",
					GetLastError());
				if (GetLastError() == ERROR_NOT_SUPPORTED)
				{
					wprintf(L"[-] This is likely due to missing PT support\n");
				}
			}

			//
			// Done with the service
			//
			CloseServiceHandle(hSc);
		}
		else
		{
			wprintf(L"[-] Unable to open IPT Service (err=%d). "
				L"Are you running Windows 10 1809?\n",
				GetLastError());
		}

		//
		// Done with the SCM
		//
		CloseServiceHandle(hScm);
	}
	else
	{
		wprintf(L"[-] Unable to open a handle to the SCM (err=%d)\n",
			GetLastError());
	}

	//
	// Return the result
	//
	return bRes;
}

BOOL
EnableAndValidateIptServices(
	VOID
)
{
	WORD wTraceVersion;
	DWORD dwBufferVersion;
	BOOL bRes;

	//
	// First enable IPT
	//
	bRes = EnableIpt();
	if (bRes == FALSE)
	{
		wprintf(L"[-] Intel PT Service could not be started!\n");
		goto Cleanup;
	}

	//
	// Next, check if the driver uses a dialect we understand
	//
	bRes = GetIptBufferVersion(&dwBufferVersion);
	if (bRes == FALSE)
	{
		wprintf(L"[-] Failed to communicate with IPT Service: (err=%d)\n",
			GetLastError());
		goto Cleanup;
	}
	if (dwBufferVersion != IPT_BUFFER_MAJOR_VERSION_CURRENT)
	{
		wprintf(L"[-] IPT Service buffer version is not supported: %d\n",
			dwBufferVersion);
		goto Cleanup;
	}

	//
	// Then, check if the driver uses trace versions we speak
	//
	bRes = GetIptTraceVersion(&wTraceVersion);
	if (bRes == FALSE)
	{
		wprintf(L"[-] Failed to get Trace Version from IPT Service (err=%d)\n",
			GetLastError());
		goto Cleanup;
	}
	if (wTraceVersion != IPT_TRACE_VERSION_CURRENT)
	{
		wprintf(L"[-] IPT Service trace version is not supported %d\n",
			wTraceVersion);
		goto Cleanup;
	}

Cleanup:
	//
	// Return result
	//
	return bRes;
}

BOOL
ConfigureTraceFlags(
	_In_ DWORD dwFlags,
	_Inout_ PIPT_OPTIONS pOptions
)
{
	BOOL bRes;
	bRes = FALSE;

	if (dwFlags & ~IPT_TOOL_VALID_FLAGS)
	{
		wprintf(L"[-] Invalid flags: %x\n", dwFlags);
		goto Cleanup;
	}

	//
	// If the user didn't specify MTC, but wants CYC, set MTC too as the IPT
	// driver wil enable those packets anyway.
	//
	if ((dwFlags & IPT_TOOL_USE_CYC_TIMING_PACKETS) &&
		!(dwFlags & IPT_TOOL_USE_MTC_TIMING_PACKETS))
	{
		wprintf(L"[*] CYC Packets require MTC packets, adjusting flags!\n");
		dwFlags |= IPT_TOOL_USE_MTC_TIMING_PACKETS;
	}

	//
	// If the user didn't specify MTC, but wants CYC, set MTC too as the IPT
	// driver wil enable those packets anyway.
	//
	if ((dwFlags & (IPT_TOOL_TRACE_KERNEL_MODE | IPT_TOOL_TRACE_ALL_MODE)) ==
		(IPT_TOOL_TRACE_KERNEL_MODE | IPT_TOOL_TRACE_ALL_MODE))
	{
		wprintf(L"[-] Cannot enable both `kernel` and `user + kernel` tracing."
			L" Please pick a single flag to use!\n");
		goto Cleanup;
	}

	//
	// There are no matching options for process tradces
	//
	pOptions->MatchSettings = IptMatchByAnyApp;

	//
	// Choose the right timing setting
	//
	if (dwFlags & IPT_TOOL_USE_MTC_TIMING_PACKETS)
	{
		pOptions->TimingSettings = IptEnableMtcPackets;
		pOptions->MtcFrequency = 3; // FIXME
	}
	else if (dwFlags & IPT_TOOL_USE_CYC_TIMING_PACKETS)
	{
		pOptions->TimingSettings = IptEnableCycPackets;
		pOptions->CycThreshold = 1; // FIXME
	}
	else
	{
		pOptions->TimingSettings = IptNoTimingPackets;
	}

	//
	// Choose the right mode setting
	//
	if (dwFlags & IPT_TOOL_TRACE_KERNEL_MODE)
	{
		pOptions->ModeSettings = IptCtlKernelModeOnly;
	}
	else if (dwFlags & IPT_TOOL_TRACE_ALL_MODE)
	{
		pOptions->ModeSettings = IptCtlUserAndKernelMode;
	}
	else
	{
		pOptions->ModeSettings = IptCtlUserModeOnly;
	}

	//
	// Print out chosen options
	//
	bRes = TRUE;
	/*wprintf(L"[+] Tracing Options:\n"
			L"           Match by: %s\n"
			L"         Trace mode: %s\n"
			L"     Timing packets: %s\n",
			L"Any process",
			(pOptions->ModeSettings == IptCtlUserAndKernelMode) ?
			L"Kernel and user-mode" :
			(pOptions->ModeSettings == IptCtlKernelModeOnly) ?
			L"Kernel-mode only" : L"User-mode only",
			(pOptions->TimingSettings == IptEnableMtcPackets) ?
			L"MTC Packets" :
			(pOptions->TimingSettings == IptEnableCycPackets) ?
			L"CYC Packets" : L"No  Packets");*/

Cleanup:
	//
	// Return result
	//
	return bRes;
}

BOOL
ConfigureBufferSize(
	_In_ DWORD dwSize,
	_Inout_ PIPT_OPTIONS pOptions
)
{
	BOOL bRes;
	bRes = FALSE;

	//
	// Warn the user about incorrect values
	//
	if (!((dwSize) && ((dwSize & (~dwSize + 1)) == dwSize)))
	{
		wprintf(L"[*] Size will be aligned to a power of 2\n");
	}
	else if (dwSize < 4096)
	{
		wprintf(L"[*] Size will be set to minimum of 4KB\n");
	}
	else if (dwSize > (128 * 1024 * 1024))
	{
		wprintf(L"[*] Size will be set to a maximum of 128MB\n");
	}

	//
	// Compute the size option
	//
	pOptions->TopaPagesPow2 = ConvertToPASizeToSizeOption(dwSize);
	bRes = TRUE;
	/*wprintf(L"[+] Using size: %d bytes\n",
			1 << (pOptions->TopaPagesPow2 + 12));*/

			//
			// Return result
			//
	return bRes;
}

PIPT_TRACE_DATA GetIptTrace(HANDLE hProcess)
{
	BOOL bRes;
	DWORD dwTraceSize;
	PIPT_TRACE_DATA pTraceData;

	//
	// Get the size of the trace
	//
	bRes = GetProcessIptTraceSize(hProcess, &dwTraceSize);
	if (bRes == FALSE)
	{
		wprintf(L"[-] Failed to query trace size (err=%d). "
			L"Are you sure one is active?\n",
			GetLastError());
		return NULL;
	}

	//
	// Allocate a local buffer
	//
	pTraceData = HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		dwTraceSize);
	if (pTraceData == NULL)
	{
		wprintf(L"[-] Out of memory while trying to allocate trace data\n");
		return NULL;
	}

	//
	// Query the trace
	//
	// wprintf(L"[+] Found active trace with %d bytes so far\n", dwTraceSize);
	bRes = GetProcessIptTrace(hProcess, pTraceData, dwTraceSize);
	if (bRes == FALSE)
	{
		wprintf(L"[-] Failed to query trace (err=%d)\n",
			GetLastError());
		return NULL;
	}

	return pTraceData;
}