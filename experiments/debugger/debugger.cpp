#include "pch.h"
#include <tchar.h>
#include <stdio.h>

#define NUM_ITER 50
void ReportCreateProcessEvent(DWORD ProcessId, DWORD ThreadId, const CREATE_PROCESS_DEBUG_INFO& Event)
{
	_tprintf(_T("\nEVENT: Process creation\n"));

	_tprintf(_T("  ProcessId:                %u\n"), ProcessId);
	_tprintf(_T("  ThreadId:                 %u\n"), ThreadId);

	_tprintf(_T("  CREATE_PROCESS_DEBUG_INFO members:\n"));
	_tprintf(_T("    hFile:                  %08p\n"), Event.hFile);
	_tprintf(_T("    hProcess:               %08p\n"), Event.hProcess);
	_tprintf(_T("    hThread                 %08p\n"), Event.hThread);
	_tprintf(_T("    lpBaseOfImage:          %08p\n"), Event.lpBaseOfImage);
	_tprintf(_T("    dwDebugInfoFileOffset:  %08x\n"), Event.dwDebugInfoFileOffset);
	_tprintf(_T("    nDebugInfoSize:         %08x\n"), Event.nDebugInfoSize);
	_tprintf(_T("    lpThreadLocalBase:      %08p\n"), Event.lpThreadLocalBase);
	_tprintf(_T("    lpStartAddress:         %08p\n"), Event.lpStartAddress);
	_tprintf(_T("    lpImageName:            %08p\n"), Event.lpImageName);
	_tprintf(_T("    fUnicode:               %u\n"), Event.fUnicode);

}

void ReportExceptionEvent(DWORD ProcessId, DWORD ThreadId, const EXCEPTION_DEBUG_INFO& Event)
{
	_tprintf(_T("\nEVENT: Exception\n"));

	_tprintf(_T("  ProcessId:                %u\n"), ProcessId);
	_tprintf(_T("  ThreadId:                 %u\n"), ThreadId);

	_tprintf(_T("  EXCEPTION_DEBUG_INFO members:\n"));
	_tprintf(_T("    dwFirstChance:          %u\n"), Event.dwFirstChance);
	_tprintf(_T("    EXCEPTION_RECORD members:\n"));
	_tprintf(_T("      ExceptionCode:        %08x\n"), Event.ExceptionRecord.ExceptionCode);
	_tprintf(_T("      ExceptionFlags:       %08x\n"), Event.ExceptionRecord.ExceptionFlags);
	_tprintf(_T("      ExceptionRecord:      %08p\n"), Event.ExceptionRecord.ExceptionRecord);
	_tprintf(_T("      ExceptionAddress:     %08p\n"), Event.ExceptionRecord.ExceptionAddress);
	_tprintf(_T("      NumberParameters:     %u\n"), Event.ExceptionRecord.NumberParameters);

	DWORD NumParameters = Event.ExceptionRecord.NumberParameters;

	if (NumParameters > EXCEPTION_MAXIMUM_PARAMETERS)
		NumParameters = EXCEPTION_MAXIMUM_PARAMETERS;

	for (DWORD i = 0; i < NumParameters; i++)
		_tprintf(_T("      ExceptionInformation[%d]:     %08p\n"), i, Event.ExceptionRecord.ExceptionInformation[i]);

}

void ReportTimeout(DWORD Timeout)
{
	_tprintf(_T("\nTIMEOUT: %u milliseconds\n"), Timeout);
}


void ReportCreateThreadEvent(DWORD ProcessId, DWORD ThreadId, const CREATE_THREAD_DEBUG_INFO& Event)
{
	_tprintf(_T("\nEVENT: Thread creation\n"));

	_tprintf(_T("  ProcessId:                %u\n"), ProcessId);
	_tprintf(_T("  ThreadId:                 %u\n"), ThreadId);

	_tprintf(_T("  CREATE_THREAD_DEBUG_INFO members:\n"));
	_tprintf(_T("    hThread                 %08p\n"), Event.hThread);
	_tprintf(_T("    lpThreadLocalBase:      %08p\n"), Event.lpThreadLocalBase);
	_tprintf(_T("    lpStartAddress:         %08p\n"), Event.lpStartAddress);

}


void ReportExitProcessEvent(DWORD ProcessId, DWORD ThreadId, const EXIT_PROCESS_DEBUG_INFO& Event)
{
	_tprintf(_T("\nEVENT: Process exit\n"));

	_tprintf(_T("  ProcessId:                %u\n"), ProcessId);
	_tprintf(_T("  ThreadId:                 %u\n"), ThreadId);

	_tprintf(_T("  EXIT_PROCESS_DEBUG_INFO members:\n"));
	_tprintf(_T("    dwExitCode:             %u\n"), Event.dwExitCode);

}

void ReportExitThreadEvent(DWORD ProcessId, DWORD ThreadId, const EXIT_THREAD_DEBUG_INFO& Event)
{
	_tprintf(_T("\nEVENT: Thread exit\n"));

	_tprintf(_T("  ProcessId:                %u\n"), ProcessId);
	_tprintf(_T("  ThreadId:                 %u\n"), ThreadId);

	_tprintf(_T("  EXIT_THREAD_DEBUG_INFO members:\n"));
	_tprintf(_T("    dwExitCode:             %u\n"), Event.dwExitCode);

}

bool DebugLoop(DWORD Timeout)
{
	// Run the debug loop and handle the events 

	DEBUG_EVENT DebugEvent;

	bool bContinue = true;

	bool bSeenInitialBreakpoint = false;

	while (bContinue)
	{
		// Call WaitForDebugEvent 

		if (WaitForDebugEvent(&DebugEvent, Timeout))
		{
			// Handle the debug event 

			DWORD ContinueStatus = DBG_CONTINUE;

			switch (DebugEvent.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
				ReportCreateProcessEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId,
					DebugEvent.u.CreateProcessInfo);

				// With this event, the debugger receives the following handles:
				//   CREATE_PROCESS_DEBUG_INFO.hProcess - debuggee process handle
				//   CREATE_PROCESS_DEBUG_INFO.hThread  - handle to the initial thread of the debuggee process
				//   CREATE_PROCESS_DEBUG_INFO.hFile    - handle to the executable file that was 
				//                                        used to create the debuggee process (.EXE file)
				// 
				// hProcess and hThread handles will be closed by the operating system 
				// when the debugger calls ContinueDebugEvent after receiving 
				// EXIT_PROCESS_DEBUG_EVENT for the given process
				// 
				// hFile handle should be closed by the debugger, when the handle 
				// is no longer needed
				//

				{
					HANDLE hFile = DebugEvent.u.CreateProcessInfo.hFile;

					if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
					{
						if (!CloseHandle(hFile))
						{
							_tprintf(_T("CloseHandle(hFile) failed. Error: %u\n"), GetLastError());
						}
					}
				}

				break;

			case EXIT_PROCESS_DEBUG_EVENT:
				ReportExitProcessEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId,
					DebugEvent.u.ExitProcess);
				bContinue = false; // Last event - exit the loop
				break;

			case CREATE_THREAD_DEBUG_EVENT:
				ReportCreateThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId,
					DebugEvent.u.CreateThread);

				// With this event, the debugger receives the following handle:
				//   CREATE_THREAD_DEBUG_INFO.hThread  - handle to the thread that has been created
				// 
				// This handle will be closed by the operating system 
				// when the debugger calls ContinueDebugEvent after receiving 
				// EXIT_THREAD_DEBUG_EVENT for the given thread
				// 

				break;

			case EXIT_THREAD_DEBUG_EVENT:
				ReportExitThreadEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId,
					DebugEvent.u.ExitThread);
				break;

			case LOAD_DLL_DEBUG_EVENT:

				// With this event, the debugger receives the following handle:
				//   LOAD_DLL_DEBUG_INFO.hFile    - handle to the DLL file 
				// 
				// This handle should be closed by the debugger, when the handle 
				// is no longer needed
				//

			{
				HANDLE hFile = DebugEvent.u.LoadDll.hFile;

				if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
				{
					if (!CloseHandle(hFile))
					{
						_tprintf(_T("CloseHandle(hFile) failed. Error: %u\n"), GetLastError());
					}
				}
			}

			// Note: Closing the file handle here can lead to the following side effect:
			//   After the file has been closed, the handle value will be reused 
			//   by the operating system, and if the next "load dll" debug event 
			//   comes (for another DLL), it can contain the file handle with the same 
			//   value (but of course the handle now refers to that another DLL). 
			//   Don't be surprised!
			//

			break;

			case UNLOAD_DLL_DEBUG_EVENT:

				break;

			case OUTPUT_DEBUG_STRING_EVENT:

				break;

			case RIP_EVENT:

				break;

			case EXCEPTION_DEBUG_EVENT:
				ReportExceptionEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId,
					DebugEvent.u.Exception);

				// By default, do not handle the exception 
				// (let the debuggee handle it if it wants to)

				ContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

				// Now the special case - the initial breakpoint 

				DWORD ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;

				if (!bSeenInitialBreakpoint && (ExceptionCode == EXCEPTION_BREAKPOINT))
				{
					// This is the initial breakpoint, which is used to notify the debugger 
					// that the debuggee has initialized 
					// 
					// The debugger should handle this exception
					// 

					//printf("breakpoint\n");
					ContinueStatus = DBG_CONTINUE;

					bSeenInitialBreakpoint = true;

				}

				//printf("DEB_EXCEPTION not handled\n");
				break;
			}

			// Let the debuggee continue 

			if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, ContinueStatus))
			{
				_tprintf(_T("ContinueDebugEvent() failed. Error: %u \n"), GetLastError());
				return false;
			}


			// Proceed to the beginning of the loop...

		}
		else
		{
			// WaitForDebugEvent failed...

			// Is it because of timeout ?

			DWORD ErrCode = GetLastError();

			if (ErrCode == ERROR_SEM_TIMEOUT)
			{
				// Yes, report timeout and continue 
				//ReportTimeout(Timeout);
			}
			else
			{
				// No, exit the loop
				printf(("WaitForDebugEvent() failed. Error: %u \n"), GetLastError());
				return false;
			}
		}
	}


	// Complete 

	return true;

}

int main(int argc, char** argv)
{
	if (argc != 3)
	{
		printf("Usage: %s pid eventptr\n", argv[0]);
		exit(1);
	}
	DWORD pid = atoi(argv[1]);
	DWORD eventptr = atoi(argv[2]);
	printf("Wow %d %p\n", pid, eventptr);
	getc(stdin);
	DebugActiveProcess(pid);
	DebugLoop(10);
	DebugActiveProcessStop(pid);
	getc(stdin);
}
