#include "pch.h"

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <conio.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>

#include <forklib.h>

#define DEBUG_LOG_FILE "C:\\sslab\\temp.log"
const char* remove_cmd = "del " DEBUG_LOG_FILE;
LONGLONG pid;

void createConsole()
{
	AllocConsole();
	freopen_s((FILE**)stdout, "CONOUT$", "w+", stdout);
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
}

void check_fwrite(int usefork, int dryrun) {
	FILE *fp;
	fp = fopen(DEBUG_LOG_FILE, "a");
	if (!fp) return; // sometimes the file is locked or some BS like that
	fprintf(fp, "fork:%d, dry:%d\n", usefork, dryrun);
	fclose(fp);
}

LARGE_INTEGER time()
{
	LARGE_INTEGER now;
	QueryPerformanceCounter(&now);
	return now;
}

void* lol;
int forkCount = 0;

int child()
{
	//Sleep(1000 * 20);
	//getc(stdin);
	printf("Hello!!!\n");
	check_fwrite(pid, forkCount);

	Sleep(5); // Simulate some work

	//DebugBreak(); // give a breakpoint to debugger.
	((int*)lol)[forkCount % 1000];

	printf("We need to talk.\n");
	BYTE message[1] = { 0x69 };
	DWORD nRead;
	BYTE response[1];
	BOOL result = CallNamedPipeA("\\\\.\\pipe\\fuzzer", message, sizeof(message), response, sizeof(response), &nRead, NMPWAIT_WAIT_FOREVER);
	printf("Okay, goodbye.\n");	
	TerminateProcess(GetCurrentProcess(), 0);
	return 0;
}

#define NUM_ITER 80

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	system(remove_cmd);

	// just initialize some data to make it more work to fork.
	void* lol = HeapAlloc(GetProcessHeap(), 0, 12345);
	memset(lol, 0x90, 12345);

	// don't display error dialog on crash.
	//SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

	// needed or child will crash upon exiting when under the debugger
	MarkAllHandles();

	FreeConsole();
	createConsole();

	HANDLE hConnectEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	OVERLAPPED overlapped;
	RtlZeroMemory(&overlapped, sizeof(overlapped));
	overlapped.hEvent = hConnectEvent;
	HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\fuzzer", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf("CreateNamedPipe failed with %d.\n", GetLastError());
		return 0;
	}

	if (ConnectNamedPipe(hPipe, &overlapped))
	{
		printf("ConnectNamedPipe failed with %d.\n", GetLastError());
		return 0;
	}

	DWORD numChildren = 0;
	std::vector<HANDLE> waitHandles;
	waitHandles.push_back(overlapped.hEvent);

	// forkserver
	LARGE_INTEGER start = time();
	do
	{
		// careful waitHandles.size() must never exceed MAXIMUM_WAIT_OBJECTS !!!
		DWORD waitResult = WaitForMultipleObjects(waitHandles.size(), waitHandles.data(), FALSE, 0);
		if (waitResult == WAIT_OBJECT_0)
		{
			DWORD nRead;
			BYTE message[1];
			BYTE response[1] = { 0x69 };
			if (!GetOverlappedResult(hPipe, &overlapped, &nRead, TRUE))
			{
				printf("GetOverlappedResult failed = %d ?!!!!!\n", GetLastError());
			}
			printf("Pipe connected\n");

			if (!ReadFile(hPipe, message, sizeof(message), NULL, &overlapped))
			{
				printf("Rx: %d!!!!!\n", GetLastError());
			}
			if (!GetOverlappedResult(hPipe, &overlapped, &nRead, TRUE))
			{
				printf("Read error %d!!!!!\n", GetLastError());
			}
			printf("Rx done. Got %02x\n", message[0]);

			if (!WriteFile(hPipe, response, sizeof(response), NULL, &overlapped))
			{
				printf("Tx: %d!!!!!\n", GetLastError());
			}
			if (!GetOverlappedResult(hPipe, &overlapped, &nRead, TRUE))
			{
				printf("Write error: %d!!!!!\n", GetLastError());
			}
			printf("Tx done.\n");

			DisconnectNamedPipe(hPipe);

			if (ConnectNamedPipe(hPipe, &overlapped))
			{
				printf("ConnectNamedPipe failed with %d.\n", GetLastError());
				return 0;
			}
			else if (GetLastError() == ERROR_PIPE_CONNECTED)
			{
				printf("Love me\n");
				SetEvent(overlapped.hEvent);
			}
			else if (GetLastError() != ERROR_IO_PENDING)
			{
				printf("ConnectNamedPipe failed with %d.\n", GetLastError());
				return 0;
			}
		}
		else if (waitResult > WAIT_OBJECT_0  && waitResult < WAIT_ABANDONED_0)
		{
			int index = waitResult - WAIT_OBJECT_0;
			HANDLE hProcess = waitHandles[index];
			printf("Process %d (pid %d) finished\n", index, GetProcessId(hProcess));
			waitHandles.erase(waitHandles.begin() + index);
			numChildren--;
		}

		if (forkCount < NUM_ITER && numChildren < MAXIMUM_WAIT_OBJECTS - 1)
		{
			// spawn new child with fork
			PROCESS_INFORMATION pi;
			pid = fork(&pi);
			if (pid == -1)
			{
				printf("fork FAILED!");
				getc(stdin);
				break;
			}
			else if (pid) // parent
			{
				//printf("pid: %d, count:%d\n", pid, forkCount);
				forkCount++;
				numChildren++;
				waitHandles.push_back(pi.hProcess);
				printf("%d\n", forkCount);
			}
			else //child (pid==0)
			{
				return child();
			}
		}
	} while (forkCount < NUM_ITER || numChildren);

	LARGE_INTEGER end = time();
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	double elapsed = (end.QuadPart - start.QuadPart) / (double)freq.QuadPart;
	printf("Took %f seconds\n", elapsed);
	printf("approxi. %f exec/sec , %f ms/exec\n", NUM_ITER / elapsed, elapsed * 1000 / NUM_ITER);
	getc(stdin);
	return 0;
}
