// Harness API
//
// This file defines an interface fuzzing harnesses must expose for the injected forkserver.

#pragma once

#include <stdint.h>
#include <Windows.h>

// Unfortunately, no stdatomic without VS 2019.

typedef volatile struct
{
	LPVOID target_method;			   // Required. The function to hook. The injected component of fuzzer will hook this function and enter the fuzzing loop once it is hit.
	void (CALLBACK *fuzz_iter_func)(); // Required. Target function to fuzz. The injected forkserver will call this function repeatedly. The function should follow stdcall convention and return gracefully.
	const WCHAR* input_file;           // Optional. The input filename that the fuzzer will mutate; for example, L"my_input.txt". If NULL, defaults to L".cur_input".
	void (CALLBACK *setup_func)();     // Optional. If not NULL, a function that will be called after the target process initializes, before entering the forkserver loop.
	                                   // You might want to use setup_func for doing things like marking all of the handles as inheritable, killing other threads, closing problematic handles, etc.
	BOOL network;                      // Optional. If true, apply de-socket techniques (redirects Winsock APIs)
	volatile CHAR ready;               // Required. Set this to true only when all the other struct members are populated and ready.
} HARNESS_INFO, *PHARNESS_INFO;

#define HARNESS_INFO_PROC "HarnessInfo"

#define EXPOSE_HARNESS(target_method, fuzz_iter_func, preload, input_file, setup_func, network) \
	extern "C" { \
		__declspec(dllexport) HARNESS_INFO HarnessInfo = { \
		target_method, \
		fuzz_iter_func, \
		input_file, \
		setup_func, \
		network, \
		}; \
	};
