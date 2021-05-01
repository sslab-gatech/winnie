#pragma once

#include "../forkserver-proto.h"

extern "C" {
	extern __declspec(dllexport) AFL_SETTINGS fuzzer_settings;
	extern __declspec(dllexport) volatile FORKSERVER_STATE forkserver_state;
	extern __declspec(noreturn dllexport) void call_target();
};
