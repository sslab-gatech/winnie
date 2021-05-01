// injected-harness.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "exports.h"

__declspec(dllexport) AFL_SETTINGS fuzzer_settings;
__declspec(dllexport) volatile FORKSERVER_STATE forkserver_state = FORKSERVER_NOT_READY;
