// Fullspeed interface for fuzzer
//
// This file provides a streamlined API for AFL to run the target process using the forkserver.
// It also implements a watchdog timer to monitor the forkserver for hangs and timeouts.
//
// In persistent mode, the watchdog is the only way we detect timeouts.

#include <Windows.h>

#include <stdint.h>

#include "types.h"
#include "config.h"
#include "debug.h"

#include "afl.h"
#include "forkserver.h"
#include "fullspeed.h"

static volatile uint64_t watchdog_timeout_time;
static volatile bool watchdog_enabled;

static void arm_watchdog_timer(uint64_t timeout)
{
	// Strictly speaking, on MSVC (with /volatile:ms which is default on x86) volatile is write-release read-acquire
	// so we don't really NEED barriers here. Yet here we are because MSVC is, like gcc,
	// a crappy compiler with a billion nonstandard extensions
	watchdog_timeout_time = get_cur_time() + timeout;
	MemoryBarrier(); // VS2017 has no C11, so no stdatomic.h, so no atomic_signal_fence().
	watchdog_enabled = true;
	_WriteBarrier(); // release barrier
}

static void fullspeed_options_init(int argc, const char** argv) {
	char bbfile[MAX_PATH];

	for (int i = 0; i < argc; i++) {
		const char *token = argv[i];
		if (strcmp(token, "-bbfile") == 0) {
			if (i + 1 >= argc) FATAL("missing bb-filename");
			strncpy(bbfile, argv[++i], sizeof(bbfile));
		} else {
			FATAL("UNRECOGNIZED FULLSPEED OPTION: \"%s\"\n", token);
		}
	}

	if (!*bbfile) {
		FATAL("No basic blocks file specified!\n");
	}

	load_bbs(bbfile);
}

// Main fullspeed/forkserver init entrypoint
int fullspeed_init(int argc, char **argv) {
	watchdog_enabled = false;

	int last_fullspeed_option = -1;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			last_fullspeed_option = i;
			break;
		}
	}
	if (last_fullspeed_option <= 0) return 0;
	fullspeed_options_init(last_fullspeed_option - 1, argv + 1);

	int lastoption = -1;
	for (int i = last_fullspeed_option + 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			lastoption = i;
			break;
		}
	}
	if (lastoption <= 0) return 0;

	forkserver_options_init(lastoption - last_fullspeed_option - 1, argv + last_fullspeed_option + 1);

	return lastoption;
}

// FORK MODE
static int run_target_fullspeed_fork(char **argv, uint32_t timeout, uint32_t init_timeout, int drun) {
	//trace_printf("\nRUNNING TARGET WITH FORK: forkserver pid = %d\n", forksrv_pid);		
	int ret = -1, ret_status = -1;
	if (drun == 1) {
		arm_watchdog_timer((init_timeout + timeout) * 2);
		char *cmd = argv_to_cmd(argv);
		spawn_child_with_injection(cmd, DRYRUN, timeout, init_timeout);
		resume_child();
		ret_status = get_child_result();
		kill_process();
	}
	else {
		arm_watchdog_timer(timeout * 2);
		if (forksrv_pid < 0) {
			// No forkserver yet, let's spin one up.
			forksrv_pid = spawn_forkserver(argv, timeout, init_timeout);
		}
		CHILD_IDS child_ids = fork_new_child();
		if (!child_ids.ProcessId) {
			ret_status = DEBUGGER_ERROR;
		} else {
			HANDLE hProcess_child = OpenProcess(PROCESS_ALL_ACCESS, FALSE, child_ids.ProcessId);
			if (!hProcess_child) {
				FATAL("failed to open forked process!");
			}
			if (!fork_run_child())
				return DEBUGGER_ERROR;
			ret_status = get_child_result();
			TerminateProcess(hProcess_child, 0);
			CloseHandle(hProcess_child); // DO NOT LEAK HANDLES IT WILL MAKE AFL CRASH FEW HOURS LATER
		}
	}

	if (get_cur_time() > watchdog_timeout_time || ret_status == DEBUGGER_HANGED) {
		ret = FAULT_TMOUT;
	}
	else if (ret_status == DEBUGGER_PROCESS_EXIT) {
		ret = FAULT_NONE;
	}
	else if (ret_status == DEBUGGER_CRASHED) {
		ret = FAULT_CRASH;
	}
	else if (ret_status == DEBUGGER_ERROR) {
		kill_process();
		forksrv_pid = -1;
		ret = FAULT_ERROR;
	}

	return ret;
}

// Persistent mode.
static int run_target_fullspeed_persistent(char **argv, uint32_t timeout, uint32_t init_timeout, int drun) {
	int ret = -1, ret_status = -1;

	if (drun == 1) {
		// Dry run
		arm_watchdog_timer((init_timeout + timeout) * 2);
		char *cmd = argv_to_cmd(argv);
		spawn_child_with_injection(cmd, DRYRUN, timeout, init_timeout);
		resume_child();
		ret_status = get_child_result();
		kill_process();
	} else {
		arm_watchdog_timer(timeout * 2);
		if (persistent_pid < 0) {
			//ACTF("Launch new persistent server\n");
			start_persistent(argv, timeout, init_timeout);
		}
		// Normal execution
		ret_status = run_with_persistent();
	}

	if (get_cur_time() > watchdog_timeout_time || ret_status == DEBUGGER_HANGED) {
		ret = FAULT_TMOUT;
	}
	else if (ret_status == DEBUGGER_PROCESS_EXIT) {
		ret = FAULT_NONE;
	}
	else if (ret_status == DEBUGGER_CRASHED) {
		ret = FAULT_CRASH;
	}
	else if (ret_status == DEBUGGER_ERROR) {
		ret = FAULT_ERROR;
	}

	return ret;
}

int run_target_fullspeed(char **argv, uint32_t timeout, uint32_t init_timeout, int drun) {
	if (use_fork)
		return run_target_fullspeed_fork(argv, timeout, init_timeout, drun);
	else
		return run_target_fullspeed_persistent(argv, timeout, init_timeout, drun);
}

void destroy_target_process() {
	kill_process();
}

static DWORD CALLBACK watchdog_timer_thread(HANDLE hMainThread) {
	while (!stop_soon) {
		if (!watchdog_enabled) {
			Sleep(50);
			continue;
		}
		MemoryBarrier(); // want acquire barrier here
		uint64_t now = get_cur_time();
		if (watchdog_timeout_time > now) {
			Sleep(watchdog_timeout_time - now);
			continue;
		}

		// timeout detected
		trace_printf("Watchdog timeout\n");
		SuspendThread(hMainThread); // LOL resolve race conditions by just temporarily suspending the other thread.
		kill_process();
		CancelSynchronousIo(hMainThread);
		watchdog_enabled = false;
		MemoryBarrier();
		ResumeThread(hMainThread);
	}
	return 0;
}

void setup_watchdog_timer() {
	HANDLE hThisThread;
	BOOL succ = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &hThisThread, THREAD_ALL_ACCESS, FALSE, 0);
	if (!succ) {
		dank_perror("DuplicateHandle");
	}
	HANDLE hThread = CreateThread(NULL, 0, watchdog_timer_thread, hThisThread, 0, NULL);
	CloseHandle(hThread);
}
