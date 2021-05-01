#pragma once

#include <stdbool.h>
#include <winternl.h> // CLIENT_ID

#include "../forkserver-proto.h"

#define DEBUGGER_PROCESS_EXIT       0
#define DEBUGGER_FUZZMETHOD_REACHED 1
#define DEBUGGER_FUZZMETHOD_END     2
#define DEBUGGER_CRASHED            3
#define DEBUGGER_HANGED             4
#define DEBUGGER_ERROR              5 // some weird unknown error

#define COVERAGE_BB 0

#define BREAKPOINT_UNKNOWN      0
#define BREAKPOINT_ENTRYPOINT   1
#define BREAKPOINT_MODULELOADED 2
#define BREAKPOINT_FUZZMETHOD   3
#define BREAKPOINT_BB           4

#ifdef _WIN64
#define INSTRUCTION_POINTER Rip
#else
#define INSTRUCTION_POINTER Eip
#endif

typedef struct _forkserver_option_t {
	bool debug_mode;
	int coverage_kind;
	char fuzz_harness[MAX_PATH+1];
	char minidump_path[MAX_PATH+1];
	void *fuzz_address;
	bool enable_wer; // enable Windows Error Reporting
} forkserver_option_t;

extern forkserver_option_t options;

void forkserver_options_init(int argc, const char *argv[]);
void load_bbs(char *bbfile);
CLIENT_ID spawn_child_with_injection(char* cmd, INJECTION_MODE injection_type, uint32_t timeout, uint32_t init_timeout);
void resume_child();
int get_child_result();
void kill_process();

void get_coverage_info(u32 *visited_bbs_out, u32 *total_bbs_out);

typedef struct _CHILD_IDS
{
	DWORD ProcessId;
	DWORD ThreadId;
} CHILD_IDS;

// --- Fork mode ---
DWORD spawn_forkserver(char** argv, uint32_t timeout, uint32_t init_timeout);
CHILD_IDS fork_new_child();
int fork_run_child();

// --- Persistent mode ---
void reset_persistent();
void start_persistent(char** argv, uint32_t timeout, uint32_t init_timeout);
int run_with_persistent();

struct winafl_breakpoint {
	int type;
	struct _module_info_t* module;
    int file_offset;
	uintptr_t rva;
    unsigned char original_opcode;
	BOOL visited;
	int id;
    struct winafl_breakpoint *next;
};
struct winafl_breakpoint *breakpoints;

// HERE'S HOW YOU USE THE FORKSERVER API.
// A. DRY-RUN MODE
// 1. spawn_child_with_injection()
// Spawns a child process with the harness injected in a SUSPENDED state.
// The harness has not run yet but it IS injected and the target hooks are in place.
// 2. resume_child()
// Now you need to RESUME the child process so the program will run and it will get
// to the harness hook.
// 3. get_child_result()
// Now you need to consume all of the results from the pipe from the child, such as
// the coverage events and whatever.
// 4. kill_process()
// The process will wait for YOU to kill it, will not kill itself! This method
// also will close all the handles and whatever.
//
// B. FORK MODE
// 1. spawn_forkserver()
// Spawn a forkserver first if there isn't one yet. You only need to do this ONCE.
// This will do spawn_child_with_injection(), resume_child() for you
// 2. fork_new_child()
// Forks a new child ready to execute the target function in a SUSPENDED state.
// 3. fork_run_child()
// RESUMES the awaiting child and runs the target function. This will give you a PID
// of the child that you need to use later to kill it once it finishes.
// 4. get_child_result()
// You need to consume the fuzzing events from the pipe, or else it will have junk
// that will cause an error next iteration.
// 5. TerminateProcess()
// You need to MANUALLY kill the child. It will wait for YOU to clean it up.
//
// C. PERSISTENT MODE
// 1. start_persistent()
// Spin up the persistent-mode daemon. This is similar to spawn_forkserver().
// You only need to do this ONCE. It will SUSPEND when it gets to the target function.
// 2. run_with_persistent()
// RESUMES the daemon and iterates the target function once. It will SELF-SUSPEND at the end
// unless it crashes or hangs. This will also take care of the pipe stuff for you so
// don't bother with get_child_result(). Just run this over and over again

