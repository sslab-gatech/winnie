#pragma once

/* Execution status fault codes */

enum {
	/* 00 */ FAULT_NONE,
	/* 01 */ FAULT_TMOUT,
	/* 02 */ FAULT_CRASH,
	/* 03 */ FAULT_ERROR,
	/* 04 */ FAULT_NOINST,
	/* 05 */ FAULT_NOBITS
};

u64 get_cur_time(void);
char *argv_to_cmd(char** argv);

extern volatile u8 stop_soon;

extern u8 use_fork;
extern u8 use_fullspeed;
extern u8 use_intelpt;
extern u8 forkserver_same_console;

extern s32 forksrv_pid;
extern s32 persistent_pid;

extern u32 queued_paths;
extern char run_dryrun;
extern u8 *out_dir;
extern u8 *trace_bits;
extern u8 *binary_name;
extern char *out_file;
extern char no_trim;

extern u64 mem_limit;
extern u64 cpu_aff;
extern u64 total_execs;

extern char *fuzzer_id;
extern struct winafl_breakpoint *breakpoints;

char *argv_to_cmd(char** argv);
char *alloc_printf(const char *_str, ...);
