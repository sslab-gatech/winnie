#include "utils.h"
#ifdef INTELPT
#define  _CRT_SECURE_NO_WARNINGS

#include <vector>
#include <map>

#include <stdio.h>
#include <stdint.h>

#include <Windows.h>
#include <direct.h> // for _mkdir
#include <Psapi.h>
#include <intrin.h>

#include <forklib.h>

extern "C"
{
#include <libipt.h>
#include <ipttool.h>
#include <intel-pt.h>
#include <internal/pt_cpu.h>
}

extern "C"
{
#include "debug.h"
#include "ptdecode.h"

#include "winaflpt.h"
#include "afl.h"
#include "forkserver.h"
}

#define DECODER_TIP_FAST 0
#define DECODER_TIP_REFERENCE 1
#define DECODER_FULL_FAST 2
#define DECODER_FULL_REFERENCE 3

typedef struct _pt_option_t {
	int decoder;
	unsigned long trace_buffer_size;
	unsigned long winipt_ring_buffer_size;
	std::vector<std::string> coverage_modules;
} pt_option_t;
static pt_option_t pt_options;

static char section_cache_dir[MAX_PATH];

class pt_image_wrapper;
class module_cache;

struct module_info_t {
	char module_name[MAX_PATH];
	char tmpfilename[MAX_PATH];
	int isid;
	void *base;
	size_t size;
};

class pt_image_wrapper
{
	module_cache& modules;
	struct pt_image *image = NULL;
public:
	pt_image_wrapper(module_cache& module_cache);
	pt_image_wrapper(pt_image_wrapper& other) = delete; // NO COPYING
	pt_image_wrapper(pt_image_wrapper&& other) noexcept;
	~pt_image_wrapper();
	pt_image_wrapper& operator=(pt_image_wrapper& other) = delete; // NO COPYING
	pt_image_wrapper& operator=(pt_image_wrapper&& other) noexcept;
	
	operator pt_image*() const { return image; }
};

class module_cache
{
	friend class pt_image_wrapper;

	std::map<uint64_t, module_info_t> loaded_modules;
	pt_image_section_cache *section_cache;

public:
	module_cache();
	module_cache(module_cache& other) = delete; // NO COPYING
	module_cache(module_cache&& other) noexcept;
	~module_cache();
	module_cache& module_cache::operator=(module_cache& other) = delete; // NO COPYING
	module_cache& module_cache::operator=(module_cache&& other) noexcept;

	module_info_t *get_loaded_module(char *module_name, void *base);
	module_info_t *get_intersecting_module(void *base, DWORD size);
	void add_module(module_info_t&);
	pt_image_wrapper setup_pt_image() { return pt_image_wrapper(*this); }
};

class fuzz_process
{
	module_cache module_cache;
	unsigned char *trace_buffer = NULL;
	size_t trace_size = 0;
	size_t last_ring_buffer_offset = 0;

	int fuzz_thread_id = 0;
	uint64_t fuzz_ip = 0;

	size_t ReadProcessMemory_tolerant(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);
	int get_all_modules(std::vector<HMODULE>& modules);
	void add_module_to_section_cache(HMODULE module, char *module_name);

	void append_trace_data(unsigned char *trace_data, size_t append_size);
	bool collect_thread_trace(PIPT_TRACE_HEADER traceHeader);
	bool collect_trace(PIPT_TRACE_DATA pTraceData);
	
public:
	HANDLE hProcess = NULL;
	
	fuzz_process() {}
	fuzz_process(fuzz_process& other) = delete;
	fuzz_process(fuzz_process&& other) noexcept;
	fuzz_process::fuzz_process(HANDLE hProcess);
	~fuzz_process();
	fuzz_process& fuzz_process::operator=(fuzz_process& other) = delete; // NO COPYING
	fuzz_process& fuzz_process::operator=(fuzz_process&& other) noexcept;
	operator HANDLE() const { return hProcess; }
	int update_modules();
	int process_traces();
	void start_tracing(HANDLE hThread);
	void stop_tracing();
	void kill();
};

pt_image_wrapper::pt_image_wrapper(module_cache& module_cache) : modules(module_cache)
{
	image = pt_image_alloc("winafl_image");
	for (const auto& it : modules.loaded_modules) {
		const module_info_t& cur_module = it.second;
		if (cur_module.isid > 0) {
			int ret = pt_image_add_cached(image, modules.section_cache, cur_module.isid, NULL);
		}
	}
}

pt_image_wrapper::~pt_image_wrapper()
{
	if (image)
		pt_image_free(image);
}

pt_image_wrapper::pt_image_wrapper(pt_image_wrapper&& other) noexcept : modules(other.modules), image(other.image)
{
	other.image = NULL;
}

pt_image_wrapper& pt_image_wrapper::operator=(pt_image_wrapper&& other) noexcept
{
	image = other.image;
	modules = std::move(other.modules);
	other.image = NULL;
	return *this;
}

module_cache::module_cache()
{
	section_cache = pt_iscache_alloc("winafl_cache");
}

module_cache::~module_cache()
{
	if (section_cache)
		pt_iscache_free(section_cache);
}

module_cache::module_cache(module_cache&& other) noexcept : loaded_modules(std::move(other.loaded_modules)), section_cache(other.section_cache)
{
	other.section_cache = NULL;
}

module_cache& module_cache::operator=(module_cache&& other) noexcept
{
	loaded_modules = std::move(other.loaded_modules);
	section_cache = std::move(other.section_cache);
	other.section_cache = NULL;
	return *this;
}

// check if the same module was already loaded
module_info_t* module_cache::get_loaded_module(char *module_name, void *base) {
	if (base)
	{
		auto it = loaded_modules.find((uint64_t)base);
		if (it == loaded_modules.end()) return NULL;
		if (_stricmp(it->second.module_name, module_name)) return NULL;
		return &it->second;
	}
	for (auto& it : loaded_modules) {
		if (_stricmp(module_name, it.second.module_name) == 0) {
			return &it.second;
		}
	}
	return NULL;
}

// find if there is a *different* module that previously occupied
// the same space
module_info_t* module_cache::get_intersecting_module(void *base, DWORD size) {
	uint64_t upper = (uint64_t)base + size;
	for (auto it = loaded_modules.begin(); it != loaded_modules.end(); ++it) {
		module_info_t& current_module = it->second;
		if ((uint64_t)current_module.base > upper) break;
		if ((uint64_t)current_module.base + current_module.size > (uint64_t)base) {
			return &current_module;
		}
	}
	return NULL;
}

void module_cache::add_module(module_info_t& loaded_module) {
	if (pt_options.decoder == DECODER_FULL_REFERENCE || pt_options.decoder == DECODER_FULL_FAST)
	{
		loaded_module.isid = pt_iscache_add_file(section_cache, loaded_module.tmpfilename, 0, loaded_module.size, (uint64_t)loaded_module.base);
		if (loaded_module.isid <= 0) {
			FATAL("Error adding file to pt cache.");
		}
	}
	loaded_modules[(uint64_t)loaded_module.base] = loaded_module;
	//printf("debug: cached %s (%p) in tmpfile %s, isid %d\n", loaded_module.module_name, loaded_module.base, loaded_module.tmpfilename, loaded_module.isid);
}

fuzz_process::fuzz_process(HANDLE hProcess)
{
	this->hProcess = hProcess;
	//printf("hprocess = %x\n", hProcess);
	fuzz_thread_id = 0;
	fuzz_ip = 0;
	trace_size = 0;
	trace_buffer = (unsigned char *)malloc(pt_options.trace_buffer_size);
	last_ring_buffer_offset = 0;
}

fuzz_process::~fuzz_process()
{
	//printf("Bye\n");
	free(trace_buffer);
	trace_buffer = 0;
	trace_size = 0;
	fuzz_thread_id = 0;
	if (hProcess)
		CloseHandle(hProcess);
	hProcess = NULL;
}

fuzz_process::fuzz_process(fuzz_process&& other) noexcept : hProcess(other.hProcess), module_cache(std::move(other.module_cache)), fuzz_thread_id(other.fuzz_thread_id), trace_size(other.trace_size), trace_buffer(other.trace_buffer), last_ring_buffer_offset(other.last_ring_buffer_offset), fuzz_ip(other.fuzz_ip)
{
	other.hProcess = NULL;
	other.trace_buffer = NULL;
}

fuzz_process& fuzz_process::operator=(fuzz_process&& other) noexcept
{
	hProcess = other.hProcess;
	module_cache = std::move(other.module_cache);
	other.hProcess = NULL;
	fuzz_thread_id = other.fuzz_thread_id;
	trace_size = other.trace_size;
	trace_buffer = other.trace_buffer;
	other.trace_buffer = NULL;
	last_ring_buffer_offset = other.last_ring_buffer_offset;
	fuzz_ip = other.fuzz_ip;
	return *this;
}

size_t fuzz_process::ReadProcessMemory_tolerant(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
	LPCVOID end_address = (char *)lpBaseAddress + nSize;
	LPCVOID cur_address = lpBaseAddress;
	MEMORY_BASIC_INFORMATION meminfobuf;
	SIZE_T size_read;
	size_t total_size_read = 0;

	while (cur_address < end_address) {
		size_t ret = VirtualQueryEx(hProcess, (LPCVOID)cur_address, &meminfobuf, sizeof(MEMORY_BASIC_INFORMATION));
		if (!ret) break;

		size_t offset = (size_t)meminfobuf.BaseAddress - (size_t)lpBaseAddress;
		size_t to_read = meminfobuf.RegionSize;
		if ((offset + to_read) > nSize) {
			to_read = nSize - offset;
		}

		if (ReadProcessMemory(hProcess, meminfobuf.BaseAddress, (char *)lpBuffer + offset, to_read, &size_read)) {
			total_size_read += size_read;
		}

		cur_address = (char *)meminfobuf.BaseAddress + meminfobuf.RegionSize;
	}

	return total_size_read;
}

int fuzz_process::get_all_modules(std::vector<HMODULE>& modules) {
	modules.resize(1024);
	DWORD hmodules_size;
	while (true) {
		if (!EnumProcessModulesEx(hProcess, &modules[0], modules.capacity() * sizeof(HMODULE), &hmodules_size, LIST_MODULES_ALL)) {
			return 0;
		}
		if (hmodules_size % sizeof(HMODULE)) FATAL("WTF, uneven hmodules_size?");
		if (hmodules_size <= modules.capacity() * sizeof(HMODULE))
		{
			modules.resize(hmodules_size / sizeof(HMODULE));
			break;
		}
		modules.resize(modules.capacity() * 2);
	}
	return 1;
}

void fuzz_process::add_module_to_section_cache(HMODULE module, char *module_name) {
	MODULEINFO module_info;
	GetModuleInformation(hProcess, module, &module_info, sizeof(module_info));

	// handle the case where module was loaded previously
	if (module_cache.get_loaded_module(module_name, module_info.lpBaseOfDll)) {
		// same module loaded on the same address, skip
		return;
	}

	// this will *probably* never happen but check for it anyway
	module_info_t *intersecting_module = module_cache.get_intersecting_module(module_info.lpBaseOfDll, module_info.SizeOfImage);
	if (intersecting_module) {
		FATAL("Module %s loaded in the address range that module %s previously occupied. This is currently unsupported.",
			module_name, intersecting_module->module_name);
	}

	module_info_t loaded_module;
	strncpy(loaded_module.module_name, module_name, sizeof(loaded_module.module_name));
	loaded_module.base = module_info.lpBaseOfDll;
	loaded_module.size = module_info.SizeOfImage;

	// todo put these files in a separate directory and clean it periodically
	if (pt_options.decoder == DECODER_FULL_REFERENCE || pt_options.decoder == DECODER_FULL_FAST)
	{
		snprintf(loaded_module.tmpfilename, sizeof(loaded_module.tmpfilename), "%s\\sectioncache_%p.dat", section_cache_dir, module_info.lpBaseOfDll);

		BYTE *modulebuf = (BYTE *)malloc(module_info.SizeOfImage);
		SIZE_T num_read;
		if (!ReadProcessMemory(hProcess, module_info.lpBaseOfDll, modulebuf, module_info.SizeOfImage, &num_read) || (num_read != module_info.SizeOfImage)) {
			if (!ReadProcessMemory_tolerant(module_info.lpBaseOfDll, modulebuf, module_info.SizeOfImage)) {
				FATAL("Error reading memory for module %s", module_name);
			}
		}

		// this is pretty horrible, writing a file only to be read again
		// but libipt only supports reading sections from file, not memory
		FILE *fp = fopen(loaded_module.tmpfilename, "wb");
		if (!fp) {
			FATAL("Error opening image cache file.");
		}
		fwrite(modulebuf, 1, module_info.SizeOfImage, fp);
		fclose(fp);
		free(modulebuf);
	}

	module_cache.add_module(loaded_module);
}

int fuzz_process::update_modules()
{
	std::vector<HMODULE> modules;
	if (!get_all_modules(modules))
		return 0;
	//printf("there are %llu modules\n", modules.size());
	for (HMODULE mod : modules)
	{
		char base_name[MAX_PATH];
		GetModuleBaseNameA(hProcess, mod, (LPSTR)(&base_name), sizeof(base_name));
		//printf("Module loaded: %s\n", base_name);
		for (auto& mod_name : pt_options.coverage_modules)
		{
			if (!_stricmp(base_name, mod_name.c_str()))
			{
				add_module_to_section_cache(mod, base_name);
			}
		}
	}
	return 1;
}

void fuzz_process::kill()
{
	TerminateProcess(hProcess, 0);
}

void fuzz_process::append_trace_data(unsigned char *trace_data, size_t append_size) {
	size_t space_left = pt_options.trace_buffer_size - trace_size;

	if (!space_left) {
		// stop collecting trace if the trace buffer is full;
		printf("Warning: Trace buffer is full\n");
		return;
	}

	if (append_size > space_left) {
		append_size = space_left;
	}

	if (append_size == 0) return;

	memcpy(trace_buffer + trace_size, trace_data, append_size);
	trace_size += append_size;
}

bool fuzz_process::collect_thread_trace(PIPT_TRACE_HEADER traceHeader) {
	// printf("ring offset: %u\n", traceHeader->RingBufferOffset);

	bool trace_buffer_overflow = false;

	unsigned char psb_and_psbend[] = {
		0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
		0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
		0x02, 0x23
	};

	trace_size = 0;

	// check if the trace buffer overflowed

	BYTE* trailing_data = traceHeader->Trace + traceHeader->RingBufferOffset;
	size_t trailing_size = traceHeader->TraceSize - traceHeader->RingBufferOffset;
	if (findpsb(&trailing_data, &trailing_size)) {
		trace_buffer_overflow = true;
		printf("Warning: Trace buffer overflowed, trace will be truncated\n");
		//if (options.debug_mode) printf(debug_log, "Trace buffer overflowed, trace will be truncated\n");
		append_trace_data(trailing_data, trailing_size);
	}

	append_trace_data(traceHeader->Trace, traceHeader->RingBufferOffset);

	return trace_buffer_overflow;
}

// parse PIPT_TRACE_DATA, extract trace bits and add them to the trace_buffer
// returns true if the trace ring buffer overflowed
bool fuzz_process::collect_trace(PIPT_TRACE_DATA pTraceData)
{
	bool trace_buffer_overflow = false;

	PIPT_TRACE_HEADER traceHeader;
	DWORD dwTraceSize;

	dwTraceSize = pTraceData->TraceSize;

	traceHeader = (PIPT_TRACE_HEADER)pTraceData->TraceData;

	while (dwTraceSize > (unsigned)(FIELD_OFFSET(IPT_TRACE_HEADER, Trace))) {
		if (traceHeader->ThreadId == fuzz_thread_id) {
			trace_buffer_overflow = collect_thread_trace(traceHeader);
		}

		dwTraceSize -= (FIELD_OFFSET(IPT_TRACE_HEADER, Trace) + traceHeader->TraceSize);

		traceHeader = (PIPT_TRACE_HEADER)(traceHeader->Trace +
			traceHeader->TraceSize);
	}

	return trace_buffer_overflow;
}

static fuzz_process* g_child_process;

int fuzz_process::process_traces()
{
	PIPT_TRACE_DATA trace_data = GetIptTrace(hProcess);
	if (!trace_data)
	{
		printf("Error getting ipt trace");
		return 0;
	}
	if (!trace_data->ValidTrace)
	{
		printf("invalid trace :(");
		HeapFree(GetProcessHeap(), 0, trace_data);
		return 0;
	}
	//printf("trace data: %p, trace size: %lx\n", trace_data->TraceData, trace_data->TraceSize);

	int trace_buffer_overflowed = collect_trace(trace_data);
	
	pt_image_wrapper pt_image = module_cache.setup_pt_image();
	auto fn = [](uint64_t ip)
	{
		module_info_t* mod = g_child_process->module_cache.get_intersecting_module((void*)ip, 1);
		//printf("ip: %p, mod: %p\n", (void *)ip, mod);
		if (!mod) return;
		uint64_t rva = ip - (uint64_t)mod->base;
		uint64_t hash = rva % MAP_SIZE;
		unsigned byte_idx = hash >> 3;
		trace_bits[byte_idx] |= 1 << (hash & 0x7);
	};
	if (pt_options.decoder == DECODER_FULL_REFERENCE)
		analyze_trace_full_reference(trace_buffer, trace_size, pt_image, trace_buffer_overflowed, fn);
	else if (pt_options.decoder == DECODER_TIP_FAST)
		decode_trace_tip_fast(trace_buffer, trace_size, 0, fn);

	HeapFree(GetProcessHeap(), 0, trace_data);
	return 1;
}

void fuzz_process::start_tracing(HANDLE hThread)
{
	//printf("handle %x\n", hProcess);
	fuzz_thread_id = GetThreadId(hThread);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	fuzz_ip = ctx.INSTRUCTION_POINTER;
	//printf("thread id = %d\n", fuzz_thread_id);
	//printf("Start IP = %p\n", fuzz_ip);
	
	IPT_OPTIONS ipt_options;
	memset(&ipt_options, 0, sizeof(IPT_OPTIONS));
	ipt_options.OptionVersion = 1;
	DWORD bufferSize = pt_options.winipt_ring_buffer_size; // Should be power of 2, up to 128M
	ConfigureBufferSize(bufferSize, &ipt_options);
	ConfigureTraceFlags(0, &ipt_options);
	
	if (!StartProcessIptTracing(hProcess, ipt_options))
	{
		printf("GLE=%d\n", GetLastError());
		FATAL("ipt tracing error\n");
	}
}

void fuzz_process::stop_tracing()
{
	StopProcessIptTracing(hProcess);
}

static int check_ipt() {
	uint32_t out[4]; // eax ebx ecx edx
	__cpuid((int*)out, 7);
	return !!(out[1] & (1 << 25));
}

static void pt_options_init(int argc, const char** argv) {
	pt_options.trace_buffer_size = 8 * 1024 * 1024; // 8M
	pt_options.winipt_ring_buffer_size = 8 * 1024 * 1024; // 8M
	pt_options.decoder = DECODER_TIP_FAST;

	for (int i = 0; i < argc; i++) {
		const char *token = argv[i];
		if (strcmp(token, "-covtype") == 0)
			FATAL("Sorry, only block coverage is supported right now.");
		else if (strcmp(token, "-m") == 0) {
			if (i + 1 >= argc) FATAL("missing module name following -coverage_module");
			pt_options.coverage_modules.push_back(argv[++i]);
		} else if (strcmp(token, "-trace_size") == 0) {
			if (i + 1 >= argc) FATAL("missing arg following -trace_size");
			pt_options.trace_buffer_size = strtoul(argv[++i], NULL, 0);
			pt_options.winipt_ring_buffer_size = pt_options.trace_buffer_size;
		} else if (strcmp(token, "-decoder") == 0) {
			if (i + 1 >= argc) FATAL("missing arg following -decoder");
			++i;
			if (strcmp(argv[i], "tip") == 0) {
				pt_options.decoder = DECODER_TIP_FAST;
			} else if (strcmp(argv[i], "tip_ref") == 0) {
				FATAL("sorry, that decoder isn't supported right now");
			}  else if (strcmp(argv[i], "full") == 0) {
				FATAL("sorry, that decoder isn't supported right now");
			} else if (strcmp(argv[i], "full_ref") == 0) {
				pt_options.decoder = DECODER_FULL_REFERENCE;
			} else {
				FATAL("Unknown decoder value");
			}
		} else {
			FATAL("UNRECOGNIZED IPT OPTION: \"%s\"\n", token);
		}
	}

	if (pt_options.coverage_modules.empty()) {
		FATAL("No coverage modules specified");
	}
}

int pt_init(int argc, const char **argv, char *module_dir) {
	if (!check_ipt())
		FATAL("This processor doesn't support Intel PT\n");

	int last_pt_option = -1;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			last_pt_option = i;
			break;
		}
	}
	if (last_pt_option <= 0) return 0;
	pt_options_init(last_pt_option - 1, argv + 1);

	int lastoption = -1;
	for (int i = last_pt_option + 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			lastoption = i;
			break;
		}
	}
	if (lastoption <= 0) return 0;
	forkserver_options_init(lastoption - last_pt_option - 1, argv + last_pt_option + 1);
	

	if (!EnableAndValidateIptServices()) {
		FATAL("No IPT\n");
	}
	else {
		fprintf(stderr, "IPT service enabled\n");
	}

	strcpy(section_cache_dir, module_dir);
	printf("saving modules to %s\n", section_cache_dir);

	return lastoption;
}

// TODO: watchdog timer
static uint64_t watchdog_timeout_time;

static int run_once(char **argv, uint32_t timeout, uint32_t init_timeout, int drun)
{
	//printf("\nRUNNING TARGET WITH PT+FORK: forkserver pid = %d\n", forksrv_pid);
	fuzz_process child_process;
	HANDLE hProcess, hThread;
	int ret_status = -1;
	if (drun == 1) {
		watchdog_timeout_time = get_cur_time() + 2 * (init_timeout + timeout);

		char *cmd = argv_to_cmd(argv);
		CLIENT_ID handles = spawn_child_with_injection(cmd, DRYRUN, timeout, init_timeout);
		hProcess = handles.UniqueProcess;
		hThread = handles.UniqueThread;
	} else {
		//ACTF("RUNNING: %d\n", total_execs);
		watchdog_timeout_time = get_cur_time() + 2 * timeout;
		if (forksrv_pid < 0) {
			// No forkserver yet, let's spin one up.
			forksrv_pid = spawn_forkserver(argv, timeout, init_timeout);
		}
		CHILD_IDS pid_tid = fork_new_child();
		if (!pid_tid.ProcessId)
			return DEBUGGER_ERROR;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_tid.ProcessId);
		if (!hProcess)
		{
			FATAL("failed to open forked process!");
		}
		if (!pid_tid.ThreadId)
			return DEBUGGER_ERROR;
		hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, pid_tid.ThreadId);
		if (!hThread)
		{
			FATAL("failed to open forked thread!");
		}
	}

	// start IPT
	child_process = fuzz_process(hProcess);
	g_child_process = &child_process;
	child_process.start_tracing(hThread);

	// run the target
	if (drun == 1) {
		resume_child();
	}
	else {
		if (!fork_run_child()) {
			g_child_process = nullptr;
			return DEBUGGER_ERROR;
		}
	}
	ret_status = get_child_result();

	// collect & process traces
	child_process.update_modules(); // update section cache for PT (Intel's pt decoder impl wants the memory on disk -.-)
	child_process.process_traces();
	child_process.stop_tracing();

	// kill the process
	if (drun == 1) {
		kill_process(); // we also gotta clean up a bunch of other stuff.
		child_process.hProcess = NULL;
	} else {
		CloseHandle(hThread);
		child_process.kill();
	}

	g_child_process = nullptr;

	return ret_status;
}

static int run_target_pt_fork(char **argv, uint32_t timeout, uint32_t init_timeout, int drun) {
	int ret_status = run_once(argv, timeout, init_timeout, drun);
	int ret = -1;
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

int run_target_pt(char **argv, uint32_t timeout, uint32_t init_timeout, int drun)
{
	_mkdir(section_cache_dir);
	if (use_fork)
		return run_target_pt_fork(argv, timeout, init_timeout, drun);
	else
		FATAL("Intel-PT with persistent mode is not supported yet");
		//return run_target_pt_persistent(argv, timeout, drun);
}

void destroy_target_process_pt() {
	if (g_child_process) {
		g_child_process->stop_tracing();
		g_child_process->kill();
		WaitForSingleObject(g_child_process->hProcess, INFINITE);
		kill_process();
	}
}

#endif
