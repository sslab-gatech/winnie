#include "pch.h"

// LOL C++
#include <vector>

#include <intrin.h> // for __nop()
#include <direct.h> // for _mkdir
#include <stdio.h>

#include <Psapi.h>

#include <forklib.h>

extern "C"
{
#include <libipt.h>
#include <ipttool.h>
#include <intel-pt.h>
#include <internal/pt_cpu.h>
}

#include "debug.h"
#include "ptdecode.h"

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
	~pt_image_wrapper();
	operator pt_image*() const { return image; }
};

class module_cache
{
	friend class pt_image_wrapper;
	
	std::vector<module_info_t> loaded_modules;
	pt_image_section_cache *section_cache;

public:
	module_cache();
	~module_cache();
	
	module_info_t *get_loaded_module(char *module_name, void *base);
	module_info_t *get_intersecting_module(char *module_name, void *base, DWORD size);
	void add_module(module_info_t&);
	pt_image_wrapper setup_pt_image() { return pt_image_wrapper(*this); }
};

class fuzz_process
{
	HANDLE hProcess;
	module_cache module_cache;

	size_t ReadProcessMemory_tolerant(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);
	void get_all_modules(std::vector<HMODULE>& modules);
	void add_module_to_section_cache(HMODULE module, char *module_name);

public:
	fuzz_process(HANDLE hProcess);
	void update_modules();
	void process_traces();
};

pt_image_wrapper::pt_image_wrapper(module_cache& module_cache) : modules(module_cache)
{
	image = pt_image_alloc("winafl_image");
	for (const module_info_t& cur_module : modules.loaded_modules) {
		if (cur_module.isid > 0) {
			int ret = pt_image_add_cached(image, modules.section_cache, cur_module.isid, NULL);
		}
	}
}
	
pt_image_wrapper::~pt_image_wrapper()
{
	if (image) pt_image_free(image);
}

module_cache::module_cache()
{
	section_cache = pt_iscache_alloc("winafl_cache");
}

module_cache::~module_cache()
{
	if (section_cache) pt_iscache_free(section_cache);
}

// check if the same module was already loaded
module_info_t* module_cache::get_loaded_module(char *module_name, void *base) {
	for (module_info_t& current_module : loaded_modules) {
		if (_stricmp(module_name, current_module.module_name) == 0) {
			if (base == NULL || base == current_module.base) {
				return &current_module;
			}
		}
	}
	return NULL;
}

// find if there is a *different* module that previously occupied
// the same space
module_info_t* module_cache::get_intersecting_module(char *module_name, void *base, DWORD size) {
	for (module_info_t& current_module : loaded_modules) {
		if (((uint64_t)current_module.base + current_module.size <= (uint64_t)base) ||
			((uint64_t)base + size <= (uint64_t)current_module.base)) {
			continue;
		}
		return &current_module;
	}
	return NULL;
}

void module_cache::add_module(module_info_t& loaded_module) {
	loaded_module.isid = pt_iscache_add_file(section_cache, loaded_module.tmpfilename, 0, loaded_module.size, (uint64_t)loaded_module.base);
	if (loaded_module.isid <= 0) {
		FATAL("Error adding file to pt cache.");
	}
	loaded_modules.push_back(loaded_module);
	printf("debug: cached %s (%p) in tmpfile %s, isid %d\n", loaded_module.module_name, loaded_module.base, loaded_module.tmpfilename, loaded_module.isid);
}

fuzz_process::fuzz_process(HANDLE hProcess) : hProcess(hProcess)
{
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

void fuzz_process::get_all_modules(std::vector<HMODULE>& modules) {
	modules.resize(1024);
	DWORD hmodules_size;
	while (true) {
		if (!EnumProcessModulesEx(hProcess, &modules[0], modules.capacity() * sizeof(HMODULE), &hmodules_size, LIST_MODULES_ALL)) {
			FATAL("EnumProcessModules failed, %x\n", GetLastError());
		}
		if (hmodules_size % sizeof(HMODULE)) FATAL("WTF, uneven hmodules_size?");
		if (hmodules_size <= modules.capacity() * sizeof(HMODULE))
		{
			modules.resize(hmodules_size / sizeof(HMODULE));
			break;
		}
		modules.resize(modules.capacity() * 2);
	}
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
	module_info_t *intersecting_module = module_cache.get_intersecting_module(module_name, module_info.lpBaseOfDll, module_info.SizeOfImage);
	if (intersecting_module) {
		FATAL("Module %s loaded in the address range that module %s previously occupied. This is currently unsupported.",
			module_name, intersecting_module->module_name);
	}

	module_info_t loaded_module;
	strncpy(loaded_module.module_name, module_name, sizeof(loaded_module.module_name));
	loaded_module.base = module_info.lpBaseOfDll;
	loaded_module.size = module_info.SizeOfImage;

	// todo put these files in a separate directory and clean it periodically
	snprintf(loaded_module.tmpfilename, sizeof(loaded_module.tmpfilename), "%s\\sectioncache_%p.dat", ".\\ptmodules", module_info.lpBaseOfDll);

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

	module_cache.add_module(loaded_module);
}

void fuzz_process::update_modules()
{
	std::vector<HMODULE> modules;
	get_all_modules(modules);
	printf("there are %d modules\n", modules.size());
	for (HMODULE mod : modules)
	{
		char base_name[MAX_PATH];
		GetModuleBaseNameA(hProcess, mod, (LPSTR)(&base_name), sizeof(base_name));
		printf("Module loaded: %s\n", base_name);
		add_module_to_section_cache(mod, base_name);
	}
}

void fuzz_process::process_traces()
{
	pt_image_wrapper pt_image = module_cache.setup_pt_image();

	PIPT_TRACE_DATA trace_data = GetIptTrace(hProcess);
	if (!trace_data)
	{
		FATAL("Error getting ipt trace");
	}
	if (!trace_data->ValidTrace)
	{
		FATAL("invalid trace :(");
	}
	printf("trace data: %p, trace size: %lx\n", trace_data->TraceData, trace_data->TraceSize);

	bool skip_first_bb = false;
	analyze_trace_full_reference(trace_data->TraceData, trace_data->TraceSize, pt_image, skip_first_bb, [](int pt_status, pt_block* pt_block)
	{
		printf("ip: %p, %d %d\n", (void *)pt_block->ip, pt_status, pt_block->iclass);
	});
}

int pt_stuff()
{
	struct pt_block_decoder *decoder;
	struct pt_config config;
	struct pt_event event;
	struct pt_block block;
	pt_config_init(&config);
	pt_cpu_read(&config.cpu);
	pt_cpu_errata(&config.errata, &config.cpu);

	// This is important not only for accurate coverage, but also because
	// if we don't set it, the decoder is sometimes going to break
	// blocks on these instructions anyway, resulting in new coverage being
	// detected where there in fact was none.
	// See also skip_next comment below
	config.flags.variant.block.end_on_call = 1;
	config.flags.variant.block.end_on_jump = 1;
	decoder = pt_blk_alloc_decoder(&config);
	if (!decoder) {
		printf("Error allocating decoder\n");
		return 1;
	}

	return 0;
}

HANDLE hEvent;

int do_parent(PROCESS_INFORMATION pi)
{
	fuzz_process child(pi.hProcess);
	child.update_modules();
	
	IPT_OPTIONS ipt_options;
	memset(&ipt_options, 0, sizeof(IPT_OPTIONS));
	ipt_options.OptionVersion = 1;
	DWORD bufferSize = 8 * 1024 * 1024; // Should be power of 2
	ConfigureBufferSize(bufferSize, &ipt_options);
	ConfigureTraceFlags(0, &ipt_options);
	if (!StartProcessIptTracing(pi.hProcess, ipt_options))
	{
		printf("ipt tracing error\n");
		return 1;
	}

	// signal child to go!
	SetEvent(hEvent);

	Sleep(500); // Let child exec a bit

	child.update_modules();
	child.process_traces();

	return 0;
}

int main(int argc, char** argv, char** envp)
{
	_mkdir(".\\ptmodules");
	
	if (!EnableAndValidateIptServices())
	{
		printf("NO IPT!\n");
		return 1;
	}
	printf("IPT available\n");

	// sync between parent and child
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE; // !!!
	hEvent = CreateEvent(&sa, TRUE, FALSE, NULL);
	
	PROCESS_INFORMATION pi;
	int pid = fork(&pi);
	if (pid == -1)
	{
		printf("Fork failed!\n");
		return 1;
	}
	else if (pid) // parent
	{
		printf("child pid: %d\n", pid);
		return do_parent(pi);
	}
	else // child
	{
		printf("i am child\n");

		// wait for parent to enable pt
		WaitForSingleObject(hEvent, INFINITE);
		printf("yeehaw cowboy lets get it on!!!\n");
		
		for (volatile int i = 0; i < 1000; i++) { __nop(); } // this will generate a really obvious repetitive pattern in the trace.

		// let parent collect the trace before we die
		Sleep(1000);
		return 0;
	}
}
