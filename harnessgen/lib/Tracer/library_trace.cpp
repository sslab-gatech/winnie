#include "pin.H"
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.18362.0/um
namespace W {
#include <Windows.h>
};
W::HANDLE current_process;

enum {
	UNIQUE, RELATION, ALL, INDIRECT, DOMINATOR
} trace_mode;

typedef enum {
	DRLTRC_NONE_POINTER,
	DRLTRC_CODE_POINTER,
	DRLTRC_DATA_POINTER
} drltrc_pointer_type_t;

#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))
#define BUFFER_LAST_ELEMENT(buf)    (buf)[BUFFER_SIZE_ELEMENTS(buf) - 1]

int tracemode;

#define VNOTIFY(level, msg, ...)

#define MAX_PTR_DEPTH 4

/* Frontend scope is defined here because if logdir is a forbidden path we have to change
 * it and provide for our client manually.
 */
KNOB<std::string> op_logdir
(KNOB_MODE_WRITEONCE, "pintool", "logdir", ".", "Log directory to print library call data\n"
	"Specify log directory where library call data will be written, in a separate file per "
	"process.  The default value is \".\" (current dir).  If set to \"-\", data for all "
	"processes are printed to stderr (warning: this can be slow).");

std::string logdir;

KNOB<std::string> op_functype
(KNOB_MODE_WRITEONCE, "pintool", "functype", "none", "functype information\n" "Specify functype file");

KNOB<bool> op_only_from_app
(KNOB_MODE_WRITEONCE, "pintool", "only_from_app", "0", "Reports only library calls from the app\n"
	"Only reports library calls from the application itself, as opposed to all calls even "
	"from other libraries or within the same library.");

KNOB<bool> op_follow_children
(KNOB_MODE_WRITEONCE, "pintool", "follow_children", "1", "Trace child processes\n"
	"Trace child processes created by a target application. Specify -no_follow_children "
	"to disable.");

KNOB<bool> op_print_ret_addr
(KNOB_MODE_WRITEONCE, "pintool", "print_ret_addr", "0", "Print library call's return address\n"
	"Print return addresses of library calls.");

KNOB<bool> op_disable_dump
(KNOB_MODE_WRITEONCE, "pintool", "disable_dump", "0", "Disable Memory Dump\n"
	"Disable Memory Dump");

KNOB<bool> op_ind_call_tracer
(KNOB_MODE_WRITEONCE, "pintool", "ind_call_tracer", "0", "Print all indirect-call (addr)\n"
	"Print all indirect-call (addr).");

KNOB<int> op_print_callback
(KNOB_MODE_WRITEONCE, "pintool", "print_callback", "0", "Print library callback functions\n"
	"Print callback functions.");

KNOB<unsigned int> op_unknown_args
(KNOB_MODE_WRITEONCE, "pintool", "num_unknown_args", "10", "Number of unknown libcall args to print\n"
	"Number of arguments to print for unknown library calls.  Specify 0 to disable "
	"unknown args printing.");

KNOB<int> op_max_args
(KNOB_MODE_WRITEONCE, "pintool", "num_max_args", "10", "Maximum number of arguments to print\n"
	"Maximum number of arguments to print.  This option allows to limit the number of "
	"arguments to be printed.  Specify 0 to disable args printing (including unknown).");

KNOB<bool> op_config_file_default
(KNOB_MODE_WRITEONCE, "pintool", "default_config", "1", "Use default config file.\n"
	"Use config file that comes with drltrace and located in the same path. Specify "
	"no_use_config and provide a path to custom config file using -config option.");

KNOB<std::string> op_config_file
(KNOB_MODE_WRITEONCE, "pintool", "config", "", "The path to custom config file.\n"
	"Specify a custom path where config is located. The config file describes the prototype"
	" of library functions for printing library call arguments.  See drltrace documentation"
	" for more details.");

KNOB<bool> op_ignore_underscore
(KNOB_MODE_WRITEONCE, "pintool", "ignore_underscore", "0", "Ignores library routine names "
	"starting with \"_\".\n" "Ignores library routine names starting with \"_\".");

KNOB<std::string> op_only_to_lib
(KNOB_MODE_WRITEONCE, "pintool", "only_to_lib", "", "Only reports calls to the library <lib_name>. \n"
	"Only reports calls to the library <lib_name>. Argument is case insensitive on Windows.");

KNOB<std::string> op_only_to_target
(KNOB_MODE_WRITEONCE, "pintool", "only_to_target", "XXXXXX", "Only reports calls to the target <target_name>. \n"
	"Only reports calls to the target <target_name>. Argument is case insensitive on Windows.");

KNOB<std::string> op_trace_mode
(KNOB_MODE_WRITEONCE, "pintool", "trace_mode", "unique", "Setup level of trace\n"
	"Setup the level of trace. (unique, relation, all, ind");

KNOB<bool> op_use_config
(KNOB_MODE_WRITEONCE, "pintool", "use_config", "1", "Use config file\n"
	"Use config file for library call arguments printing. Specify no_use_config to disable.");

KNOB<std::string> op_ltracelib_ops
(KNOB_MODE_WRITEONCE, "pintool", "ltracelib_ops", "0", "(For internal use: sweeps up drltracelib options)\n"
	"This is an internal option that sweeps up other options to pass to the drltracelib.");

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>

using namespace std;

#define MAXIMUM_PATH 260
#define MAX_SYM_RESULT 256

/* Where to write the trace */
static FILE * outf;
static FILE* out_table;

bool table_flag = true;
bool printed = false;
bool trace_ind_call = false;
bool found_module;
bool found_target;
int print_callback = 0;
int indent = 0;
int callnum = 0;
int retnum = 0;
int calltype;
int second_level_elements = 100;
const int pagesize = 0x1000;
PIN_MUTEX as_built_lock;
PIN_MUTEX as_built_lock2;

typedef UINT8 byte;
typedef ADDRINT app_pc;
typedef ADDRINT ptr_uint_t;

byte safe_buf[pagesize + 1] = { 0 };
byte safe_buf2[pagesize + 1] = { 0 };
byte safe_buf_pointer[(pagesize / 4) + 1] = { 0 };
byte safe_buf_pointer2[(pagesize / 4) + 1] = { 0 };
app_pc last_addr = 0x0;

#ifdef X64 //windows x64 
int memory_size = 8;
#else
int memory_size = 4;
#endif

void print_sp(ADDRINT addr);

using namespace std;
vector<pair<int, ptr_uint_t>> print_args(ADDRINT RSP, int count, int tid);
bool fast_safe_read(void* base, size_t size, void* out_buf, size_t* outsize);
void print_pointer_arrow(drltrc_pointer_type_t type);
bool print_if_printable(ADDRINT addr, int tid);
static VOID event_app_instruction(TRACE trace, VOID*);
static void print_ret_value(ADDRINT addr);
void dump_at_return(vector<pair<int, ptr_uint_t>> dumped, int tid);

std::set<std::string> dlls;
std::vector<std::string> file_related;
std::vector<app_pc> return_candidate;

/* Avoid exe exports, as on Linux many apps have a ton of global symbols. */
static app_pc exe_start;
static app_pc module_start;
static app_pc module_end;
static app_pc target_start;
static app_pc target_end;

/* map to store function name and the number of argument */
map<string, int> func_arg_map;
map<string, int>::iterator map_it;
map<int, int> tid_callid;
map<int, int> tid_retid;
typedef map<app_pc, vector<pair<int, ptr_uint_t>> > CallListMap;

CallListMap calls;

TLS_KEY calllist_map_key;

class MUTEX {
public:
	MUTEX() {
		PIN_LockClient();
		// PIN_MutexLock(&as_built_lock);
	}

	~MUTEX() {
		PIN_UnlockClient();
		// PIN_MutexUnlock(&as_built_lock);
	}
};

CallListMap& calllist_map_() {
	return *(CallListMap*)(PIN_GetThreadData(calllist_map_key));
}

void insert_calllist(app_pc addr, vector<pair<int, ptr_uint_t>> data) {
	//FIXME: check x64 case 
	//fprintf(outf, "insert %x\n", addr);
	//last_addr = (app_pc)addr+6;
	calls.insert(make_pair(addr, data));
}

void increase_callnum(int tid) {
	// new thread-id?
	if (tid_callid.find(tid) == tid_callid.end()) {
		tid_callid.insert(make_pair(tid, 0));
	}
	else {
		tid_callid[tid]++;
	}
}

int get_callnum(int tid) {
	if (tid_callid.find(tid) == tid_callid.end()) {
		return 0;
	}
	else {
		return tid_callid[tid];
	}
}

// some hardcoded routine to check file operations
bool is_file_related(char* symbol, bool check_offset) {
	if (symbol == NULL) {
		return false;
	}
	if ((strcasestr(symbol, "CreateFil") != NULL) ||
		(strcasestr(symbol, "ReadFil") != NULL) ||
		(strcasestr(symbol, "SetFilePoin") != NULL) ||
		(strcasestr(symbol, "WriteFil") != NULL)) {

		if (check_offset && strcasestr(symbol, "+0x0") != NULL) {
			return true;
		}

		else if (!check_offset) {
			return true;
		}
	}
	return false;
}

void increase_retid(int tid) {
	// new thread-id?
	if (tid_retid.find(tid) == tid_retid.end()) {
		tid_retid.insert(make_pair(tid, 0));
	}
	else {
		tid_retid[tid]++;
	}
}

int get_retid(int tid) {
	if (tid_retid.find(tid) == tid_retid.end()) {
		return 0;
	}
	else {
		return tid_retid[tid];
	}
}

/* return argument-map given the address */
vector<pair<int, ptr_uint_t>> check_calladdr(app_pc addr) {
	//fprintf(outf, "finding %x\n", addr);

	auto calllist_map = calls;
	if (calllist_map.find(addr) == calllist_map.end()) {
		//fprintf(outf, "nothing in callist_map\n");
		vector<pair<int, ptr_uint_t>> temp;
		temp.push_back(make_pair(-1, -1));
		//vector<pair<int, ptr_uint_t>> temp = calllist_map[last_addr];
		//calllist_map.erase(last_addr);
		return temp;

	}
	else {
		//fprintf(outf, "something in callist_map\n");
		vector<pair<int, ptr_uint_t>> data = calllist_map[addr];
		//calllist_map.erase(addr);
		//fprintf(outf, "FOUND return patch with cid:%d\n", data);
		return data;
	}
}

void insert_func_arg(string funcname, int args) {
	func_arg_map.insert(make_pair(funcname, args));
}

int ret_func_arg(string funcname) {

	map_it = func_arg_map.find(funcname);
	if (map_it != func_arg_map.end()) {
		return func_arg_map[funcname];
	}
	return -1;
}

static std::string is_printable(ptr_uint_t arg_val)
{
	std::stringstream stream;
	stream << std::hex << arg_val;
	std::string result(stream.str());
	uint j;
	std::string h;
	std::string s;
	if (result.length() != 8)
		return s;
	unsigned int x;

	for (j = 0; j < 4; j++) {
		std::stringstream ss;
		char c[5];
		h = "";
		h.push_back(result.at(j * 2));
		h.push_back(result.at(j * 2 + 1));
		ss << std::hex << h;
		ss >> x;
		if (static_cast<int>(x) < 32 || static_cast<int>(x) > 126)
			return s;
		sprintf(c, "%c", static_cast<int>(x));
		s.push_back(c[0]);
	}
	reverse(s.begin(), s.end());
	return s;
}

/* get the decoded string of a specific address (terminated by space or non-ascii char) */
static std::string get_string(ptr_uint_t arg_val, ptr_uint_t ptr_val, size_t sz)
{
	std::string res;
	std::string ret = is_printable(arg_val);
	if (ret.length() < sz)
		return ret;
	res += ret;
	/* keep access the subsequent value */
	if (arg_val == ptr_val)
		return res;
	while (true) {
		ptr_uint_t deref = 0;
		ptr_val += sz;
		fast_safe_read((void*)(ptr_val), sz, &deref, NULL);
		if (deref == 0)
			break;
		ret = is_printable(deref);
		if (ret.length() < sz) {
			res += ret;
			break;
		}
		res += ret;
	}
	return res;
}

//FIXME: I assume that all writable region as DATA pointer (regardless of execution)
/* determine whether a pointer is code pointer or data pointer
   implement for the print structure feature for harness generation */
static bool is_code_pointer(ptr_uint_t arg_val)
{
	//fprintf(outf, "\naddr:%x\n", arg_val);
	VOID* pAddress = (void*)arg_val;
	OS_MEMORY_AT_ADDR_INFORMATION info;
	NATIVE_PID pid;
	OS_GetPid(&pid);
	if (OS_QueryMemory(pid, pAddress, &info).generic_err != OS_RETURN_CODE_QUERY_FAILED) {
		if (info.Protection == (OS_PAGE_PROTECTION_TYPE_READ | OS_PAGE_PROTECTION_TYPE_EXECUTE))
			return true;
		else
			return false;
	}
	return false;
}

/*  determine whether an address is data or pointer
	implement for the print structure feature for harness generation */
static drltrc_pointer_type_t _is_pointer(ptr_uint_t arg_val, int sz)
{
	ptr_uint_t deref = 0;
	bool ret = fast_safe_read((void*)arg_val, sz, &deref, NULL);
	/* arg_val is a pointer */
	if (ret) {
		if (is_code_pointer(arg_val))
			return DRLTRC_CODE_POINTER;
		else
			return DRLTRC_DATA_POINTER;
	}
	return DRLTRC_NONE_POINTER;
}

/* try to print the module and the symbol of a specific address */
static void print_mod_and_symbol(void* drcontext, ptr_uint_t addr)
{
	MUTEX lock;
	IMG mod = IMG_FindByAddress(addr);
	string sym, modname;

	/* get the module name and function name via the module table first */
	if (IMG_Valid(mod)) {
		sym = RTN_FindNameByAddress(addr);
		modname = IMG_Name(mod);
	}

	/* if fail to get module name via module table => use GetModuleFileName API to get it */
	//if (modname.empty()) {
	//	MEMORY_BASIC_INFORMATION memInfo;
	//	TCHAR dlpath[MAX_PATH];
	//	if (VirtualQuery((LPCVOID)addr, &memInfo, sizeof(memInfo)) != 0) {
	//		DWORD r = GetModuleFileName((HMODULE)memInfo.AllocationBase, dlpath, MAX_PATH);
	//		if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE)
	//			fprintf(outf, "[%s!%s]", dlpath, sym.name);
	//		else
	//			fprintf(outf, "[%s]", dlpath);
	//	}
	//}
	if (!modname.empty() && !sym.empty()) {
		fprintf(outf, "[%s!%s]", modname.c_str(), sym.c_str());
	}
	else if (modname.empty() && !sym.empty()) {
		fprintf(outf, "[!%s]", sym.c_str());
	}
	else if (!modname.empty() && sym.empty()) {
		fprintf(outf, "[%s!unknown_symbol]", modname);
	}
	else {
		fprintf(outf, "");
	}
}

static void print_structure(void* drcontext, ptr_uint_t addr, int sz, int level, ptr_uint_t ptr_val)
{
	std::string ret;
	drltrc_pointer_type_t type = _is_pointer(addr, sz);
	/* access the value of the pointer, if it is not a pointer, try to decode it to be a string. */
	if (type == DRLTRC_NONE_POINTER) {
		fprintf(outf, " (DATA) ");
		ret = get_string(addr, ptr_val, sz);
		if (ret.length() != 0) {
			fprintf(outf, " ( string: %s )", ret.c_str());
		}
	}
	else if (type == DRLTRC_CODE_POINTER) {
		fprintf(outf, " (CODE_POINTER) ");
		print_mod_and_symbol(drcontext, addr);
	}
	else if (type == DRLTRC_DATA_POINTER) {
		fprintf(outf, " (DATA_POINTER) ");
		ptr_uint_t deref = 0;
		bool flag = fast_safe_read((void*)addr, sz, &deref, NULL);
		if (flag && level < MAX_PTR_DEPTH) {
			fprintf(outf, " => " "%p", deref);
			print_structure(drcontext, deref, sz, level + 1, addr);
		}
	}
}

bool fast_safe_read(void* base, size_t size, void* out_buf, size_t* outsize)
{
	/* For all of our uses, a failure is rare, so we do not want
	 * to pay the cost of the syscall (DrMemi#265).
	 */
	bool res = true;
	res = !!W::ReadProcessMemory(current_process, base, out_buf, size, (W::SIZE_T*)outsize);
	return res;
}

bool addr_belongs_module(app_pc addr) {
	if (addr >= module_start && addr <= module_end) {
		return true;
	}
	return false;
}

bool addr_belongs_target(app_pc addr) {
	if (addr >= target_start && addr <= target_end) {
		return true;
	}
	return false;
}

static void print_two_modules(app_pc inst_addr, app_pc target_addr)
{
	MUTEX lock;
	IMG data1 = IMG_FindByAddress(inst_addr);

	if (!IMG_Valid(data1)) {
		return;
	}
	auto modname1 = IMG_Name(data1);

	IMG data2 = IMG_FindByAddress(target_addr);
	if (!IMG_Valid(data2)) {
		return;
	}
	auto modname2 = IMG_Name(data2);
	auto pair = modname1 + "--" + modname2;

	if (!dlls.count(pair)) {
		char* remove_str = ":\\windows"; // use windows default path
		if (strcasestr(modname1.c_str(), remove_str) == NULL && strcasestr(modname2.c_str(), remove_str) == NULL) {
			fprintf(outf, "%s\n", modname2.c_str());
		}
		else {
			fprintf(outf, "Windows Library ===> %s\n", modname2.c_str());
		}
		dlls.insert(pair);
	}
}

static void print_ind_address(app_pc src, app_pc dest, const char* prefix) {
	fprintf(outf, "%s:" "%p" "," "%p" " \n", prefix, src, dest);
}

int print_thread_id(int tid, bool is_call) {
	if (is_call) {
		increase_callnum(tid);
		fprintf(outf, "CALLID[%d] TID[%d] ", get_callnum(tid), tid);
	}
	else {
		increase_retid(tid);
		fprintf(outf, "RETID[%d] TID[%d] ", get_retid(tid), tid);
	}

	return tid;
}

//// from instrcalls
static std::string print_address(app_pc addr, const char* prefix, bool newline)
{
	MUTEX lock;
	IMG data = IMG_FindByAddress(addr);
	string sym;
	if (!IMG_Valid(data)) {
		fprintf(outf, "%s " "%p" " ? ??:0\n", prefix, addr);
		return sym;
	}

	RTN rtn = RTN_FindByAddress(addr);

	if (RTN_Valid(rtn)) {
		sym = RTN_Name(rtn);
		ADDRINT rtn_addr = RTN_Address(rtn);
		auto modname = IMG_Name(data);
		if (modname.empty())
			modname = "<noname>";
		//fprintf(outf, "[LEV%d] %s " "%p" " %s!%s+" "%p", indent, prefix, addr, modname, sym.name, addr - data->start - sym.start_offs);
		if (newline)
			fprintf(outf, "%s""%p""(%s!%s+" "%p"")\n", prefix, addr, modname.c_str(), sym.c_str(), addr - rtn_addr);
		else
			fprintf(outf, "%s""%p""(%s!%s+" "%p"")", prefix, addr, modname.c_str(), sym.c_str(), addr - rtn_addr);

	}
	else

		// apply when from?
		if (newline)
			fprintf(outf, "%s""%p""\n", prefix, addr);
		else
			fprintf(outf, "%s""%p""", prefix, addr);
	return sym;
}

static char* get_symbol_at_addr(app_pc addr)
{
	MUTEX lock;
	static char ret_str[0x100] = { 0 };
	RTN rtn = RTN_FindByAddress(addr);

	if (RTN_Valid(rtn)) {
		sprintf(ret_str, "%s+" "%p""", RTN_Name(rtn).c_str(), addr - RTN_Address(rtn));
		return ret_str;
	}

	ret_str[0] = '?';
	ret_str[1] = '\0';
	return ret_str;
}


static void PIN_FAST_ANALYSIS_CALL at_call(app_pc instr_addr, app_pc target_addr, app_pc RSP, int tid, app_pc next_addr)
{
	if (tracemode == RELATION) {
		if (addr_belongs_module(instr_addr) || addr_belongs_module(target_addr))
			print_two_modules(instr_addr, target_addr);
	}

	else if (tracemode == ALL) {
		if (found_module == true) {
			// if call-from-module and call-to-outside        
			char name[0x30];
			bool print = false;

			if (print_callback == 1) {
				if (addr_belongs_module(instr_addr) && addr_belongs_target(target_addr)) {
					sprintf(name, "DC M2T @");  //in case of indirect jmp, this may be M2J
					print = true;
				}
			}

			// if call-from-outside and call-to-module                
			if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
				sprintf(name, "DC T2M @");
				print = true;
			}

			if (print) {
				//PIN_MutexLock(&as_built_lock);
				MUTEX mutex;
				fprintf(outf, "==\n");
				tid = print_thread_id(tid, true);
				print_address(instr_addr, name, false);
				print_address(target_addr, "->", true);
				vector<pair<int, ptr_uint_t>> dumped = print_args(RSP, 10, tid);
				insert_calllist(next_addr, dumped);
				//PIN_MutexUnlock(&as_built_lock);
			}
		}
	}

	else if (tracemode == DOMINATOR) {
		PIN_MutexLock(&as_built_lock);
		// target to target (binary to binary)
		char name[0x30];
		bool print = false;
		bool dump = false;

		//We need to print address (simple information)
		//print_address(target_addr, "==", true);
		char* sym = get_symbol_at_addr(target_addr);
		//fprintf(outf, "%s\n", sym);
		if (is_file_related(sym, true)) {
			//fprintf(outf, "sym:%s\n", sym);
			sprintf(name, "FR "); // File Related
			print = true;
			dump = true;
		}

		if (addr_belongs_target(instr_addr) && addr_belongs_target(target_addr)) {
			sprintf(name, "DC T2T ");
			print = true;
		}
		else if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
			sprintf(name, "DC T2M ");
			print = true;
		}

		if (print) {
			MUTEX mutex;
			fprintf(outf, "==\n");
			tid = print_thread_id(tid, true);  //print unique call_id and thread_id
			//print_ret_addr(instr_addr, cur_instr_length);
			//fprintf(outf, "here1\n");
			print_address(instr_addr, name, false);
			print_address(target_addr, "->", true);
			print_sp(RSP);

			if (dump) {
				print_args(RSP, 10, tid);
				return_candidate.push_back(instr_addr);
			}
			else {
				if (print_if_printable(RSP, tid)) {
					return_candidate.push_back(instr_addr);
				}
			}
			//fprintf(outf, "here2\n");
		}
		PIN_MutexUnlock(&as_built_lock);
	}
}

static void PIN_FAST_ANALYSIS_CALL at_call_ind(app_pc instr_addr, app_pc target_addr, app_pc RSP, int tid, app_pc next_addr)
{
	app_pc ret_addr;
	//fprintf(outf, "at_call_ind\n");    

	if (tracemode == RELATION) {
		if (addr_belongs_module(instr_addr) || addr_belongs_module(target_addr))
			print_two_modules(instr_addr, target_addr);
	}

	else if (tracemode == ALL) {
		if (found_module == true) {
			// if call-from-module and call-to-outside        
			char name[0x30];
			bool print = false;

			if (print_callback == 1) {
				if (addr_belongs_module(instr_addr) && addr_belongs_target(target_addr)) {
					sprintf(name, "IC M2T @");  //in case of indirect jmp, this may be M2J
					print = true;
				}
			}

			// if call-from-outside and call-to-module                
			if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
				sprintf(name, "IC T2M @");
				print = true;
			}

			if (print) {
				MUTEX mutex;
				fprintf(outf, "==\n");
				tid = print_thread_id(tid, true);
				print_address(instr_addr, name, false);
				print_address(target_addr, "->", true);

				vector<pair<int, ptr_uint_t>> dumped = print_args(RSP, 10, tid);
				insert_calllist(next_addr, dumped);
			}
		}
	}

	else if (tracemode == DOMINATOR) {
		PIN_MutexLock(&as_built_lock);
		// target to target (binary to binary)
		char name[0x30];
		bool print = false;
		bool dump = false;

		char* sym = get_symbol_at_addr(target_addr);
		if (is_file_related(sym, true)) {
			//fprintf(outf, "sym:%s\n", sym);
			sprintf(name, "FR ");
			print = true;
			dump = true;
		}

		//print_address(target_addr, "--", true);        

		if (addr_belongs_target(instr_addr) && addr_belongs_target(target_addr)) {
			sprintf(name, "IC T2T ");
			print = true;
		}
		else if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
			sprintf(name, "IC T2M ");
			print = true;
		}

		if (print) {
			//fprintf(outf, "here3\n");
			//fprintf(outf, "ins_size:%d\n", cur_instr_length);
			MUTEX mutex;
			fprintf(outf, "==\n");
			tid = print_thread_id(tid, true);  //print unique call_id and thread_id
			//print_ret_addr(instr_addr, cur_instr_length);
			print_address(instr_addr, name, false);
			print_address(target_addr, "->", true);
			print_sp(RSP);
			//print_args(10, tid);
			if (dump) {
				print_args(RSP, 10, tid);
				return_candidate.push_back(instr_addr);
			}
			else {
				if (print_if_printable(RSP, tid)) {
					return_candidate.push_back(instr_addr);
				}
			}
		}
		PIN_MutexUnlock(&as_built_lock);
	}
}

static void PIN_FAST_ANALYSIS_CALL at_jmp_ind(app_pc instr_addr, app_pc target_addr, ADDRINT RSP, int tid)
{
	app_pc ret_addr;
	//fprintf(outf, "at_jmp_ind\n");    

	if (tracemode == RELATION) {
		if (addr_belongs_module(instr_addr) || addr_belongs_module(target_addr))
			print_two_modules(instr_addr, target_addr);
	}

	else if (tracemode == ALL) {
		if (found_module == true) {
			// if call-from-module and call-to-outside        
			char name[0x30];
			bool print = false;

			if (print_callback == 1) {
				if (addr_belongs_module(instr_addr) && addr_belongs_target(target_addr)) {
					sprintf(name, "IJ M2T @");  //in case of indirect jmp, this may be M2J

					print = true;
				}
			}

			// if call-from-outside and call-to-module                
			if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
				sprintf(name, "IJ T2M @");
				print = true;
			}

			if (print) {
				//PIN_MutexLock(&as_built_lock);
				MUTEX mutex;
				fprintf(outf, "==\n");
				tid = print_thread_id(tid, true);
				print_address(instr_addr, name, false);
				print_address(target_addr, "->", true);
				vector<pair<int, ptr_uint_t>> dumped = print_args(10, tid, ret_addr);
				insert_calllist(ret_addr, dumped);

				//PIN_MutexUnlock(&as_built_lock);
			}
		}
	}

	else if (tracemode == DOMINATOR) {
		PIN_MutexLock(&as_built_lock);
		// target to target (binary to binary)
		char name[0x30];
		bool print = false;
		bool dump = false;

		char* sym = get_symbol_at_addr(target_addr);
		if (is_file_related(sym, true)) {
			//fprintf(outf, "sym:%s\n", sym);
			sprintf(name, "FR ");
			print = true;
			dump = true;
		}
		//print_address(target_addr, "~~", true);

		if (addr_belongs_target(instr_addr) && addr_belongs_target(target_addr)) {
			sprintf(name, "IC T2T ");
			print = true;
		}
		else if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
			sprintf(name, "IC T2M ");
			print = true;
		}

		if (print) {
			MUTEX mutex;
			//fprintf(outf, "here5\n");
			fprintf(outf, "==\n");
			tid = print_thread_id(tid, true);  //print unique call_id and thread_id
			//print_ret_addr(instr_addr, cur_instr_length);
			print_address(instr_addr, name, false);
			print_address(target_addr, "->", true);
			print_sp(RSP);
			//print_args(10, tid);
			if (dump) {
				print_args(RSP, 10, tid);
				return_candidate.push_back(instr_addr);
			}
			else {
				if (print_if_printable(RSP, tid)) {
					return_candidate.push_back(instr_addr);
				}
			}
		}
		PIN_MutexUnlock(&as_built_lock);
	}
}

bool return_to_candidate(app_pc target_addr) {
	app_pc del_item = 0;
	size_t index = 0;
	for (size_t i = 0; i < return_candidate.size(); i++) {
		if (return_candidate[i] < target_addr + 7 && return_candidate[i] > target_addr - 7) {
			del_item = return_candidate[i];
			index = i;
		}
	}


	if (del_item == 0)
		return false;
	else {
		return_candidate.erase(return_candidate.begin() + index);
		return true;
	}
}

static void PIN_FAST_ANALYSIS_CALL at_return(app_pc instr_addr, app_pc target_addr, ADDRINT RSP, ADDRINT RAX, int tid)
{
	if (tracemode == RELATION) {
		if (addr_belongs_module(instr_addr) || addr_belongs_module(target_addr))
			print_two_modules(instr_addr, target_addr);
	}

	else if (tracemode == ALL) {
		char* name;
		bool print = false;

		if (print_callback == 1) {
			if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
				name = "RET2M ";
				print = true;
			}
		}

		if (found_module == true) {
			if (addr_belongs_module(instr_addr) && addr_belongs_target(target_addr)) {
				name = "RET2T ";
				print = true;
			}
		}

		if (print) {
			MUTEX mutex;
			fprintf(outf, "==\n");
			tid = print_thread_id(tid, false);
			print_address(instr_addr, name, false);
			print_address(target_addr, "->", true);
			print_ret_value(RAX);

			// dump the arguments of function                
			vector<pair<int, ptr_uint_t>> dumped = check_calladdr(target_addr);
			dump_at_return(dumped, tid);
		}
	}

	else if (tracemode == DOMINATOR) {
		PIN_MutexLock(&as_built_lock);

		char name[0x30];
		bool print = false;
		bool dump = false;

		/*
		char* sym = get_symbol_at_addr(instr_addr);
		if (is_file_related(sym, false)){
			//fprintf(outf, "sym:%s\n", sym);
			sprintf(name, "RET_FR ");
			print = true;
			dump = true;
			//fprintf(outf, "here2-2\n");
		}
		//fprintf(outf, "here3\n");
		*/

		if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
			sprintf(name, "RET2M ");
			//name = "RET2M ";
			print = true;
		}

		else if ((addr_belongs_module(instr_addr) && addr_belongs_target(target_addr)) ||
			(addr_belongs_target(instr_addr) && addr_belongs_target(target_addr))) {
			sprintf(name, "RET2T ");
			//name = "RET2T ";
			print = true;
		}

		if (print) {
			MUTEX mutex;
			//fprintf(outf, "here3-1\n");
			if (print == false) {
				sprintf(name, "RETFR ");
			}

			fprintf(outf, "==\n");
			tid = print_thread_id(tid, false);  //print unique call_id and thread_id
			print_address(instr_addr, name, false);
			print_address(target_addr, "->", true);
			print_sp(RSP);
			print_ret_value(RAX);
		}

		if (return_to_candidate(target_addr)) {
			MUTEX mutex;
			if (print == false) {
				sprintf(name, "RETFR ");
			}

			fprintf(outf, "==\n");
			tid = print_thread_id(tid, false);  //print unique call_id and thread_id
			print_address(instr_addr, name, false);
			print_address(target_addr, "->", true);
			print_sp(RSP);
			print_ret_value(RAX);
		}
		PIN_MutexUnlock(&as_built_lock);
	}

	else if (tracemode == INDIRECT) {
		if (addr_belongs_target(instr_addr) && addr_belongs_module(target_addr)) {
			print_ind_address(instr_addr, target_addr, "RETURN");
		}
	}
}


void print_pointer_arrow(drltrc_pointer_type_t type) {
	if (type == DRLTRC_NONE_POINTER) {
		fprintf(outf, "[D]");
	}
	else if (type == DRLTRC_CODE_POINTER) {
		fprintf(outf, "[CP]");
		//fprintf(outf, " -> " "%p", deref);
	}
	else if (type == DRLTRC_DATA_POINTER) {
		fprintf(outf, "[DP]");
	}
}

void check_pointer_wholepage(int arg_index, int cid, int tid, char* fix) {

	void* deref = 0;
	bool result = false;
	drltrc_pointer_type_t _type;
	ptr_uint_t* addr;

	char memdump_pn[0x100];
	char out_pn[0x100];

	//init the array
	for (int i = 0; i < (pagesize / 4) + 1; i++)
		safe_buf_pointer[i] = 0;

	// read data and check whether it is pointer or not
	for (int i = 0; i < pagesize + 1; i = i + 4) {

		addr = ((ptr_uint_t*)(safe_buf + i));
		//fprintf(outf, "%x ", *test);
		result = fast_safe_read((void*)* addr, 4, (void*)& deref, NULL);
		if (result) {
			_type = _is_pointer(*addr, memory_size);
			if (_type == DRLTRC_CODE_POINTER) {
				safe_buf_pointer[i / 4] = DRLTRC_CODE_POINTER;
			}
			else {
				safe_buf_pointer[i / 4] = DRLTRC_DATA_POINTER;

				// dump the second level pointer
				if (i < second_level_elements && cid >= 0) {
					sprintf(memdump_pn, "%s\\memdump\\t%d-c%d-a%d-%s", logdir.c_str(), tid, cid, arg_index, fix);
					OS_MkDir(memdump_pn, 0777);
					fast_safe_read((void*)* addr, pagesize, safe_buf2, NULL);

					sprintf(out_pn, "%s\\%d", memdump_pn, i);
					FILE* out_fp = fopen(out_pn, "wb");
					fwrite(safe_buf2, 1, pagesize, out_fp);
					fclose(out_fp);
				}
			}
		}
		else {
			//fprintf(outf, "N");
			safe_buf_pointer[i / 4] = DRLTRC_NONE_POINTER;
		}
	}
}

void dump_address(ptr_uint_t addr, int arg_index, int cid, int tid) {
	//void *data = NULL;
	int current_callid;
	char* fix;

	// at-call || at-call-ind || at-jmp-ind
	if (cid == -1) {
		current_callid = get_callnum(tid);
		fix = "pre";
	}
	// at-return
	else {
		current_callid = get_retid(tid);
		fix = "post";
	}
	bool result = false;
	size_t bytes_read;
	char out_pn[0x100];

	byte safe_buf[pagesize + 1] = { 0 };
	memset(safe_buf, 0x0, sizeof(safe_buf));

	// safe_read target address
	result = fast_safe_read((void*)addr, pagesize, safe_buf, &bytes_read);
	check_pointer_wholepage(arg_index, cid, tid, fix);

	// store to file (e.g., memdump\\c1-a1.bin)    
	sprintf(out_pn, "memdump\\t%d-c%d-a%d.%s", tid, current_callid, arg_index, fix);
	FILE* out_fp = fopen((logdir + "\\" + out_pn).c_str(), "wb");
	fwrite(safe_buf, 1, pagesize, out_fp);
	fwrite(safe_buf_pointer, 1, pagesize / 4, out_fp);
	fclose(out_fp);
}

void dump_at_return(vector<pair<int, ptr_uint_t>> dumped, int tid) {

	if (dumped.size() == 1) {
		return;
	}
	int cid = dumped.at(0).second;
	int len = dumped.size();

	int _arg;
	ptr_uint_t _addr;

	for (int i = 1; i < len; i++) {
		_arg = dumped.at(i).first;
		_addr = dumped.at(i).second;

		if (!op_disable_dump)
			dump_address(_addr, _arg, cid, tid);
	}
}

/*
fast_safe_read(addr, sizeof(arg), &arg);
result = access_and_print((ptr_uint_t)arg, i, tid, addr);
*/
bool is_printable_ascii(char* input) {

	for (int i = 0; i < 4; i++) {
		if (!isprint(input[i]))
			return false;
	}
	return true;
}

char* should_access_and_print(ptr_uint_t arg, int index, int tid, ADDRINT* addr) {
	bool rst = false;
	char s_buf[0x101];
	static char s_out[0x101];
	static char s_out2[0x101];
	bzero(s_buf, 0x101);
	bzero(s_out, 0x101);
	bzero(s_out2, 0x101);

	rst = fast_safe_read((void*)arg, 0x100, (void*)& s_buf, NULL);

	if (index == 0 && rst == true) {
		sprintf(s_out, "%s", s_buf);
		sprintf(s_out2, "%s", s_buf);
		if (is_printable_ascii(s_out)) {
			//fprintf(outf, " -STR: %s\n", s_out);
			return s_out;
		}

		else if (is_printable_ascii(s_out2)) {
			//fprintf(outf, " -STR: %s\n", s_out2);
			return s_out2;
		}
	}
	return NULL;
}

bool access_and_print(ptr_uint_t arg, int index, int tid, ADDRINT* addr) {
	bool rst = false;
	char s_buf[0x101];
	char s_out[0x101];
	char s_out2[0x101];
	bzero(s_buf, 0x101);
	rst = fast_safe_read((void*)arg, 0x100, &s_buf, NULL);
	if (index == 0 && rst == true) {
		sprintf(s_out, "%s", s_buf);
		sprintf(s_out2, "%s", s_buf);
		if (is_printable_ascii(s_out))
			fprintf(outf, " -STR: %s\n", s_out);
		else if (is_printable_ascii(s_out2))
			fprintf(outf, " -STR: %s\n", s_out2);
	}

	std::string ret = is_printable(arg);
	void* deref = 0;
	void* next_arg = NULL;
	bool result = false;
	bool has_datapointer = false;

	//FIXME: make it as a function        
	result = fast_safe_read((void*)arg, 4, &deref, NULL);
	fprintf(outf, " -A%d: ""%p""", index, arg);
	if (result) {
		if (ret.length() == 4)
			fprintf(outf, " (str:%s)", ret.c_str());
	}

	// 1st dereference
	result = fast_safe_read((void*)arg, 4, &deref, NULL);
	if (result) {
		drltrc_pointer_type_t _type = _is_pointer(arg, memory_size);
		print_pointer_arrow(_type);

		// test dump here
		// TODO: now we only consider dump for the first layer
		if (_type == DRLTRC_DATA_POINTER) {
			has_datapointer = true;
			//fprintf(outf, "dump_address()\n");
			if (!op_disable_dump)
				dump_address(arg, index, -1, tid);
		}

		fprintf(outf, " > " "%p", deref);
		ret = is_printable((ptr_uint_t)deref);
		if (ret.length() == 4) {
			if (deref > 0)
				fprintf(outf, " (str:%s)", ret.c_str());
		}
	}

	// 2nd dereference
	next_arg = deref;
	deref = 0;
	result = fast_safe_read((void*)next_arg, 4, &deref, NULL);
	if (result) {
		drltrc_pointer_type_t _type = _is_pointer((ptr_uint_t)next_arg, memory_size);
		print_pointer_arrow(_type);
		fprintf(outf, " > " "%p", deref);
		ret = is_printable((ptr_uint_t)deref);
		if (ret.length() == 4) {
			if (deref > 0)
				fprintf(outf, " (str:%s)", ret.c_str());
		}
	}

	// 3rd dereference
	next_arg = deref;
	deref = 0;
	result = fast_safe_read((void*)next_arg, 4, &deref, NULL);
	if (result) {
		drltrc_pointer_type_t _type = _is_pointer((ptr_uint_t)next_arg, memory_size);
		print_pointer_arrow(_type);
		fprintf(outf, " > " "%p", deref);
		ret = is_printable((ptr_uint_t)deref);
		if (ret.length() == 4) {
			if (deref > 0)
				fprintf(outf, " (str:%s)", ret.c_str());
		}
	}

	return has_datapointer;
}

bool print_if_printable(ADDRINT addr, int tid) {
	ADDRINT arg;
	char* rst;

	fast_safe_read((void*)addr, sizeof(arg), &arg, nullptr);
	rst = should_access_and_print((ptr_uint_t)arg, 0, tid, (ADDRINT*)addr);
	if (rst != NULL) {
		fprintf(outf, " -STR: %s\n", rst);
		return true;
	}
	return false;
}

void print_sp(ADDRINT addr) {
	ADDRINT arg = 0x3f3f3f3f;
	fast_safe_read((void*)addr, sizeof(arg), &arg, nullptr);

	fprintf(outf, "SP: ""%p"" -> ""%p""\n", addr, arg);
}

vector<pair<int, ptr_uint_t>> print_args(app_pc RSP, int count, int tid) {
	//void print_args (int count){
	ADDRINT* addr;
	void* arg;
	bool result = false;
	vector<pair<int, ptr_uint_t>> dumped_args;

#ifdef X64 //windows x64 
	fprintf(outf, "  - ARG%d: ""%p""\n", 0, mc.rcx);
	fprintf(outf, "  - ARG%d: ""%p""\n", 1, mc.rdx);
	fprintf(outf, "  - ARG%d: ""%p""\n", 2, mc.r8);
	fprintf(outf, "  - ARG%d: ""%p""\n", 3, mc.r9);

	for (int i = 4; i < count; i++) {
		addr = (reg_t*)(mc.xsp + (i + 0) * sizeof(reg_t));
		fast_safe_read(addr, sizeof(arg), &arg);
		fprintf(outf, "  - ARG%d: ""%p""\n", i, arg);
	}
#else  // windows x86
	dumped_args.push_back(make_pair(-1, get_callnum(tid)));
	for (int i = 0; i < count; i++) {
		arg = nullptr;
		addr = (ADDRINT*)(RSP + (i + 0) * sizeof(ADDRINT));
		fast_safe_read(addr, sizeof(arg), &arg, nullptr);
		result = access_and_print((ptr_uint_t)arg, i, tid, addr);
		if (result == true) {
			dumped_args.push_back(make_pair(i, (ptr_uint_t)arg));
		}
		fprintf(outf, "\n");
	}
#endif
	return dumped_args;
}

static void print_ret_addr(app_pc instr_addr, int instr_size) {
	/*
	dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
	dr_get_mcontext(dr_get_current_drcontext(), &mc);

	reg_t *addr;
	void *arg;
	addr = (reg_t *) (mc.xsp);
	fast_safe_read(addr, sizeof(arg), &arg);
	fprintf(outf, "(ret:""%p"", xsp:""%p"")", arg, addr);
	*/

	fprintf(outf, "(ret:""%p"") ", instr_addr + instr_size);
}

static void print_ret_value(ADDRINT addr) {
	fprintf(outf, "RETVAL: ""%p""\n", addr);
}

static bool library_matches_filter(IMG info)
{
	if (!op_only_to_lib.Value().empty()) {
		string libname = IMG_Name(info);
		return (!libname.empty() && strcasestr(libname.c_str(), op_only_to_lib.Value().c_str()) != NULL);
	}
	return true;
}

static bool target_matches_filter(IMG info)
{
	if (!op_only_to_target.Value().empty()) {
		string libname = IMG_Name(info);
		return (!libname.empty() && strcasestr(libname.c_str(), op_only_to_target.Value().c_str()) != NULL);
	}
	return true;
}

struct ImageTracker {
	ADDRINT start, end;
	ADDRINT entry;
	ADDRINT r1, r2, r3;
	std::string path;
};

static std::vector<ImageTracker> ss;
void loaded(IMG info) {
	static int i;

	ss.push_back({
		IMG_LowAddress(info),
		IMG_HighAddress(info) + 1,
		IMG_LowAddress(info) + IMG_EntryAddress(info),
		0, 0, 0,
		IMG_Name(info)
		});
	return;
}

static void event_exit(INT32 code, VOID* v);

static void event_module_load(IMG info, VOID*)
{
	loaded(info);

	//fprintf(outf, "!!! %s\n", IMG_Name(info).c_str());
	char* remove_str = ":\\windows"; // use windows default path
	if (tracemode == UNIQUE && strcasestr(IMG_Name(info).c_str(), remove_str) == NULL) {
		dlls.insert(IMG_Name(info));
	}

	if (!IMG_IsMainExecutable(info) && library_matches_filter(info)) {
		module_start = IMG_LowAddress(info);
		module_end = IMG_HighAddress(info) + 1;

		if (tracemode == ALL) {
			print_address(module_start, "LIBRARY MODULE START ADDR:", true);
			print_address(module_end, "LIBRARY MODULE END ADDR:", true);
		}

		found_module = true;
	}

	if (IMG_IsMainExecutable(info) && tracemode == ALL) {
		fprintf(outf, "CHECKING MODULE...\n");
		exe_start = IMG_LowAddress(info);
		target_start = exe_start;
		target_end = IMG_HighAddress(info) + 1;

		print_address(target_start, "TARGET MODULE START ADDR:", true);
		print_address(target_end, "TARGET MODULE END ADDR:", true);
		found_target = true;
	}

	if (target_matches_filter(info)) {
		target_start = IMG_LowAddress(info);
		target_end = IMG_HighAddress(info) + 1;

		if (tracemode == ALL) {
			print_address(target_start, "TARGET MODULE START ADDR:", true);
			print_address(target_end, "TARGET MODULE END ADDR:", true);
		}

		found_target = true;
	}

	auto rtn = RTN_FindByName(info, "NtTerminateProcess");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)event_exit, IARG_UINT32, 0, IARG_ADDRINT, 0, IARG_END);
		RTN_Close(rtn);
	}
}

static void init_file_related(void) {
	file_related.push_back("CreateFile");
	file_related.push_back("ReadFile");
	file_related.push_back("SetFilePointer");
	file_related.push_back("WriteFile");
}

static void open_log_file(void)
{
	if (op_logdir.Value().compare("-") == 0) {
		outf = stderr;
	}
	else {
		NATIVE_PID pid; OS_GetPid(&pid);
		char filename[100];
		sprintf(filename, "drltrace.%d.log", pid);
		outf = fopen((logdir + "\\" + filename).c_str(), "wb");
		ASSERT(outf, "failed to open log file");
		//setvbuf(outf, nullptr, _IONBF, 0);
		VNOTIFY(0, "drltrace log file is %s""\n", buf);
	}
}

void reset_memdumnp_storage(void) {
	const char memdump_pn[] = "memdump";
	{
		std::stringstream s;
		s << "cd \"" << logdir << "\" && rmdir /s /q " << memdump_pn;
		system(s.str().c_str());
	}
	OS_MkDir((logdir + "\\" + memdump_pn).c_str(), 0777);
}

static void open_functype_file(void)
{
	VNOTIFY(0, "Opened functype is %s""\n", op_functype.Value().c_str());
	FILE* fp;

	char  line[255];
	fp = fopen(op_functype.Value().c_str(), "r");

	while (fgets(line, sizeof(line), fp) != NULL) {

		char* val1 = strtok(line, "|");
		char* val2 = strtok(NULL, "|");
		int val3 = atoi(strtok(NULL, "|"));
		//fprintf("insert %s %d\n", val1, val3);
		std::string val1_str(val1);
		insert_func_arg(val1_str, val3);
	}

}

static void
event_thread_init(void* drcontext)
{
	PIN_SetThreadData(calllist_map_key, new CallListMap);
}

static void
event_thread_exit(void* drcontext)
{
}

void drmodtrack_dump(FILE* out) {
	int index = 0;
	fprintf(outf, "Module Table: version 4, count %d\n", ss.size());
	for (auto&& item : ss) {
		fprintf(out, "%-3d, %-3d, 0x%08x, 0x%08x, 0x%08x, %016x, 0x%08x, 0x%08x,  %s\n",
			index, index, item.start, item.end, item.entry, item.r1, item.r2, item.r3, item.path.c_str());
		index++;
	}
}

static void event_exit(INT32 code, VOID* v)
{
	//drmgr_unregister_thread_init_event(event_thread_init);
	//drmgr_unregister_thread_exit_event(event_thread_exit);

	//if (op_use_config)
	//	libcalls_hashtable_delete();

	if (outf != stderr && tracemode != UNIQUE && tracemode != RELATION) {

		MUTEX mutex;
		fprintf(outf, "\n\n==\n");
		drmodtrack_dump(outf);
		fclose(outf);
	}
}

INT32 print_usage()
{
	cerr << "This tool counts the number of dynamic instructions executed" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

int main(int argc, CHAR** argv)
{
	if (PIN_Init(argc, argv)) {
		return print_usage();
	}

#define MAXPATH 0x1000
	char logdir_buf[MAXPATH] = {};
	if (!W::GetFullPathNameA(op_logdir.Value().c_str(), MAXPATH, logdir_buf, NULL)) {
		return print_usage();
	}

	logdir = logdir_buf;

	PIN_InitSymbols();
	PIN_AddFiniFunction(event_exit, nullptr);

	calllist_map_key = PIN_CreateThreadDataKey(NULL);

	//FOR BB
	TRACE_AddInstrumentFunction(event_app_instruction, nullptr);

	//FOR MODULE
	IMG_AddInstrumentFunction(event_module_load, nullptr);

	trace_ind_call = op_ind_call_tracer.Value();

	PIN_MutexInit(&as_built_lock);
	PIN_MutexInit(&as_built_lock2);
	open_log_file();
	init_file_related();

	if (!strcasestr("none", op_functype.Value().c_str()) != NULL)
		open_functype_file();
	print_callback = op_print_callback;

	//take care of memdump storage
	reset_memdumnp_storage();

	// read option for tracing 
	// 1) unique: print out unique dlls loaded
	// 2) relation: print out all dlls related with specified dll
	// 3) all: print all traces between two dlls
	if (strcasestr("unique", op_trace_mode.Value().c_str()) != NULL) {
		tracemode = UNIQUE;
	}
	else if (strcasestr("relation", op_trace_mode.Value().c_str()) != NULL) {
		tracemode = RELATION;
	}
	else if (strcasestr("all", op_trace_mode.Value().c_str()) != NULL) {
		tracemode = ALL;
	}
	else if (strcasestr("indirect", op_trace_mode.Value().c_str()) != NULL) {
		tracemode = INDIRECT;
	}
	else if (strcasestr("dominator", op_trace_mode.Value().c_str()) != NULL) {
		tracemode = DOMINATOR;
	}

	current_process = W::GetCurrentProcess();
	PIN_StartProgram();
}

static VOID event_app_instruction(TRACE trace, VOID*)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {

		for (INS instr = BBL_InsHead(bbl); INS_Valid(instr); instr = INS_Next(instr)) {
			auto next_addr = INS_Address(instr) + INS_Size(instr);
			if (INS_IsDirectCall(instr)) {
				INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_call, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_THREAD_ID, IARG_ADDRINT, next_addr, IARG_END);
			}

			else if (INS_IsRet(instr)) {
				INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_return, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_REG_VALUE, REG_EAX, IARG_THREAD_ID, IARG_END);
			}

			else if (INS_IsIndirectControlFlow(instr)) {
				if (INS_Opcode(instr) != XED_ICLASS_JMP)
				INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_call_ind, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_THREAD_ID, IARG_ADDRINT, next_addr, IARG_END);
				else
					INS_InsertCall(instr, IPOINT_BEFORE, (AFUNPTR)at_jmp_ind, IARG_FAST_ANALYSIS_CALL
					, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_ESP, IARG_THREAD_ID, IARG_END);
			}

		}
	}
	return;
}

