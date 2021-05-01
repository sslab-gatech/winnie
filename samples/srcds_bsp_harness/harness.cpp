#include <Windows.h>

#include "csgo.h"

#include <harness-api.h>

#pragma comment(lib,"forklib.lib")
#include <forklib.h>

#include "csgo.h"

#include <tlhelp32.h>
#include <tchar.h>

// Just use to export the function so I can see it in debugger easily.
#define DBGEXPORT extern "C" __declspec(dllexport)

// HARDCODED REVERSE-ENGINEERED OFFSETS
// dedicated.dll!FileSystemFactory
const DWORD dwDedicated_FilesystemFactory = 0x00003FF0;
// engine.dll!modelloader = ( IModelLoader * )&g_ModelLoader
const DWORD dwEngine_Modelloader = 0x0776218;
// engine.dll!Sys_Error::bReentry (function static var)
const DWORD dwEngine_Sys_Error_bReentry = 0x891FF5;
// engine.dll!s_nMapLoadRecursion
const DWORD dwEngine_s_nMapLoadRecursion = 0x889EC0;
// engine.dll!CMapLoadHelper::Shutdown
const DWORD dwEngine_CMapLoadHelper_Shutdown = 0x137590;

// Source engine globals
HMODULE hDedicated = 0;
HMODULE hEngine = 0;
HMODULE hTier0 = 0;
CModelInfoClient* pModelInfo;
IFileSystem* pFileSystem;
CModelLoader* modelloader;


// Harness start
// Hook 32-bit function
void RedirectFunction32(void* fnptr, void* dst)
{
	DWORD dwOldProtect;
	BOOL success = VirtualProtect(fnptr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (!success)
	{
		pMsg("Failed to hook function!\n"); // FATAL!
		ExitProcess(1);
	}

	// Assemble jmp
	BYTE* code = (BYTE*)fnptr;
	*code = 0xe9;
	*(DWORD*)(code + 1) = (DWORD)((DWORD)dst - ((DWORD)fnptr + 5));

	DWORD trash;
	VirtualProtect(fnptr, 5, dwOldProtect, &trash);
}

BOOL __fastcall returnZero(void* ecx)
{
	return 0;
}

// Hook callback to simply die.
void __declspec(naked) Fail()
{
	TerminateProcess(GetCurrentProcess(), 0);
}

// Hook some routines use by target to kill itself, because that is not okay.
void SuicidePrevention()
{
	// Triggers segfault on purpose to cause a crash (to get minidump, even when disabled) -.-
	RedirectFunction32(GetProcAddress(GetModuleHandleA("tier0"), "Plat_ExitProcess"), Fail);
	
	pMsg("Hooked 1 functions\n");
}

// Hooked vtables
DWORD cStdMemAlloc_fakeVtable[47]; // 47 members

// Hook callback
extern "C" __declspec(dllexport) void* __fastcall Hk_Alloc(IMemAlloc* pThis, void* _edx, size_t nSize)
{
	static int in_alloc;
#ifdef ALLOC_DEBUG
	if (!in_alloc && nSize >= 0x1000) // avoid recursion
	{
		in_alloc = 1;
		pMsg("Allocation of size %x requested\n", nSize);
		in_alloc = 0;
	}
#endif
	if (nSize >= 0x10000000)
	{
		in_alloc = 1;
		pMsg("BAD ALLOCATION SIZE %x\n", nSize);
		in_alloc = 0;
		Fail();
	}
	return pAlloc(pThis, nSize);
}


#ifdef NDEBUG
#define getc(X)
#define freopen_s(...)
#define printf(...)
#else
#include <stdio.h>
#endif

void __cdecl HkDevMsg(const char * fmt, ...)
{
	if (!strcmp(fmt, "Unknown read error %d\n"))
	{
		printf("LMAO NO\n");
		Fail();
	}
#ifndef _NDEBUG
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
#endif
}

DBGEXPORT void CALLBACK InitFuzz()
{
	// Used for debugging as the dedicated server seems to redirect stdio.
	hTier0 = GetModuleHandleA("tier0.dll");
	pMsg = (pMsg_t)GetProcAddress(hTier0, "Msg");
	
	// Stop minidumps. That's really annoying.
	((void (*__cdecl)(void*))GetProcAddress(hTier0, "SetMiniDumpFunction"))(Fail);

	hEngine = GetModuleHandleA("engine.dll");
	CreateInterfaceFn engine_CreateInterface = (CreateInterfaceFn)GetProcAddress(hEngine, "CreateInterface");
	pModelInfo = (CModelInfoClient*)engine_CreateInterface("VModelInfoClient004", nullptr);
	pMsg("pModelInfo = %p\n", pModelInfo);

	//CreateInterfaceFn fs_CreateInterface = (CreateInterfaceFn)((DWORD)hDedicated + dwDedicated_FilesystemFactory);
	//pFileSystem = (IFileSystem*)fs_CreateInterface("VFileSystem017", nullptr);
	//pMsg("pIFileSystem = %p\n", pFileSystem);

	// Not exported...need to get from offset (!!!) T_T"
	modelloader = (CModelLoader*)((DWORD)hEngine + dwEngine_Modelloader);
	pMsg("modelloader = %p\n", modelloader);

	// bye, ur WaitForSingleObject hEvent suck (demangled name: CThreadEvent::Wait)
	void* cthreadevent__wait = (void*) GetProcAddress(hTier0, "?Check@CThreadEvent@@QAE_NXZ");
	pMsg("CThreadEvent::Wait = %p\n", cthreadevent__wait);
	if (cthreadevent__wait)
	{
		RedirectFunction32(cthreadevent__wait, returnZero);
	}
	else
	{
		pMsg("failed to hook CThreadEvent::Wait\n");
		while (1) { Sleep(1000); }
	}

	// hook devmsg, kill annoying "Unknown Read error 38" problem
	void* devmsg = (void*)GetProcAddress(hTier0, "?DevMsg@@YAXPBDZZ");
	RedirectFunction32(devmsg, HkDevMsg);

	// Hook memory allocator to abort on large allocation.
	// IMemAlloc* g_pMemAlloc = *(IMemAlloc**) GetProcAddress(hTier0, "g_pMemAlloc");
	// memcpy(cStdMemAlloc_fakeVtable, *(DWORD**)g_pMemAlloc, sizeof(cStdMemAlloc_fakeVtable));
	// pAlloc = (AllocFn) cStdMemAlloc_fakeVtable[1];
	// pMsg("Alloc = %p\n", pAlloc);
	// cStdMemAlloc_fakeVtable[1] = (DWORD)Hk_Alloc;
	// *(DWORD**)g_pMemAlloc = cStdMemAlloc_fakeVtable; // Apply hook.

	// When map is corrupt, or some other error happens, source engine tries to kill itself.
	// This is done in tier0.dll!Error, tier0.dll!Plat_ExitProcess, etc.
	SuicidePrevention();
}

char* map = "maps/fuzz.bsp";

DBGEXPORT void CALLBACK FuzzIter()
{
	pMsg("Let's try our best!\n");
	//pMsg("m_iMapLoad=%d\n", pFileSystem->m_iMapLoad);
	// Load the model
	 modelloader->GetModelForName(map, CModelLoader::FMODELLOADER_SERVER);
	//void* model = nullptr;
	//void* pStudioHdr = pModelInfo->FindModel(nullptr, &model, map);
	//pMsg("pStudioHdr = %p; model = %p\n", pStudioHdr, model);
	//modelloader->Print();

	//while (*(int*)((DWORD)hEngine + dwEngine_s_nMapLoadRecursion) > 0) // Global reference counter
	//	((void(*)(void))((DWORD)hEngine + dwEngine_CMapLoadHelper_Shutdown))();

	// Close input file handle 2
	//pMsg("m_iMapLoad=%d\n", pFileSystem->m_iMapLoad);
	//while (pFileSystem->m_iMapLoad > 0) // Global reference counter, should always be 1 unless something catastrophic occurred.
	//	pFileSystem->EndMapAccess();
	pMsg("Done!\n");
}

EXPOSE_HARNESS(
	NULL,  // target method, we will fill this in dynamically at DllMain
	FuzzIter,  // fuzz iteration func
	L"fuzz.bsp",  // input filename that the target program expects
	InitFuzz,  // no setup func needed
	FALSE, // don't need desocket
	FALSE  // Not ready yet, we initialize dynamically in DllMain.
);

// Apply hooks early in execution so that srcds will play nicer with harness, and to trigger the fuzzing loop
// once the engine has been totally initialized, right before the main server runs.
int WINAPI DoSetup(void* param)
{
	WCHAR path[MAX_PATH];
	GetModuleFileNameW(NULL, path, MAX_PATH);
	WCHAR* wow = wcsrchr(path, L'\\')+1;
	wcscpy(wow, L"bin");
	printf("%S\n", path);
	AddDllDirectory(path);

	hDedicated = LoadLibraryEx("dedicated.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
	printf("Dedicated = %p\n", hDedicated);
	CreateInterfaceFn dedicated_CreateInterface = (CreateInterfaceFn)GetProcAddress(hDedicated, "CreateInterface");
	IDedicatedExports* pDedicatedExports = (IDedicatedExports*)dedicated_CreateInterface("VENGINE_DEDICATEDEXPORTS_API_VERSION003", nullptr);
	printf("dedicatedExports = %p\n", pDedicatedExports);

	pRunServer = (RunServerFn)(*(DWORD**)pDedicatedExports)[10];
	printf("RunServer = %p\n", pRunServer);
	HarnessInfo.target_method = pRunServer;

	FreeConsole(); // necessary.

	MemoryBarrier();
	InterlockedExchange8(&HarnessInfo.ready, TRUE);
	
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		DoSetup(NULL);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
